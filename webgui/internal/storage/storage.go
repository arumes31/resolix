package storage

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"tailscale-dnsrewrite/webgui/internal/config"
	"tailscale-dnsrewrite/webgui/internal/encryption"
	"tailscale-dnsrewrite/webgui/internal/models"
)

// Store manages the in-memory ring buffer of events and disk persistence.
type Store struct {
	cfg      *config.Config
	events   []models.QueryEvent
	head     int
	count    int
	eventsMu sync.RWMutex

	pendingQueries map[string]map[string][]pendingInfo
	pendingMu      sync.Mutex

	idCounter uint64

	hourlyStats map[int64]int
	statsMu     sync.RWMutex

	windowDomainCounts map[string]int
	windowClientCounts map[string]int

	lastArchivedTime int64
	totalEvents      int64

	// Cache Hit Ratio tracking (Improvement 98)
	cacheHits    int64
	totalReplies int64
	cacheMu      sync.RWMutex

	// Rolling window counters (Optimization)
	rpmBuckets     [60]int
	rpmTimes       [60]int64
	rphBuckets     [60]int
	rphTimes       [60]int64
	nodeRPMBuckets map[string]*[60]int
	nodeRPMTimes   map[string]*[60]int64
	nodeRPHBuckets map[string]*[60]int
	nodeRPHTimes   map[string]*[60]int64

	// String interning (Optimization)
	internPool map[string]string

	// Health and Trends (New Features)
	upstreamHealth map[string]float64
	healthMu       sync.RWMutex
	lastTopStats   map[string][]models.StatEntry
}

type pendingInfo struct {
	startTime time.Time
	upstream  string
}

// NewStore initializes a new Store with the provided configuration.
func NewStore(cfg *config.Config) *Store {
	return &Store{
		cfg:                cfg,
		events:             make([]models.QueryEvent, cfg.MaxEvents),
		pendingQueries:     make(map[string]map[string][]pendingInfo),
		hourlyStats:        make(map[int64]int),
		windowDomainCounts: make(map[string]int),
		windowClientCounts: make(map[string]int),
		lastArchivedTime:   0,
		nodeRPMBuckets:     make(map[string]*[60]int),
		nodeRPMTimes:       make(map[string]*[60]int64),
		nodeRPHBuckets:     make(map[string]*[60]int),
		nodeRPHTimes:       make(map[string]*[60]int64),
		internPool:         make(map[string]string),
		upstreamHealth:     make(map[string]float64),
		lastTopStats:       make(map[string][]models.StatEntry),
	}
}

func (s *Store) intern(str string) string {
	if str == "" {
		return ""
	}
	if v, ok := s.internPool[str]; ok {
		return v
	}
	s.internPool[str] = str
	return str
}

// Init ensures the history directory exists and warms up stats from disk.
func (s *Store) Init() {
	if err := os.MkdirAll(s.cfg.HistoryDir, 0750); err != nil {
		log.Printf("Error creating history directory: %v", err)
	}
	s.loadStatsFromHistory()
}

func (s *Store) loadStatsFromHistory() {
	files, err := os.ReadDir(s.cfg.HistoryDir)
	if err != nil {
		return
	}
	now := time.Now().Unix()
	cutoff := now - int64(s.cfg.HistoryRetention.Seconds())

	for _, f := range files {
		if strings.HasPrefix(f.Name(), "history-") && strings.HasSuffix(f.Name(), ".jsonl") {
			path := filepath.Join(s.cfg.HistoryDir, filepath.Clean(f.Name()))
			file, err := os.Open(path) // #nosec G304
			if err != nil {
				continue
			}

			// Defer file close immediately
			func() {
				defer func() { _ = file.Close() }()
				scanner := bufio.NewScanner(file)
				for scanner.Scan() {
					line := scanner.Text()
					var e models.QueryEvent

					// Decrypt if password is set
					plain := []byte(line)
					if s.cfg.HistoryPassword != "" {
						decrypted, err := encryption.Decrypt(line, s.cfg.HistoryPassword)
						if err != nil {
							continue
						}
						plain = decrypted
					}

					if err := json.Unmarshal(plain, &e); err == nil {
						s.statsMu.Lock()
						s.totalEvents++
						s.statsMu.Unlock()

						if e.UnixTime >= cutoff {
							hour := e.UnixTime / 3600
							s.statsMu.Lock()
							s.hourlyStats[hour]++
							s.statsMu.Unlock()

							if e.Latency != nil || e.Upstream != "" {
								s.cacheMu.Lock()
								s.totalReplies++
								if e.Upstream == "System Cache" {
									s.cacheHits++
								}
								s.cacheMu.Unlock()
							}
						}
					}
				}
				if err := scanner.Err(); err != nil {
					log.Printf("Error scanning history file %s: %v", path, err)
				}
			}()
		}
	}
	s.statsMu.RLock()
	log.Printf("Warmed up stats: %d buckets loaded", len(s.hourlyStats))
	s.statsMu.RUnlock()
}

// GetConfig returns the application configuration.
func (s *Store) GetConfig() *config.Config {
	return s.cfg
}

// AddEvent adds a new query event to the ring buffer and updates stats.
func (s *Store) AddEvent(e models.QueryEvent) {
	s.statsMu.Lock()
	e.Node = s.intern(e.Node)
	e.Type = s.intern(e.Type)
	e.ClientIP = s.intern(e.ClientIP)

	// Rolling buckets update
	secBucket := e.UnixTime % 60
	minBucket := (e.UnixTime / 60) % 60
	minuteStart := (e.UnixTime / 60) * 60

	if s.rpmTimes[secBucket] != e.UnixTime {
		s.rpmTimes[secBucket] = e.UnixTime
		s.rpmBuckets[secBucket] = 1
	} else {
		s.rpmBuckets[secBucket]++
	}

	if s.rphTimes[minBucket] != minuteStart {
		s.rphTimes[minBucket] = minuteStart
		s.rphBuckets[minBucket] = 1
	} else {
		s.rphBuckets[minBucket]++
	}

	nodeName := e.Node
	if nodeName == "" {
		nodeName = "local"
	}
	if s.nodeRPMBuckets[nodeName] == nil {
		s.nodeRPMBuckets[nodeName] = &[60]int{}
		s.nodeRPMTimes[nodeName] = &[60]int64{}
		s.nodeRPHBuckets[nodeName] = &[60]int{}
		s.nodeRPHTimes[nodeName] = &[60]int64{}
	}
	if s.nodeRPMTimes[nodeName][secBucket] != e.UnixTime {
		s.nodeRPMTimes[nodeName][secBucket] = e.UnixTime
		s.nodeRPMBuckets[nodeName][secBucket] = 1
	} else {
		s.nodeRPMBuckets[nodeName][secBucket]++
	}
	if s.nodeRPHTimes[nodeName][minBucket] != minuteStart {
		s.nodeRPHTimes[nodeName][minBucket] = minuteStart
		s.nodeRPHBuckets[nodeName][minBucket] = 1
	} else {
		s.nodeRPHBuckets[nodeName][minBucket]++
	}

	hourBucket := e.UnixTime / 3600
	s.hourlyStats[hourBucket]++
	s.totalEvents++
	s.statsMu.Unlock()

	s.eventsMu.Lock()
	e.ID = fmt.Sprintf("%d", atomic.AddUint64(&s.idCounter, 1))
	if s.count == s.cfg.MaxEvents {
		old := s.events[s.head]
		s.windowDomainCounts[old.Domain]--
		s.windowClientCounts[old.ClientIP]--
	}
	s.events[s.head] = e
	s.windowDomainCounts[e.Domain]++
	s.windowClientCounts[e.ClientIP]++
	s.head = (s.head + 1) % s.cfg.MaxEvents
	if s.count < s.cfg.MaxEvents {
		s.count++
	}
	s.eventsMu.Unlock()
}

// UpdateEvent searches for a matching pending event and updates its latency and upstream.
func (s *Store) UpdateEvent(node, domain string, latency float64, upstream string) *models.QueryEvent {
	s.eventsMu.Lock()
	defer s.eventsMu.Unlock()

	scanLimit := s.count
	if scanLimit > config.DefaultScanLimit {
		scanLimit = config.DefaultScanLimit
	}
	for i := 0; i < scanLimit; i++ {
		idx := (s.head - 1 - i + s.cfg.MaxEvents) % s.cfg.MaxEvents
		if s.events[idx].Domain == domain && s.events[idx].Node == node && s.events[idx].Latency == nil {
			s.events[idx].Latency = &latency
			s.events[idx].Upstream = upstream

			s.cacheMu.Lock()
			s.totalReplies++
			if upstream == "System Cache" {
				s.cacheHits++
			}
			s.cacheMu.Unlock()
			return &s.events[idx]
		}
	}
	return nil
}

// GetOrderedEvents returns the latest N events in chronological order (oldest first).
func (s *Store) GetOrderedEvents(limit int) []models.QueryEvent {
	s.eventsMu.RLock()
	defer s.eventsMu.RUnlock()

	n := s.count
	if limit > 0 && n > limit {
		n = limit
	}

	result := make([]models.QueryEvent, 0, n)
	for i := 0; i < n; i++ {
		idx := (s.head - n + i + s.cfg.MaxEvents) % s.cfg.MaxEvents
		result = append(result, s.events[idx])
	}
	return result
}

// GetRecentEvents returns events newer than the provided unix timestamp.
func (s *Store) GetRecentEvents(since int64) []models.QueryEvent {
	s.eventsMu.RLock()
	defer s.eventsMu.RUnlock()

	n := s.count
	if n > config.DefaultScanLimit {
		n = config.DefaultScanLimit
	}

	result := make([]models.QueryEvent, 0, n)
	for i := 0; i < n; i++ {
		idx := (s.head - 1 - i + s.cfg.MaxEvents) % s.cfg.MaxEvents
		e := s.events[idx]
		if e.UnixTime > since {
			result = append(result, e)
		}
	}
	return result
}
// GetStats returns aggregated traffic statistics.
func (s *Store) GetStats() map[string]interface{} {
	domainCounts := make(map[string]int)
	clientCounts := make(map[string]int)

	now := time.Now().Unix()
	rpm := 0
	rph := 0
	rpd := 0

	s.statsMu.RLock()
	for i := 0; i < 60; i++ {
		if now-s.rpmTimes[i] < 60 {
			rpm += s.rpmBuckets[i]
		}
		if now-s.rphTimes[i] < 3600 {
			rph += s.rphBuckets[i]
		}
	}

	nodeList := make(map[string]interface{})
	for node, buckets := range s.nodeRPHBuckets {
		nRPM := 0
		nRPH := 0
		rpmTs := s.nodeRPMTimes[node]
		rphTs := s.nodeRPHTimes[node]
		rpmB := s.nodeRPMBuckets[node]
		for i := 0; i < 60; i++ {
			if now-rpmTs[i] < 60 {
				nRPM += rpmB[i]
			}
			if now-rphTs[i] < 3600 {
				nRPH += buckets[i]
			}
		}
		if nRPH > 0 {
			nodeList[node] = map[string]int{
				"rpm": nRPM,
				"rph": nRPH,
			}
		}
	}

	currentHour := now / 3600
	for h := currentHour - 23; h <= currentHour; h++ {
		rpd += s.hourlyStats[h]
	}
	s.statsMu.RUnlock()

	s.eventsMu.RLock()
	for k, v := range s.windowDomainCounts {
		if v > 0 {
			domainCounts[k] = v
		}
	}
	for k, v := range s.windowClientCounts {
		if v > 0 {
			clientCounts[k] = v
		}
	}
	s.eventsMu.RUnlock()

	toStats := func(m map[string]int, category string) []models.StatEntry {
		st := make([]models.StatEntry, 0, len(m))
		for k, v := range m {
			entry := models.StatEntry{Key: k, Count: v}
			if category == "clients" {
				if alias, ok := s.cfg.ClientAliases[k]; ok {
					entry.Alias = alias
				}
			}
			// Compute trend
			s.statsMu.RLock()
			if last, ok := s.lastTopStats[category]; ok {
				for _, le := range last {
					if le.Key == k {
						if v > le.Count {
							entry.Trend = "up"
						} else if v < le.Count {
							entry.Trend = "down"
						} else {
							entry.Trend = "stable"
						}
						break
					}
				}
			}
			s.statsMu.RUnlock()
			st = append(st, entry)
		}
		sort.Slice(st, func(i, j int) bool { return st[i].Count > st[j].Count })
		if len(st) > 10 {
			st = st[:10]
		}
		return st
	}

	// Heatmap data
	heatmap := make(map[string]int)
	s.statsMu.RLock()
	for h := currentHour - 23; h <= currentHour; h++ {
		t := time.Unix(h*3600, 0)
		heatmap[t.Format("15:00")] = s.hourlyStats[h]
	}
	s.statsMu.RUnlock()

	// Upstream health
	s.healthMu.RLock()
	health := make(map[string]float64)
	for k, v := range s.upstreamHealth {
		health[k] = v
	}
	s.healthMu.RUnlock()

	// Improvement 98: Calculate cache hit ratio
	s.cacheMu.RLock()
	var cacheRatio float64
	if s.totalReplies > 0 {
		cacheRatio = float64(s.cacheHits) / float64(s.totalReplies) * 100
	}
	s.cacheMu.RUnlock()

	return map[string]interface{}{
		"top_domains":     toStats(domainCounts, "domains"),
		"top_clients":     toStats(clientCounts, "clients"),
		"rpm":             rpm,
		"rph":             rph,
		"rpd":             rpd,
		"total":           s.totalEvents,
		"nodes":           nodeList,
		"cache_hit_ratio": cacheRatio,
		"upstream_health": health,
		"heatmap":         heatmap,
	}
}

// CleanupPending removes stale entries from the pending query map.
func (s *Store) CleanupPending(now time.Time) {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	cutoff := now.Add(-30 * time.Second)
	for node, domains := range s.pendingQueries {
		for domain, infos := range domains {
			// Remove expired infos from the queue
			newInfos := make([]pendingInfo, 0)
			for _, info := range infos {
				if info.startTime.After(cutoff) {
					newInfos = append(newInfos, info)
				}
			}
			if len(newInfos) == 0 {
				delete(domains, domain)
			} else {
				domains[domain] = newInfos
			}
		}
		if len(domains) == 0 {
			delete(s.pendingQueries, node)
		}
	}
}

// SetPending records the start time of a DNS query.
func (s *Store) SetPending(node, domain string, t time.Time) {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	if s.pendingQueries[node] == nil {
		s.pendingQueries[node] = make(map[string][]pendingInfo)
	}
	s.pendingQueries[node][domain] = append(s.pendingQueries[node][domain], pendingInfo{startTime: t})
}

// GetPending retrieves and removes the oldest pending DNS query for a domain.
func (s *Store) GetPending(node, domain string) (time.Time, string, bool) {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()

	if s.pendingQueries[node] == nil {
		return time.Time{}, "", false
	}
	infos := s.pendingQueries[node][domain]
	if len(infos) == 0 {
		return time.Time{}, "", false
	}

	// Pop oldest
	info := infos[0]
	if len(infos) == 1 {
		delete(s.pendingQueries[node], domain)
	} else {
		s.pendingQueries[node][domain] = infos[1:]
	}
	return info.startTime, info.upstream, true
}

// SetUpstream records the upstream server used for the latest query of a domain.
func (s *Store) SetUpstream(node, domain, upstream string) {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	if s.pendingQueries[node] == nil {
		return
	}
	infos := s.pendingQueries[node][domain]
	if len(infos) == 0 {
		return
	}
	// Update the latest query (assuming dnsmasq logs forwarded right after query)
	infos[len(infos)-1].upstream = upstream
}

// ArchiveStep performs a single archiving cycle, moving events from memory to disk.
func (s *Store) ArchiveStep(now time.Time) int {
	cutoff := now.Add(-1 * time.Hour).Unix()

	var toArchive []models.QueryEvent
	s.eventsMu.RLock()
	for i := 0; i < s.count; i++ {
		idx := (s.head - 1 - i + s.cfg.MaxEvents) % s.cfg.MaxEvents
		e := s.events[idx]
		if e.UnixTime > s.lastArchivedTime && e.UnixTime <= cutoff {
			toArchive = append(toArchive, e)
		}
	}
	s.eventsMu.RUnlock()

	if len(toArchive) > 0 {
		sort.Slice(toArchive, func(i, j int) bool {
			return toArchive[i].UnixTime < toArchive[j].UnixTime
		})

		files := make(map[string][]models.QueryEvent)
		for _, e := range toArchive {
			dateStr := time.Unix(e.UnixTime, 0).Format("2006-01-02")
			files[dateStr] = append(files[dateStr], e)
		}

		allSuccess := true
		for dateStr, evs := range files {
			filename := fmt.Sprintf("history-%s.jsonl", dateStr)
			path := filepath.Join(s.cfg.HistoryDir, filename)
			f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600) // #nosec G304
			if err != nil {
				log.Printf("Error opening history file %s: %v", path, err)
				allSuccess = false
				continue
			}

			writeErr := func() error {
				for _, e := range evs {
					data, err := json.Marshal(e)
					if err != nil {
						return err
					}
					// Encrypt if password is set
					line := string(data)
					if s.cfg.HistoryPassword != "" {
						encrypted, err := encryption.Encrypt(data, s.cfg.HistoryPassword)
						if err != nil {
							return err
						}
						line = encrypted
					}
					if _, err := fmt.Fprintln(f, line); err != nil {
						return err
					}
				}
				return f.Sync()
			}()

			closeErr := f.Close()
			if writeErr != nil {
				log.Printf("Error writing to history file %s: %v", path, writeErr)
				allSuccess = false
			}
			if closeErr != nil {
				log.Printf("Error closing history file %s: %v", path, closeErr)
				allSuccess = false
			}
		}

		if allSuccess {
			s.lastArchivedTime = cutoff
			log.Printf("Archived %d events to disk", len(toArchive))
		}
	}

	// Cleanup old files
	files, err := os.ReadDir(s.cfg.HistoryDir)
	if err == nil {
		for _, f := range files {
			if strings.HasPrefix(f.Name(), "history-") && strings.HasSuffix(f.Name(), ".jsonl") {
				info, err := f.Info()
				if err == nil && now.Sub(info.ModTime()) > s.cfg.HistoryRetention {
					_ = os.Remove(filepath.Join(s.cfg.HistoryDir, f.Name()))
					log.Printf("Deleted old history file: %s", f.Name())
				}
			}
		}
	}

	// Also cleanup hourly stats
	s.statsMu.Lock()
	cutoffHour := now.Unix()/3600 - int64(s.cfg.HistoryRetention.Hours())
	for h := range s.hourlyStats {
		if h < cutoffHour {
			delete(s.hourlyStats, h)
		}
	}
	s.statsMu.Unlock()
	return len(toArchive)
}

// SetUpstreamHealth updates the latency mapping for upstream DNS servers.
func (s *Store) SetUpstreamHealth(health map[string]float64) {
	s.healthMu.Lock()
	s.upstreamHealth = health
	s.healthMu.Unlock()
}

// GetAlias returns the friendly name for a client IP if configured.
func (s *Store) GetAlias(ip string) string {
	if alias, ok := s.cfg.ClientAliases[ip]; ok {
		return alias
	}
	return ""
}

// StartStatsTrends begins periodic snapshots of top lists for trend analysis.
func (s *Store) StartStatsTrends() {
	go func() {
		for {
			s.updateTrends()
			time.Sleep(5 * time.Minute)
		}
	}()
}

func (s *Store) updateTrends() {
	stats := s.GetStats()
	s.statsMu.Lock()
	if td, ok := stats["top_domains"].([]models.StatEntry); ok {
		s.lastTopStats["domains"] = td
	}
	if tc, ok := stats["top_clients"].([]models.StatEntry); ok {
		s.lastTopStats["clients"] = tc
	}
	s.statsMu.Unlock()
}

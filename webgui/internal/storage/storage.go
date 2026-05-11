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

	hourlyStats map[int64]int
	statsMu     sync.RWMutex

	windowDomainCounts map[string]int
	windowClientCounts map[string]int

	lastArchivedTime int64

	// Cache Hit Ratio tracking (Improvement 98)
	cacheHits    int64
	totalReplies int64
	cacheMu      sync.RWMutex
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
	}
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
	s.eventsMu.Lock()

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

	// Nested locking fixed
	hourBucket := e.UnixTime / 3600
	s.statsMu.Lock()
	s.hourlyStats[hourBucket]++
	s.statsMu.Unlock()
}

// UpdateEvent searches for a matching pending event and updates its latency and upstream.
func (s *Store) UpdateEvent(node, domain string, latency float64, upstream string) {
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
			s.events[idx].LatencyFormatted = fmt.Sprintf("%.1fms", latency)
			s.events[idx].Upstream = upstream

			s.cacheMu.Lock()
			s.totalReplies++
			if upstream == "System Cache" {
				s.cacheHits++
			}
			s.cacheMu.Unlock()
			break
		}
	}
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
	nodeRPM := make(map[string]int)
	nodeRPH := make(map[string]int)

	now := time.Now().Unix()
	rpm := 0
	rph := 0
	rpd := 0
	total := 0

	s.eventsMu.RLock()
	total = s.count
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

	for i := 0; i < s.count; i++ {
		idx := (s.head - 1 - i + s.cfg.MaxEvents) % s.cfg.MaxEvents
		e := s.events[idx]

		nodeName := e.Node
		if nodeName == "" {
			nodeName = "local"
		}

		if e.UnixTime >= now-60 {
			rpm++
			nodeRPM[nodeName]++
		}
		if e.UnixTime >= now-3600 {
			rph++
			nodeRPH[nodeName]++
		}
	}
	s.eventsMu.RUnlock()

	currentHour := now / 3600
	s.statsMu.RLock()
	for h := currentHour - 23; h <= currentHour; h++ {
		rpd += s.hourlyStats[h]
	}
	s.statsMu.RUnlock()

	toStats := func(m map[string]int) []models.StatEntry {
		st := make([]models.StatEntry, 0, len(m))
		for k, v := range m {
			st = append(st, models.StatEntry{Key: k, Count: v})
		}
		sort.Slice(st, func(i, j int) bool { return st[i].Count > st[j].Count })
		if len(st) > 10 {
			st = st[:10]
		}
		return st
	}

	nodeList := make(map[string]interface{})
	for node := range nodeRPH {
		nodeList[node] = map[string]int{
			"rpm": nodeRPM[node],
			"rph": nodeRPH[node],
		}
	}

	// Improvement 98: Calculate cache hit ratio
	s.cacheMu.RLock()
	var cacheRatio float64
	if s.totalReplies > 0 {
		cacheRatio = float64(s.cacheHits) / float64(s.totalReplies) * 100
	}
	s.cacheMu.RUnlock()

	return map[string]interface{}{
		"top_domains":     toStats(domainCounts),
		"top_clients":     toStats(clientCounts),
		"rpm":             rpm,
		"rph":             rph,
		"rpd":             rpd,
		"total":           total,
		"nodes":           nodeList,
		"cache_hit_ratio": cacheRatio,
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

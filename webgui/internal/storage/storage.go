package storage

import (
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
	"tailscale-dnsrewrite/webgui/internal/models"
)

// Store manages the in-memory and persistent storage of DNS events and statistics.
type Store struct {
	cfg      *config.Config
	events   []models.QueryEvent
	head     int
	count    int
	eventsMu sync.RWMutex

	pendingQueries   map[string]map[string]time.Time
	pendingUpstreams map[string]map[string]string
	pendingMu        sync.Mutex

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

// NewStore creates a new storage engine.
func NewStore(cfg *config.Config) *Store {
	return &Store{
		cfg:                cfg,
		events:             make([]models.QueryEvent, cfg.MaxEvents),
		pendingQueries:     make(map[string]map[string]time.Time),
		pendingUpstreams:   make(map[string]map[string]string),
		hourlyStats:        make(map[int64]int),
		windowDomainCounts: make(map[string]int),
		windowClientCounts: make(map[string]int),
		lastArchivedTime:   time.Now().Add(-1 * time.Hour).Unix(),
	}
}

// Init initializes the store by loading historical data.
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
			file, err := os.Open(path)
			if err != nil {
				continue
			}
			scanner := json.NewDecoder(file)
			for scanner.More() {
				var e models.QueryEvent
				if err := scanner.Decode(&e); err == nil {
					if e.UnixTime >= cutoff {
						hour := e.UnixTime / 3600
						s.statsMu.Lock()
						s.hourlyStats[hour]++
						s.statsMu.Unlock()

						// Improvement 98: Recover cache stats from history
						if e.Latency > 0 || e.Upstream != "" {
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
			_ = file.Close()
		}
	}
	s.statsMu.RLock()
	log.Printf("Warmed up stats: %d buckets loaded", len(s.hourlyStats))
	s.statsMu.RUnlock()
}

// AddEvent inserts a new query event into the ring buffer and updates statistics.
func (s *Store) AddEvent(e models.QueryEvent) {
	s.eventsMu.Lock()
	defer s.eventsMu.Unlock()

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

	hourBucket := e.UnixTime / 3600
	s.statsMu.Lock()
	s.hourlyStats[hourBucket]++
	s.statsMu.Unlock()
}

// UpdateEvent searches for an existing event and updates its latency and upstream info.
func (s *Store) UpdateEvent(node, domain string, latency float64, upstream string) {
	s.eventsMu.Lock()
	defer s.eventsMu.Unlock()

	scanLimit := s.count
	if scanLimit > config.DefaultScanLimit {
		scanLimit = config.DefaultScanLimit
	}
	for i := 0; i < scanLimit; i++ {
		idx := (s.head - 1 - i + s.cfg.MaxEvents) % s.cfg.MaxEvents
		if s.events[idx].Domain == domain && s.events[idx].Node == node && s.events[idx].Latency == 0 {
			s.events[idx].Latency = latency
			s.events[idx].Upstream = upstream

			// Improvement 98: Track cache hits
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

// GetOrderedEvents returns a list of events ordered from newest to oldest.
func (s *Store) GetOrderedEvents(limit int) []models.QueryEvent {
	s.eventsMu.RLock()
	defer s.eventsMu.RUnlock()

	n := s.count
	if limit > 0 && n > limit {
		n = limit
	}

	result := make([]models.QueryEvent, 0, n)
	for i := 0; i < n; i++ {
		idx := (s.head - 1 - i + s.cfg.MaxEvents) % s.cfg.MaxEvents
		result = append(result, s.events[idx])
	}
	return result
}

// GetRecentEvents returns events that occurred after the specified unix timestamp.
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
		} else if since > 0 {
			break
		}
	}
	return result
}

// GetStats calculates and returns real-time metrics for the dashboard.
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
		if e.UnixTime < now-3600 {
			break
		}

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

// CleanupPending removes stale entries from the pending queries tracking.
func (s *Store) CleanupPending(now time.Time) int {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	cleaned := 0
	for node, queries := range s.pendingQueries {
		for dom, start := range queries {
			if now.Sub(start) > s.cfg.CleanupInterval {
				delete(queries, dom)
				delete(s.pendingUpstreams[node], dom)
				cleaned++
			}
		}
		if len(queries) == 0 {
			delete(s.pendingQueries, node)
			delete(s.pendingUpstreams, node)
		}
	}
	return cleaned
}

// SetPending marks a query as started.
func (s *Store) SetPending(node, domain string, t time.Time) {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	if s.pendingQueries[node] == nil {
		s.pendingQueries[node] = make(map[string]time.Time)
	}
	s.pendingQueries[node][domain] = t
}

// GetPending retrieves the start time of a query.
func (s *Store) GetPending(node, domain string) (time.Time, bool) {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	t, ok := s.pendingQueries[node][domain]
	return t, ok
}

// RemovePending deletes a query from the pending tracking.
func (s *Store) RemovePending(node, domain string) {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	delete(s.pendingQueries[node], domain)
	delete(s.pendingUpstreams[node], domain)
}

// SetUpstream records the upstream server used for a domain.
func (s *Store) SetUpstream(node, domain, upstream string) {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	if s.pendingUpstreams[node] == nil {
		s.pendingUpstreams[node] = make(map[string]string)
	}
	s.pendingUpstreams[node][domain] = upstream
}

// GetUpstream retrieves the upstream server used for a domain.
func (s *Store) GetUpstream(node, domain string) string {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	return s.pendingUpstreams[node][domain]
}

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

		for dateStr, evs := range files {
			path := fmt.Sprintf("%s/history-%s.jsonl", s.cfg.HistoryDir, dateStr)
			f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600) // #nosec G304
			if err != nil {
				log.Printf("Error opening history file %s: %v", path, err)
				continue
			}
			enc := json.NewEncoder(f)
			for _, e := range evs {
				_ = enc.Encode(e)
			}
			_ = f.Close()
		}
		s.lastArchivedTime = cutoff
		log.Printf("Archived %d events to disk", len(toArchive))
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

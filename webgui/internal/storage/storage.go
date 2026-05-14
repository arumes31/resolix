package storage

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"tailscale-dnsrewrite/webgui/internal/config"
	"tailscale-dnsrewrite/webgui/internal/db"
	"tailscale-dnsrewrite/webgui/internal/models"
)

// Store manages the in-memory ring buffer of events and SQLite disk persistence.
type Store struct {
	cfg      *config.Config
	db       *sql.DB
	events   []models.QueryEvent
	head     int
	count    int
	eventsMu sync.RWMutex

	pendingQueries map[string]map[string][]pendingInfo
	pendingMu      sync.Mutex

	idCounter uint64

	// Database Batching
	batchMu sync.Mutex
	batch   []models.QueryEvent

	statsMu sync.RWMutex

	// Rolling window counters for fast real-time sparklines
	rpmBuckets     [60]int
	rpmTimes       [60]int64
	rphBuckets     [60]int
	rphTimes       [60]int64
	nodeRPMBuckets map[string]*[60]int
	nodeRPMTimes   map[string]*[60]int64
	nodeRPHBuckets map[string]*[60]int
	nodeRPHTimes   map[string]*[60]int64

	// Health and Trends (Per Node)
	nodeUpstreamHealth        map[string]map[string]float64   // node -> upstream -> latency
	nodeUpstreamHealthHistory map[string]map[string][]float64 // node -> upstream -> history
	healthMu                  sync.RWMutex
	lastTopStats              map[string][]models.StatEntry

	// UX Addons
	typeCounts       map[string]int
	clientRPMBuckets map[string]*[60]int
	clientRPMTimes   map[string]*[60]int64
	clientRPHBuckets map[string]*[60]int
	clientRPHTimes   map[string]*[60]int64
}

type pendingInfo struct {
	startTime time.Time
	upstream  string
}

// NewStore initializes a new Store with the provided configuration.
func NewStore(cfg *config.Config) *Store {
	return &Store{
		cfg:                       cfg,
		events:                    make([]models.QueryEvent, cfg.MaxEvents),
		pendingQueries:            make(map[string]map[string][]pendingInfo),
		nodeRPMBuckets:            make(map[string]*[60]int),
		nodeRPMTimes:              make(map[string]*[60]int64),
		nodeRPHBuckets:            make(map[string]*[60]int),
		nodeRPHTimes:              make(map[string]*[60]int64),
		nodeUpstreamHealth:        make(map[string]map[string]float64),
		nodeUpstreamHealthHistory: make(map[string]map[string][]float64),
		lastTopStats:              make(map[string][]models.StatEntry),
		typeCounts:                make(map[string]int),
		clientRPMBuckets:          make(map[string]*[60]int),
		clientRPMTimes:            make(map[string]*[60]int64),
		clientRPHBuckets:          make(map[string]*[60]int),
		clientRPHTimes:            make(map[string]*[60]int64),
		batch:                     make([]models.QueryEvent, 0, 1000),
	}
}

// Init ensures the SQLite database is ready and warms up basic stats.
func (s *Store) Init() {
	database, err := db.InitDB(s.cfg.HistoryDir)
	if err != nil {
		log.Fatalf("Failed to initialize SQLite DB: %v", err)
	}
	s.db = database

	// Warmup basic type counts from DB for current day
	cutoff := time.Now().Add(-24 * time.Hour).Unix()
	rows, err := s.db.Query("SELECT type, COUNT(*) FROM queries WHERE unix_time >= ? GROUP BY type", cutoff)
	if err == nil {
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var t string
			var count int
			if err := rows.Scan(&t, &count); err == nil {
				s.typeCounts[t] = count
			}
		}
		if err := rows.Err(); err != nil {
			log.Printf("Error iterating warmup rows: %v", err)
		}
	}
}

// GetConfig returns the application configuration.
func (s *Store) GetConfig() *config.Config {
	return s.cfg
}

// AddEvent adds a new query event to the ring buffer and batches it for SQLite.
func (s *Store) AddEvent(e models.QueryEvent) {
	s.statsMu.Lock()
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

	// UX tracking
	s.typeCounts[e.Type]++
	if s.clientRPMBuckets[e.ClientIP] == nil {
		s.clientRPMBuckets[e.ClientIP] = &[60]int{}
		s.clientRPMTimes[e.ClientIP] = &[60]int64{}
		s.clientRPHBuckets[e.ClientIP] = &[60]int{}
		s.clientRPHTimes[e.ClientIP] = &[60]int64{}
	}
	if s.clientRPMTimes[e.ClientIP][secBucket] != e.UnixTime {
		s.clientRPMTimes[e.ClientIP][secBucket] = e.UnixTime
		s.clientRPMBuckets[e.ClientIP][secBucket] = 1
	} else {
		s.clientRPMBuckets[e.ClientIP][secBucket]++
	}
	if s.clientRPHTimes[e.ClientIP][minBucket] != minuteStart {
		s.clientRPHTimes[e.ClientIP][minBucket] = minuteStart
		s.clientRPHBuckets[e.ClientIP][minBucket] = 1
	} else {
		s.clientRPHBuckets[e.ClientIP][minBucket]++
	}

	s.statsMu.Unlock()

	s.eventsMu.Lock()
	e.ID = fmt.Sprintf("%d", atomic.AddUint64(&s.idCounter, 1))
	s.events[s.head] = e
	s.head = (s.head + 1) % s.cfg.MaxEvents
	if s.count < s.cfg.MaxEvents {
		s.count++
	}
	s.eventsMu.Unlock()

	// Add to SQLite batch
	s.batchMu.Lock()
	s.batch = append(s.batch, e)
	s.batchMu.Unlock()
}

// UpdateEvent searches for a matching pending event and updates its latency and upstream in memory and batch.
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

			// Also try to update it in the pending batch if it hasn't been written to SQLite yet
			s.batchMu.Lock()
			for b := len(s.batch) - 1; b >= 0; b-- {
				if s.batch[b].Domain == domain && s.batch[b].Node == node && s.batch[b].Latency == nil {
					s.batch[b].Latency = &latency
					s.batch[b].Upstream = upstream
					break
				}
			}
			s.batchMu.Unlock()

			return &s.events[idx]
		}
	}
	return nil
}

// GetOrderedEvents returns the latest N events from memory.
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

// GetRecentEvents returns events newer than the provided unix timestamp from memory.
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

// GetStats returns aggregated traffic statistics using SQLite.
//
//nolint:gocyclo
func (s *Store) GetStats() map[string]interface{} {
	now := time.Now().Unix()
	cutoff24h := now - 86400

	rpm := 0
	rph := 0

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

	typeCounts := make(map[string]int)
	for k, v := range s.typeCounts {
		typeCounts[k] = v
	}
	s.statsMu.RUnlock()

	// Query SQLite for long-term aggregates
	var totalEvents int64
	var rpd int
	if s.db != nil {
		if err := s.db.QueryRow("SELECT COUNT(*) FROM queries").Scan(&totalEvents); err != nil && err != sql.ErrNoRows {
			log.Printf("Error getting totalEvents: %v", err)
		}
		if err := s.db.QueryRow("SELECT COUNT(*) FROM queries WHERE unix_time >= ?", cutoff24h).Scan(&rpd); err != nil && err != sql.ErrNoRows {
			log.Printf("Error getting rpd: %v", err)
		}
	}

	var cacheHits, totalReplies int64
	if s.db != nil {
		if err := s.db.QueryRow("SELECT COUNT(*) FROM queries WHERE upstream = 'System Cache' AND unix_time >= ?", cutoff24h).Scan(&cacheHits); err != nil && err != sql.ErrNoRows {
			log.Printf("Error getting cacheHits: %v", err)
		}
		if err := s.db.QueryRow("SELECT COUNT(*) FROM queries WHERE upstream != '' AND unix_time >= ?", cutoff24h).Scan(&totalReplies); err != nil && err != sql.ErrNoRows {
			log.Printf("Error getting totalReplies: %v", err)
		}
	}

	cacheHitRatio := 0.0
	if totalReplies > 0 {
		cacheHitRatio = float64(cacheHits) / float64(totalReplies) * 100
	}

	domainCounts := make(map[string]int)
	clientCounts := make(map[string]int)
	heatmap := make(map[string]int)

	if s.db != nil {
		// Top 10 Domains
		rowsDomains, err := s.db.Query("SELECT domain, COUNT(*) as c FROM queries WHERE unix_time >= ? GROUP BY domain ORDER BY c DESC LIMIT 10", cutoff24h)
		if err == nil {
			defer func() { _ = rowsDomains.Close() }()
			for rowsDomains.Next() {
				var d string
				var c int
				if rowsDomains.Scan(&d, &c) == nil {
					domainCounts[d] = c
				}
			}
			if err := rowsDomains.Err(); err != nil {
				log.Printf("Error iterating domain rows: %v", err)
			}
		}

		// Top 10 Clients
		rowsClients, err := s.db.Query("SELECT client_ip, COUNT(*) as c FROM queries WHERE unix_time >= ? GROUP BY client_ip ORDER BY c DESC LIMIT 10", cutoff24h)
		if err == nil {
			defer func() { _ = rowsClients.Close() }()
			for rowsClients.Next() {
				var ip string
				var c int
				if rowsClients.Scan(&ip, &c) == nil {
					clientCounts[ip] = c
				}
			}
			if err := rowsClients.Err(); err != nil {
				log.Printf("Error iterating client rows: %v", err)
			}
		}

		// Hourly heatmap
		currentHour := now / 3600
		rowsHeatmap, err := s.db.Query("SELECT unix_time / 3600 as hr, COUNT(*) FROM queries WHERE unix_time >= ? GROUP BY hr", cutoff24h)
		if err == nil {
			defer func() { _ = rowsHeatmap.Close() }()
			for rowsHeatmap.Next() {
				var hr int64
				var c int
				if rowsHeatmap.Scan(&hr, &c) == nil {
					t := time.Unix(hr*3600, 0)
					heatmap[t.Format("15:00")] = c
				}
			}
			if err := rowsHeatmap.Err(); err != nil {
				log.Printf("Error iterating heatmap rows: %v", err)
			}
		}

		// Fill missing hours in heatmap
		for h := currentHour - 23; h <= currentHour; h++ {
			t := time.Unix(h*3600, 0)
			k := t.Format("15:00")
			if _, exists := heatmap[k]; !exists {
				heatmap[k] = 0
			}
		}
	}

	s.healthMu.RLock()
	nodeHealth := make(map[string]map[string]float64)
	nodeHealthHist := make(map[string]map[string][]float64)
	for node, upstreams := range s.nodeUpstreamHealth {
		nodeHealth[node] = make(map[string]float64)
		nodeHealthHist[node] = make(map[string][]float64)
		for up, lat := range upstreams {
			nodeHealth[node][up] = lat
			if hist, ok := s.nodeUpstreamHealthHistory[node][up]; ok {
				nodeHealthHist[node][up] = append([]float64(nil), hist...)
			}
		}
	}
	s.healthMu.RUnlock()

	return map[string]interface{}{
		"top_domains":      s.toStats(domainCounts, "domains"),
		"top_clients":      s.toStats(clientCounts, "clients"),
		"rpm":              rpm,
		"rph":              rph,
		"rpd":              rpd,
		"total":            totalEvents,
		"nodes":            nodeList,
		"cache_hit_ratio":  cacheHitRatio,
		"node_health":      nodeHealth,
		"node_health_hist": nodeHealthHist,
		"heatmap":          heatmap,
		"type_counts":      typeCounts,
	}
}

func (s *Store) toStats(m map[string]int, category string) []models.StatEntry {
	st := make([]models.StatEntry, 0, len(m))
	for k, v := range m {
		entry := models.StatEntry{Key: k, Count: v}
		if category == "clients" {
			if alias, ok := s.cfg.ClientAliases[k]; ok {
				entry.Alias = alias
			}
		}
		s.statsMu.RLock()
		if last, ok := s.lastTopStats[category]; ok {
			for _, le := range last {
				if le.Key == k {
					switch {
					case v > le.Count:
						entry.Trend = "up"
					case v < le.Count:
						entry.Trend = "down"
					default:
						entry.Trend = "stable"
					}
					break
				}
			}
		}
		s.statsMu.RUnlock()
		st = append(st, entry)
	}

	sort.Slice(st, func(i, j int) bool {
		return st[i].Count > st[j].Count
	})

	if len(st) > 10 {
		st = st[:10]
	}
	return st
}

// GetClientStats returns the RPM/RPH stats for a specific client.
func (s *Store) GetClientStats(ip string) map[string]interface{} {
	s.statsMu.RLock()
	defer s.statsMu.RUnlock()

	now := time.Now().Unix()
	rpm := 0
	rph := 0
	rpmHistory := make([]int, 60)

	rpmBuckets := s.clientRPMBuckets[ip]
	rpmTimes := s.clientRPMTimes[ip]
	rphBuckets := s.clientRPHBuckets[ip]
	rphTimes := s.clientRPHTimes[ip]

	if rpmBuckets != nil && rpmTimes != nil {
		for i := 0; i < 60; i++ {
			if now-rpmTimes[i] < 60 {
				rpm += rpmBuckets[i]
			}
			idx := (now - 59 + int64(i)) % 60
			if now-rpmTimes[idx] < 60 {
				rpmHistory[i] = rpmBuckets[idx]
			}
		}
	}
	if rphBuckets != nil && rphTimes != nil {
		for i := 0; i < 60; i++ {
			if now-rphTimes[i] < 3600 {
				rph += rphBuckets[i]
			}
		}
	}

	return map[string]interface{}{
		"ip":          ip,
		"alias":       s.cfg.ClientAliases[ip],
		"rpm":         rpm,
		"rph":         rph,
		"rpm_history": rpmHistory,
	}
}

// CleanupPending removes stale entries from the pending query map.
func (s *Store) CleanupPending(now time.Time) {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	cutoff := now.Add(-30 * time.Second)
	for node, domains := range s.pendingQueries {
		for domain, infos := range domains {
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
	infos[len(infos)-1].upstream = upstream
}

// ArchiveStep performs a batch insert of recent queries into SQLite and deletes old ones.
func (s *Store) ArchiveStep(now time.Time) int {
	s.batchMu.Lock()
	if len(s.batch) == 0 {
		s.batchMu.Unlock()
		return 0
	}
	toInsert := s.batch
	s.batch = make([]models.QueryEvent, 0, 1000)
	s.batchMu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		log.Printf("Failed to begin SQLite transaction: %v", err)
		return 0
	}

	stmt, err := tx.Prepare("INSERT INTO queries (unix_time, node, client_ip, domain, type, upstream, latency) VALUES (?, ?, ?, ?, ?, ?, ?)")
	if err != nil {
		_ = tx.Rollback()
		log.Printf("Failed to prepare SQLite statement: %v", err)
		return 0
	}
	defer func() { _ = stmt.Close() }()

	for _, e := range toInsert {
		var lat sql.NullFloat64
		if e.Latency != nil {
			lat.Float64 = *e.Latency
			lat.Valid = true
		}
		_, err = stmt.Exec(e.UnixTime, e.Node, e.ClientIP, e.Domain, e.Type, e.Upstream, lat)
		if err != nil {
			log.Printf("Error inserting event into SQLite: %v", err)
		}
	}

	if err := tx.Commit(); err != nil {
		log.Printf("Failed to commit SQLite transaction: %v", err)
		return 0
	}

	// Delete old data based on retention policy
	cutoff := now.Add(-s.cfg.HistoryRetention).Unix()
	_, err = s.db.Exec("DELETE FROM queries WHERE unix_time < ?", cutoff)
	if err != nil {
		log.Printf("Failed to prune old SQLite data: %v", err)
	}

	return len(toInsert)
}

// SetUpstreamHealth updates the latency mapping and history for upstream DNS servers for a specific node.
func (s *Store) SetUpstreamHealth(node string, health map[string]float64) {
	if node == "" {
		node = "local"
	}
	s.healthMu.Lock()
	defer s.healthMu.Unlock()

	if s.nodeUpstreamHealth[node] == nil {
		s.nodeUpstreamHealth[node] = make(map[string]float64)
		s.nodeUpstreamHealthHistory[node] = make(map[string][]float64)
	}

	s.nodeUpstreamHealth[node] = health
	for ip, lat := range health {
		hist := s.nodeUpstreamHealthHistory[node][ip]
		hist = append(hist, lat)
		if len(hist) > 20 {
			hist = hist[1:]
		}
		s.nodeUpstreamHealthHistory[node][ip] = hist
	}
}

// GetAlias returns the friendly name for a client IP if configured.
func (s *Store) GetAlias(ip string) string {
	if alias, ok := s.cfg.ClientAliases[ip]; ok {
		return alias
	}
	return ""
}

// StartStatsTrends begins periodic snapshots of top lists for trend analysis.
func (s *Store) StartStatsTrends(ctx context.Context) {
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Minute):
				s.updateTrends()
			}
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

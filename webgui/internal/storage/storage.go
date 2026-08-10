package storage

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"sort"
	"strconv"
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
	dbMu     sync.RWMutex
	closed   bool
	events   []models.QueryEvent
	head     int
	count    int
	eventsMu sync.RWMutex

	pendingQueries map[string]map[string][]pendingInfo
	pendingMu      sync.Mutex

	idCounter uint64

	// Database Batching
	batchMu   sync.Mutex
	batch     []models.QueryEvent
	archiveMu sync.Mutex

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

	// Node status tracking (Items 89, 92, 93)
	nodeStatuses map[string]*models.NodeStatus // node name -> status
	nodeStatusMu sync.RWMutex

	// UX Addons
	typeCounts       map[string]int
	clientRPMBuckets map[string]*[60]int
	clientRPMTimes   map[string]*[60]int64
	clientRPHBuckets map[string]*[60]int
	clientRPHTimes   map[string]*[60]int64
	clientLastSeen   map[string]int64

	// Prepared statements for frequently-used queries (cached at init)
	stmtInsertQuery   *sql.Stmt
	stmtGetTopDomains *sql.Stmt
	stmtGetTopClients *sql.Stmt
	stmtCleanup       *sql.Stmt

	// Background maintenance context
	ctx    context.Context
	cancel context.CancelFunc

	// Configurable intervals for background maintenance
	vacuumInterval     time.Duration
	checkpointInterval time.Duration
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
		nodeStatuses:              make(map[string]*models.NodeStatus),
		typeCounts:                make(map[string]int),
		clientRPMBuckets:          make(map[string]*[60]int),
		clientRPMTimes:            make(map[string]*[60]int64),
		clientRPHBuckets:          make(map[string]*[60]int),
		clientRPHTimes:            make(map[string]*[60]int64),
		clientLastSeen:            make(map[string]int64),
		batch:                     make([]models.QueryEvent, 0, 1000),
		vacuumInterval:            24 * time.Hour,
		checkpointInterval:        5 * time.Minute,
	}
}

// DB returns the underlying database connection for testing purposes.
func (s *Store) DB() *sql.DB {
	return s.db
}

// Init ensures the SQLite database is ready, prepares cached statements, and warms up basic stats.
func (s *Store) Init() {
	database, err := db.InitDB(s.cfg.FullDBPath())
	if err != nil {
		log.Fatalf("Failed to initialize SQLite DB: %v", err)
	}
	s.db = database

	// Prepare frequently-used SQL statements for caching (Task 20)
	if err := s.prepareStatements(); err != nil {
		log.Fatalf("Failed to prepare cached SQL statements: %v", err)
	}

	// Create background maintenance context
	s.ctx, s.cancel = context.WithCancel(context.Background())

	// Start background maintenance goroutines
	s.startVacuum(s.ctx)
	s.startWALCheckpoint(s.ctx)

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

// prepareStatements creates prepared statements for frequently-used queries and stores them on the Store.
func (s *Store) prepareStatements() error {
	var err error

	s.stmtInsertQuery, err = s.db.Prepare(
		"INSERT INTO queries (unix_time, node, client_ip, domain, type, upstream, latency, dnssec, response_code, client_hostname, blocked, latency_alert, matched_rule, block_reason) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
	if err != nil {
		return fmt.Errorf("prepare stmtInsertQuery: %w", err)
	}

	s.stmtGetTopDomains, err = s.db.Prepare(
		"SELECT domain, COUNT(*) as c FROM queries WHERE unix_time >= ? GROUP BY domain ORDER BY c DESC LIMIT 10")
	if err != nil {
		return fmt.Errorf("prepare stmtGetTopDomains: %w", err)
	}

	s.stmtGetTopClients, err = s.db.Prepare(
		"SELECT client_ip, COUNT(*) as c FROM queries WHERE unix_time >= ? GROUP BY client_ip ORDER BY c DESC LIMIT 10")
	if err != nil {
		return fmt.Errorf("prepare stmtGetTopClients: %w", err)
	}

	s.stmtCleanup, err = s.db.Prepare(
		"DELETE FROM queries WHERE unix_time < ?")
	if err != nil {
		return fmt.Errorf("prepare stmtCleanup: %w", err)
	}

	log.Printf("Prepared SQL statements cached successfully")
	return nil
}

// Close releases all prepared statements and cancels background maintenance goroutines.
func (s *Store) Close() {
	s.dbMu.Lock()
	defer s.dbMu.Unlock()
	if s.closed {
		return
	}
	s.closed = true

	// Cancel background goroutines
	if s.cancel != nil {
		s.cancel()
	}

	// Close prepared statements
	if s.stmtInsertQuery != nil {
		_ = s.stmtInsertQuery.Close()
		s.stmtInsertQuery = nil
	}
	if s.stmtGetTopDomains != nil {
		_ = s.stmtGetTopDomains.Close()
		s.stmtGetTopDomains = nil
	}
	if s.stmtGetTopClients != nil {
		_ = s.stmtGetTopClients.Close()
		s.stmtGetTopClients = nil
	}
	if s.stmtCleanup != nil {
		_ = s.stmtCleanup.Close()
		s.stmtCleanup = nil
	}

	// Close database connection
	if s.db != nil {
		_ = s.db.Close()
		s.db = nil
	}

	log.Printf("Store closed: prepared statements released, background goroutines stopped")
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
	s.clientLastSeen[e.ClientIP] = e.UnixTime

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
func (s *Store) UpdateEvent(node, domain string, latency float64, upstream string, responseCodes ...string) *models.QueryEvent {
	s.eventsMu.Lock()
	defer s.eventsMu.Unlock()
	responseCode := ""
	if len(responseCodes) > 0 {
		responseCode = responseCodes[0]
	}

	scanLimit := s.count
	if scanLimit > config.DefaultScanLimit {
		scanLimit = config.DefaultScanLimit
	}
	for i := 0; i < scanLimit; i++ {
		idx := (s.head - 1 - i + s.cfg.MaxEvents) % s.cfg.MaxEvents
		if s.events[idx].Domain == domain && s.events[idx].Node == node && !s.events[idx].Latency.Valid {
			s.events[idx].Latency = sql.NullFloat64{Float64: latency, Valid: true}
			s.events[idx].Upstream = upstream
			s.events[idx].ResponseCode = responseCode

			// Item 68: Check latency alert threshold
			if latency > float64(s.cfg.UpstreamLatencyThreshold) {
				s.events[idx].LatencyAlert = true
			}

			// Also try to update it in the pending batch if it hasn't been written to SQLite yet
			s.batchMu.Lock()
			for b := len(s.batch) - 1; b >= 0; b-- {
				if s.batch[b].Domain == domain && s.batch[b].Node == node && !s.batch[b].Latency.Valid {
					s.batch[b].Latency = sql.NullFloat64{Float64: latency, Valid: true}
					s.batch[b].Upstream = upstream
					// Propagate DNSSEC and ResponseCode from the in-memory event to the batch
					s.batch[b].DNSSEC = s.events[idx].DNSSEC
					s.batch[b].ResponseCode = s.events[idx].ResponseCode
					s.batch[b].LatencyAlert = s.events[idx].LatencyAlert
					s.batch[b].ClientHostname = s.events[idx].ClientHostname
					s.batch[b].Blocked = s.events[idx].Blocked
					break
				}
			}
			s.batchMu.Unlock()

			return &s.events[idx]
		}
	}
	return nil
}

// SetBlocked marks an event as blocked in the in-memory ring buffer and batch.
func (s *Store) SetBlocked(node, domain string) bool {
	s.eventsMu.Lock()
	defer s.eventsMu.Unlock()

	scanLimit := s.count
	if scanLimit > config.DefaultScanLimit {
		scanLimit = config.DefaultScanLimit
	}
	for i := 0; i < scanLimit; i++ {
		idx := (s.head - 1 - i + s.cfg.MaxEvents) % s.cfg.MaxEvents
		if s.events[idx].Domain == domain && s.events[idx].Node == node {
			if s.events[idx].Blocked {
				return true
			}
			s.events[idx].Blocked = true

			// Also update in the pending batch
			s.batchMu.Lock()
			for b := len(s.batch) - 1; b >= 0; b-- {
				if s.batch[b].Domain == domain && s.batch[b].Node == node {
					if !s.batch[b].Blocked {
						s.batch[b].Blocked = true
					}
					break
				}
			}
			s.batchMu.Unlock()
			return false
		}
	}
	return false
}

// SetClientHostname sets the hostname for the most recent event of a client IP on a node.
func (s *Store) SetClientHostname(node, clientIP, hostname string) bool {
	s.eventsMu.Lock()
	defer s.eventsMu.Unlock()

	scanLimit := s.count
	if scanLimit > config.DefaultScanLimit {
		scanLimit = config.DefaultScanLimit
	}
	for i := 0; i < scanLimit; i++ {
		idx := (s.head - 1 - i + s.cfg.MaxEvents) % s.cfg.MaxEvents
		if s.events[idx].ClientIP == clientIP && s.events[idx].Node == node {
			if s.events[idx].ClientHostname == hostname {
				return true
			}
			s.events[idx].ClientHostname = hostname

			// Also update in the pending batch
			s.batchMu.Lock()
			for b := len(s.batch) - 1; b >= 0; b-- {
				if s.batch[b].ClientIP == clientIP && s.batch[b].Node == node {
					s.batch[b].ClientHostname = hostname
					break
				}
			}
			s.batchMu.Unlock()
			return false
		}
	}
	return false
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
	n := min(s.count, config.DefaultScanLimit)
	result := make([]models.QueryEvent, 0, n)
	for i := 0; i < n; i++ {
		idx := (s.head - 1 - i + s.cfg.MaxEvents) % s.cfg.MaxEvents
		if event := s.events[idx]; event.UnixTime > since {
			result = append(result, event)
		}
	}
	return result
}

// GetEventsAfter returns events newer than cursor, or newer than since when
// no cursor is supplied. Results are oldest-first and bounded by limit.
func (s *Store) GetEventsAfter(cursor string, since int64, limit int) []models.QueryEvent {
	s.eventsMu.RLock()
	defer s.eventsMu.RUnlock()

	n := s.count
	if limit <= 0 || limit > config.DefaultScanLimit {
		limit = config.DefaultScanLimit
	}

	cursorID, _ := strconv.ParseUint(cursor, 10, 64)
	result := make([]models.QueryEvent, 0, min(n, limit))
	for i := 0; i < n; i++ {
		idx := (s.head - n + i + s.cfg.MaxEvents) % s.cfg.MaxEvents
		e := s.events[idx]
		eventID, _ := strconv.ParseUint(e.ID, 10, 64)
		if (cursorID > 0 && eventID > cursorID) || (cursorID == 0 && e.UnixTime > since) {
			result = append(result, e)
			if len(result) == limit {
				break
			}
		}
	}
	return result
}

// GetStats returns aggregated traffic statistics using SQLite.
//
//nolint:gocyclo
func (s *Store) GetStats() map[string]interface{} {
	s.archiveMu.Lock()
	defer s.archiveMu.Unlock()
	s.dbMu.RLock()
	defer s.dbMu.RUnlock()

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
	var queryErrors []string
	if s.db != nil {
		if err := s.db.QueryRow("SELECT COUNT(*) FROM queries").Scan(&totalEvents); err != nil && err != sql.ErrNoRows {
			log.Printf("Error getting totalEvents: %v", err)
			queryErrors = append(queryErrors, "total")
		}
		if err := s.db.QueryRow("SELECT COUNT(*) FROM queries WHERE unix_time >= ?", cutoff24h).Scan(&rpd); err != nil && err != sql.ErrNoRows {
			log.Printf("Error getting rpd: %v", err)
			queryErrors = append(queryErrors, "rpd")
		}
	}

	var cacheHits, totalReplies int64
	if s.db != nil {
		if err := s.db.QueryRow("SELECT COUNT(*) FROM queries WHERE upstream = 'System Cache' AND unix_time >= ?", cutoff24h).Scan(&cacheHits); err != nil && err != sql.ErrNoRows {
			log.Printf("Error getting cacheHits: %v", err)
			queryErrors = append(queryErrors, "cache_hits")
		}
		if err := s.db.QueryRow("SELECT COUNT(*) FROM queries WHERE upstream != '' AND unix_time >= ?", cutoff24h).Scan(&totalReplies); err != nil && err != sql.ErrNoRows {
			log.Printf("Error getting totalReplies: %v", err)
			queryErrors = append(queryErrors, "total_replies")
		}
	}

	s.batchMu.Lock()
	pending := append([]models.QueryEvent(nil), s.batch...)
	s.batchMu.Unlock()
	totalEvents += int64(len(pending))
	for _, event := range pending {
		if event.UnixTime < cutoff24h {
			continue
		}
		rpd++
		if event.Upstream != "" {
			totalReplies++
		}
		if event.Upstream == "System Cache" {
			cacheHits++
		}
	}

	cacheHitRatio := 0.0
	if totalReplies > 0 {
		cacheHitRatio = float64(cacheHits) / float64(totalReplies) * 100
	}

	// Item 67: Bandwidth savings estimate (100 bytes per cached query)
	bandwidthSaved := cacheHits * 100

	domainCounts := make(map[string]int)
	clientCounts := make(map[string]int)
	heatmap := make(map[string]int)

	if s.db != nil {
		// Top 10 Domains (use cached prepared statement if available)
		if s.stmtGetTopDomains != nil {
			rowsDomains, err := s.stmtGetTopDomains.Query(cutoff24h)
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
		}

		// Top 10 Clients (use cached prepared statement if available)
		if s.stmtGetTopClients != nil {
			rowsClients, err := s.stmtGetTopClients.Query(cutoff24h)
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
		"bandwidth_saved":  bandwidthSaved,
		"degraded":         len(queryErrors) > 0,
		"errors":           queryErrors,
	}
}

func (s *Store) toStats(m map[string]int, category string) []models.StatEntry {
	st := make([]models.StatEntry, 0, len(m))
	for k, v := range m {
		entry := models.StatEntry{Key: k, Count: v}
		if category == "clients" {
			entry.Alias = s.cfg.GetClientAlias(k)
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
		}
		for i := 0; i < 60; i++ {
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
		"alias":       s.cfg.GetClientAlias(ip),
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

	s.statsMu.Lock()
	clientCutoff := now.Add(-time.Hour).Unix()
	for client, lastSeen := range s.clientLastSeen {
		if lastSeen >= clientCutoff {
			continue
		}
		delete(s.clientLastSeen, client)
		delete(s.clientRPMBuckets, client)
		delete(s.clientRPMTimes, client)
		delete(s.clientRPHBuckets, client)
		delete(s.clientRPHTimes, client)
	}
	s.statsMu.Unlock()
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

// SetDNSSEC updates the DNSSEC validation status for the most recent query of a domain on a node.
func (s *Store) SetDNSSEC(node, domain, result string) {
	s.eventsMu.Lock()
	defer s.eventsMu.Unlock()

	scanLimit := s.count
	if scanLimit > config.DefaultScanLimit {
		scanLimit = config.DefaultScanLimit
	}
	for i := 0; i < scanLimit; i++ {
		idx := (s.head - 1 - i + s.cfg.MaxEvents) % s.cfg.MaxEvents
		if s.events[idx].Domain == domain && s.events[idx].Node == node {
			s.events[idx].DNSSEC = result
			// Also update in the pending batch
			s.batchMu.Lock()
			for b := len(s.batch) - 1; b >= 0; b-- {
				if s.batch[b].Domain == domain && s.batch[b].Node == node {
					s.batch[b].DNSSEC = result
					break
				}
			}
			s.batchMu.Unlock()
			return
		}
	}
}

// ArchiveStep performs a batch insert of recent queries into SQLite and deletes old ones.
func (s *Store) ArchiveStep(now time.Time) int {
	s.archiveMu.Lock()
	defer s.archiveMu.Unlock()
	s.dbMu.RLock()
	defer s.dbMu.RUnlock()
	if s.closed || s.db == nil {
		return 0
	}

	s.batchMu.Lock()
	toInsert := append([]models.QueryEvent(nil), s.batch...)
	s.batchMu.Unlock()
	if len(toInsert) == 0 {
		s.pruneOldEvents(now)
		return 0
	}

	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		log.Printf("Failed to begin SQLite transaction; retaining %d events for retry: %v", len(toInsert), err)
		return 0
	}

	// Use cached prepared statement within the transaction via tx.Stmt()
	var stmt *sql.Stmt
	if s.stmtInsertQuery != nil {
		stmt = tx.Stmt(s.stmtInsertQuery)
	} else {
		stmt, err = tx.Prepare("INSERT INTO queries (unix_time, node, client_ip, domain, type, upstream, latency, dnssec, response_code, client_hostname, blocked, latency_alert, matched_rule, block_reason) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
		if err != nil {
			_ = tx.Rollback()
			log.Printf("Failed to prepare SQLite statement; retaining %d events for retry: %v", len(toInsert), err)
			return 0
		}
	}
	defer func() { _ = stmt.Close() }()

	for _, e := range toInsert {
		blockedInt := 0
		if e.Blocked {
			blockedInt = 1
		}
		latencyAlertInt := 0
		if e.LatencyAlert {
			latencyAlertInt = 1
		}
		_, err = stmt.Exec(e.UnixTime, e.Node, e.ClientIP, e.Domain, e.Type, e.Upstream, e.Latency, e.DNSSEC, e.ResponseCode, e.ClientHostname, blockedInt, latencyAlertInt, e.MatchedRule, e.BlockReason)
		if err != nil {
			_ = tx.Rollback()
			log.Printf("Failed to insert SQLite batch; retaining %d events for retry: %v", len(toInsert), err)
			return 0
		}
	}

	if err := tx.Commit(); err != nil {
		log.Printf("Failed to commit SQLite transaction; retaining %d events for retry: %v", len(toInsert), err)
		return 0
	}

	s.batchMu.Lock()
	if len(s.batch) >= len(toInsert) {
		s.batch = s.batch[len(toInsert):]
	}
	s.batchMu.Unlock()

	s.pruneOldEvents(now)
	return len(toInsert)
}

func (s *Store) pruneOldEvents(now time.Time) {
	cutoff := now.Add(-s.cfg.HistoryRetention).Unix()
	var err error
	if s.stmtCleanup != nil {
		_, err = s.stmtCleanup.Exec(cutoff)
	} else {
		_, err = s.db.Exec("DELETE FROM queries WHERE unix_time < ?", cutoff)
	}
	if err != nil {
		log.Printf("Failed to prune old SQLite data: %v", err)
	}
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

// GetUpstreamHealth returns a deep copy of the current upstream health data (node -> upstream -> latency).
// This is the exported accessor for the unexported nodeUpstreamHealth map.
func (s *Store) GetUpstreamHealth() map[string]map[string]float64 {
	s.healthMu.RLock()
	defer s.healthMu.RUnlock()

	result := make(map[string]map[string]float64, len(s.nodeUpstreamHealth))
	for node, upstreams := range s.nodeUpstreamHealth {
		result[node] = make(map[string]float64, len(upstreams))
		for up, lat := range upstreams {
			result[node][up] = lat
		}
	}
	return result
}

// SetNodeStatus updates the status of a node (Items 89, 92, 93).
// This is called when a heartbeat is received from a slave node.
func (s *Store) SetNodeStatus(name string, status models.NodeStatus) {
	if name == "" {
		name = "unknown"
	}
	s.nodeStatusMu.Lock()
	defer s.nodeStatusMu.Unlock()

	status.Online = true
	status.LastSeen = time.Now()
	s.nodeStatuses[name] = &status
}

// GetNodeStatus returns the status of a single node by name.
func (s *Store) GetNodeStatus(name string) *models.NodeStatus {
	s.nodeStatusMu.RLock()
	defer s.nodeStatusMu.RUnlock()

	if ns, ok := s.nodeStatuses[name]; ok {
		// Return a copy
		result := *ns
		result.Online = ns.IsOnline(s.cfg.NodeOfflineThreshold)
		return &result
	}
	return nil
}

// GetNodeStatuses returns a copy of all node statuses with online state computed.
func (s *Store) GetNodeStatuses() []models.NodeStatus {
	s.nodeStatusMu.RLock()
	defer s.nodeStatusMu.RUnlock()

	result := make([]models.NodeStatus, 0, len(s.nodeStatuses))
	for _, ns := range s.nodeStatuses {
		copy := *ns
		copy.Online = ns.IsOnline(s.cfg.NodeOfflineThreshold)
		result = append(result, copy)
	}
	return result
}

// GetAlias returns the friendly name for a client IP if configured.
func (s *Store) GetAlias(ip string) string {
	return s.cfg.GetClientAlias(ip)
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

// startVacuum runs a background goroutine that periodically executes VACUUM
// to reclaim disk space from deleted rows. Default interval: 24 hours.
func (s *Store) startVacuum(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(s.vacuumInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.dbMu.RLock()
				if s.closed || s.db == nil {
					s.dbMu.RUnlock()
					return
				}
				log.Printf("Database VACUUM started")
				start := time.Now()
				_, err := s.db.ExecContext(ctx, "VACUUM;")
				if err != nil {
					log.Printf("Database VACUUM failed: %v", err)
				} else {
					log.Printf("Database VACUUM completed in %s", time.Since(start).Round(time.Millisecond))
				}
				s.dbMu.RUnlock()
			}
		}
	}()
	log.Printf("Periodic VACUUM started (interval: %s)", s.vacuumInterval)
}

// startWALCheckpoint runs a background goroutine that periodically executes
// PRAGMA wal_checkpoint(TRUNCATE) to prevent the WAL file from growing too large.
// Default interval: 5 minutes.
func (s *Store) startWALCheckpoint(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(s.checkpointInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.dbMu.RLock()
				if s.closed || s.db == nil {
					s.dbMu.RUnlock()
					return
				}
				var busy, logFrames, checkpointed int
				row := s.db.QueryRowContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE);")
				if err := row.Scan(&busy, &logFrames, &checkpointed); err != nil {
					log.Printf("WAL checkpoint failed: %v", err)
				} else {
					log.Printf("WAL checkpoint completed: busy=%d, logFrames=%d, checkpointed=%d", busy, logFrames, checkpointed)
				}
				s.dbMu.RUnlock()
			}
		}
	}()
	log.Printf("Periodic WAL checkpoint started (interval: %s)", s.checkpointInterval)
}

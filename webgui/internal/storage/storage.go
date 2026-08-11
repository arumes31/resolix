package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/arumes31/resolix/webgui/internal/config"
	"github.com/arumes31/resolix/webgui/internal/db"
	"github.com/arumes31/resolix/webgui/internal/models"
)

const (
	archiveRetryInitialDelay = time.Second
	archiveRetryMaxDelay     = time.Minute
	archiveDropLogInterval   = time.Minute
	archiveInsertRows        = 64
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
	batchMu          sync.Mutex
	batch            []models.QueryEvent
	batchStart       int
	batchBytes       int64
	batchDropped     atomic.Int64
	batchInFlight    atomic.Int64
	batchFlightBytes atomic.Int64
	archiveMu        sync.Mutex
	archiveReady     chan struct{}
	archiveMark      int
	archiveLimit     int
	archiveBatch     int

	// Protected by batchMu.
	batchDropLogAt      time.Time
	batchDropUnreported int64

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
	nodeStatuses   map[string]*models.NodeStatus // stable node ID -> status
	nodeTombstones map[string]time.Time          // stable node ID -> decommission time
	nodeStatusMu   sync.RWMutex

	// UX Addons
	typeCounts       map[string]int
	clientRPMBuckets map[string]*[60]int
	clientRPMTimes   map[string]*[60]int64
	clientRPHBuckets map[string]*[60]int
	clientRPHTimes   map[string]*[60]int64
	clientLastSeen   map[string]int64

	// Prepared statements for frequently-used queries (cached at init)
	stmtGetTopDomains *sql.Stmt
	stmtGetTopClients *sql.Stmt

	// Background maintenance context
	ctx    context.Context
	cancel context.CancelFunc

	// Configurable intervals for background maintenance
	vacuumInterval     time.Duration
	checkpointInterval time.Duration
	maintenanceMu      sync.RWMutex
	checkpointState    checkpointState
	vacuumState        vacuumState
	optimizeState      optimizeState
	dbBusyErrors       atomic.Int64

	// archiveInsert is overridden by tests that need to hold an archive write
	// in flight. Production always uses insertArchiveBatch.
	archiveInsert func(context.Context, []models.QueryEvent) error
}

type pendingInfo struct {
	startTime time.Time
	upstream  string
}

// ArchiveQueueMetrics describes current SQLite archive queue pressure and limits.
type ArchiveQueueMetrics struct {
	Pending      int
	PendingBytes int64
	Dropped      int64
	Capacity     int
	Trigger      int
	WriteBatch   int
}

func archiveLimits(cfg *config.Config) (capacity, trigger, writeBatch int) {
	capacity = cfg.ArchiveQueueCapacity
	if capacity < 1 {
		capacity = config.DefaultArchiveQueueCapacity
	}
	trigger = cfg.ArchiveTriggerSize
	if trigger < 1 || trigger > capacity {
		trigger = min(config.DefaultArchiveTriggerSize, max(1, capacity/2))
	}
	writeBatch = cfg.ArchiveWriteBatchSize
	if writeBatch < 1 || writeBatch > capacity {
		writeBatch = min(config.DefaultArchiveWriteBatchSize, capacity)
	}
	return capacity, trigger, writeBatch
}

// NewStore initializes a new Store with the provided configuration.
func NewStore(cfg *config.Config) *Store {
	archiveCapacity, archiveTrigger, archiveWriteBatch := archiveLimits(cfg)
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
		nodeTombstones:            make(map[string]time.Time),
		typeCounts:                make(map[string]int),
		clientRPMBuckets:          make(map[string]*[60]int),
		clientRPMTimes:            make(map[string]*[60]int64),
		clientRPHBuckets:          make(map[string]*[60]int),
		clientRPHTimes:            make(map[string]*[60]int64),
		clientLastSeen:            make(map[string]int64),
		batch:                     make([]models.QueryEvent, 0, min(1000, archiveCapacity)),
		archiveReady:              make(chan struct{}, 1),
		archiveMark:               archiveTrigger,
		archiveLimit:              archiveCapacity,
		archiveBatch:              archiveWriteBatch,
		vacuumInterval:            24 * time.Hour,
		checkpointInterval:        5 * time.Minute,
	}
}

func (s *Store) pendingBatchLenLocked() int {
	return len(s.batch) - s.batchStart
}

func (s *Store) pendingBatchLocked() []models.QueryEvent {
	return s.batch[s.batchStart:]
}

func (s *Store) compactBatchLocked() {
	if s.batchStart == 0 {
		return
	}
	pending := copy(s.batch, s.batch[s.batchStart:])
	clear(s.batch[pending:])
	s.batch = s.batch[:pending]
	s.batchStart = 0
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
	s.loadNodeTombstones()

	// Prepare frequently-used SQL statements for caching (Task 20)
	if err := s.prepareStatements(); err != nil {
		log.Fatalf("Failed to prepare cached SQL statements: %v", err)
	}

	// Create background maintenance context
	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.optimizeDatabase(s.ctx)

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

	s.stmtGetTopDomains, err = s.db.Prepare(
		"SELECT domain, SUM(count) AS c FROM query_hourly_domains WHERE hour >= ? GROUP BY domain ORDER BY c DESC LIMIT 50")
	if err != nil {
		return fmt.Errorf("prepare stmtGetTopDomains: %w", err)
	}

	s.stmtGetTopClients, err = s.db.Prepare(
		"SELECT client_ip, SUM(count) AS c FROM query_hourly_clients WHERE hour >= ? GROUP BY client_ip ORDER BY c DESC LIMIT 50")
	if err != nil {
		return fmt.Errorf("prepare stmtGetTopClients: %w", err)
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
	if s.stmtGetTopDomains != nil {
		_ = s.stmtGetTopDomains.Close()
		s.stmtGetTopDomains = nil
	}
	if s.stmtGetTopClients != nil {
		_ = s.stmtGetTopClients.Close()
		s.stmtGetTopClients = nil
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

	// Add to SQLite batch. Crossing the high-water mark wakes the asynchronous
	// archiver so normal traffic does not have to wait for the periodic timer.
	var droppedSinceWarning, droppedTotal int64
	s.batchMu.Lock()
	if s.pendingBatchLenLocked() >= s.archiveLimit {
		s.batchBytes -= eventApproxBytes(s.batch[s.batchStart])
		s.batch[s.batchStart] = models.QueryEvent{}
		s.batchStart++
		if s.batchStart >= max(1, s.archiveLimit/4) {
			s.compactBatchLocked()
		}
		droppedTotal = s.batchDropped.Add(1)
		s.batchDropUnreported++
		now := time.Now()
		if s.batchDropLogAt.IsZero() || now.Sub(s.batchDropLogAt) >= archiveDropLogInterval {
			droppedSinceWarning = s.batchDropUnreported
			s.batchDropUnreported = 0
			s.batchDropLogAt = now
		}
	}
	s.batch = append(s.batch, e)
	s.batchBytes += eventApproxBytes(e)
	if s.pendingBatchLenLocked() >= s.archiveMark {
		select {
		case s.archiveReady <- struct{}{}:
		default:
		}
	}
	s.batchMu.Unlock()
	if droppedSinceWarning > 0 {
		log.Printf("[WARN] SQLite archive batch full; dropped %d oldest event(s) since the previous warning (%d total)", droppedSinceWarning, droppedTotal)
	}
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
			for b := len(s.batch) - 1; b >= s.batchStart; b-- {
				if s.batch[b].Domain == domain && s.batch[b].Node == node && !s.batch[b].Latency.Valid {
					beforeBytes := eventApproxBytes(s.batch[b])
					s.batch[b].Latency = sql.NullFloat64{Float64: latency, Valid: true}
					s.batch[b].Upstream = upstream
					// Propagate DNSSEC and ResponseCode from the in-memory event to the batch
					s.batch[b].DNSSEC = s.events[idx].DNSSEC
					s.batch[b].ResponseCode = s.events[idx].ResponseCode
					s.batch[b].LatencyAlert = s.events[idx].LatencyAlert
					s.batch[b].ClientHostname = s.events[idx].ClientHostname
					s.batch[b].Blocked = s.events[idx].Blocked
					s.batchBytes += eventApproxBytes(s.batch[b]) - beforeBytes
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
			for b := len(s.batch) - 1; b >= s.batchStart; b-- {
				if s.batch[b].Domain == domain && s.batch[b].Node == node {
					if !s.batch[b].Blocked {
						beforeBytes := eventApproxBytes(s.batch[b])
						s.batch[b].Blocked = true
						s.batchBytes += eventApproxBytes(s.batch[b]) - beforeBytes
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
			for b := len(s.batch) - 1; b >= s.batchStart; b-- {
				if s.batch[b].ClientIP == clientIP && s.batch[b].Node == node {
					beforeBytes := eventApproxBytes(s.batch[b])
					s.batch[b].ClientHostname = hostname
					s.batchBytes += eventApproxBytes(s.batch[b]) - beforeBytes
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
	for left, right := 0, len(result)-1; left < right; left, right = left+1, right-1 {
		result[left], result[right] = result[right], result[left]
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
	return s.getStatsAt(time.Now())
}

// getStatsAt is the deterministic implementation behind GetStats. Complete
// UTC hours use incremental aggregates; the partial cutoff hour is read from
// SQLite exactly so the rolling 24-hour window never includes older rows.
//
//nolint:gocyclo
func (s *Store) getStatsAt(nowTime time.Time) map[string]interface{} {
	s.archiveMu.Lock()
	defer s.archiveMu.Unlock()
	s.batchMu.Lock()
	pending := append([]models.QueryEvent(nil), s.pendingBatchLocked()...)
	s.batchMu.Unlock()
	s.dbMu.RLock()
	defer s.dbMu.RUnlock()

	now := nowTime.Unix()
	cutoff24h := now - 86400
	cutoffHour := (cutoff24h / 3600) * 3600
	completeHourStart := cutoffHour + 3600

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
	s.statsMu.RUnlock()

	// Query SQLite for long-term aggregates
	var totalEvents int64
	var rpd int
	var cacheHits, totalReplies int64
	var queryErrors []string
	domainCounts := make(map[string]int)
	clientCounts := make(map[string]int)
	heatmap := make(map[string]int)
	mergeWindowEvent := func(event models.QueryEvent) {
		rpd++
		if event.Upstream != "" {
			totalReplies++
		}
		if isCacheHit(event) {
			cacheHits++
		}
		typeCounts[event.Type]++
		domainCounts[event.Domain]++
		clientCounts[event.ClientIP]++
		hour := time.Unix(event.UnixTime, 0).UTC().Format("15:00")
		heatmap[hour]++
	}
	if s.db != nil {
		if err := s.db.QueryRow("SELECT COALESCE(SUM(total), 0) FROM query_hourly_totals").Scan(&totalEvents); err != nil && err != sql.ErrNoRows {
			log.Printf("Error getting totalEvents: %v", err)
			s.recordDBError(err)
			queryErrors = append(queryErrors, "total")
		}
		err := s.db.QueryRow(`SELECT COALESCE(SUM(total), 0),
			COALESCE(SUM(cache_hits), 0), COALESCE(SUM(replies), 0)
			FROM query_hourly_totals WHERE hour >= ?`, completeHourStart).Scan(&rpd, &cacheHits, &totalReplies)
		if err != nil && err != sql.ErrNoRows {
			log.Printf("Error getting daily aggregates: %v", err)
			s.recordDBError(err)
			queryErrors = append(queryErrors, "rpd", "cache_hits", "total_replies")
		}
		rows, err := s.db.Query("SELECT type, SUM(count) FROM query_hourly_types WHERE hour >= ? GROUP BY type", completeHourStart)
		if err != nil {
			s.recordDBError(err)
			queryErrors = append(queryErrors, "type_counts")
		} else {
			for rows.Next() {
				var queryType string
				var count int
				if err := rows.Scan(&queryType, &count); err == nil {
					typeCounts[queryType] = count
				}
			}
			if err := rows.Err(); err != nil {
				s.recordDBError(err)
				queryErrors = append(queryErrors, "type_counts")
			}
			_ = rows.Close()
		}

		rows, err = s.db.Query(`SELECT unix_time, domain, client_ip, type, upstream, cache_status
			FROM queries WHERE unix_time >= ? AND unix_time < ?`, cutoff24h, completeHourStart)
		if err != nil {
			s.recordDBError(err)
			queryErrors = append(queryErrors, "cutoff_hour")
		} else {
			for rows.Next() {
				var event models.QueryEvent
				var upstream, cacheStatus sql.NullString
				if err := rows.Scan(
					&event.UnixTime, &event.Domain, &event.ClientIP, &event.Type,
					&upstream, &cacheStatus,
				); err != nil {
					s.recordDBError(err)
					queryErrors = append(queryErrors, "cutoff_hour")
					continue
				}
				event.Upstream = upstream.String
				event.CacheStatus = cacheStatus.String
				mergeWindowEvent(event)
			}
			if err := rows.Err(); err != nil {
				s.recordDBError(err)
				queryErrors = append(queryErrors, "cutoff_hour")
			}
			_ = rows.Close()
		}
	}

	totalEvents += int64(len(pending))
	for _, event := range pending {
		if event.UnixTime < cutoff24h {
			continue
		}
		mergeWindowEvent(event)
	}

	cacheHitRatio := 0.0
	if totalReplies > 0 {
		cacheHitRatio = float64(cacheHits) / float64(totalReplies) * 100
	}

	// Item 67: Bandwidth savings estimate (100 bytes per cached query)
	bandwidthSaved := cacheHits * 100

	if s.db != nil {
		// Domain candidates (the Top 10 are selected after pending counts are merged).
		if s.stmtGetTopDomains != nil {
			rowsDomains, err := s.stmtGetTopDomains.Query(completeHourStart)
			if err == nil {
				for rowsDomains.Next() {
					var d string
					var c int
					if rowsDomains.Scan(&d, &c) == nil {
						domainCounts[d] += c
					}
				}
				if err := rowsDomains.Err(); err != nil {
					log.Printf("Error iterating domain rows: %v", err)
				}
				_ = rowsDomains.Close()
			}
		}

		// Client candidates (the Top 10 are selected after pending counts are merged).
		if s.stmtGetTopClients != nil {
			rowsClients, err := s.stmtGetTopClients.Query(completeHourStart)
			if err == nil {
				for rowsClients.Next() {
					var ip string
					var c int
					if rowsClients.Scan(&ip, &c) == nil {
						clientCounts[ip] += c
					}
				}
				if err := rowsClients.Err(); err != nil {
					log.Printf("Error iterating client rows: %v", err)
				}
				_ = rowsClients.Close()
			}
		}

		// Hourly heatmap
		currentHour := now / 3600
		rowsHeatmap, err := s.db.Query("SELECT hour, total FROM query_hourly_totals WHERE hour >= ?", completeHourStart)
		if err == nil {
			for rowsHeatmap.Next() {
				var hr int64
				var c int
				if rowsHeatmap.Scan(&hr, &c) == nil {
					t := time.Unix(hr, 0).UTC()
					heatmap[t.Format("15:00")] += c
				}
			}
			if err := rowsHeatmap.Err(); err != nil {
				log.Printf("Error iterating heatmap rows: %v", err)
			}
			_ = rowsHeatmap.Close()
		}

		// Fill missing hours in heatmap
		for h := currentHour - 23; h <= currentHour; h++ {
			t := time.Unix(h*3600, 0).UTC()
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
			for b := len(s.batch) - 1; b >= s.batchStart; b-- {
				if s.batch[b].Domain == domain && s.batch[b].Node == node {
					beforeBytes := eventApproxBytes(s.batch[b])
					s.batch[b].DNSSEC = result
					s.batchBytes += eventApproxBytes(s.batch[b]) - beforeBytes
					break
				}
			}
			s.batchMu.Unlock()
			return
		}
	}
}

// RunArchiver persists queued events when the queue reaches its high-water mark
// or the periodic interval expires. Failed writes retry with bounded backoff.
func (s *Store) RunArchiver(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = config.DefaultArchiveInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-s.archiveReady:
		}

		retryDelay := archiveRetryInitialDelay
		for {
			_, err := s.archiveStep(ctx, time.Now())
			if err == nil {
				break
			}
			if ctx.Err() != nil {
				return
			}
			metrics := s.ArchiveMetrics()
			log.Printf("SQLite archive failed; retaining %d events and retrying in %s: %v", metrics.Pending, retryDelay, err)

			retryTimer := time.NewTimer(retryDelay)
			select {
			case <-ctx.Done():
				if !retryTimer.Stop() {
					<-retryTimer.C
				}
				return
			case <-retryTimer.C:
			}
			retryDelay = min(retryDelay*2, archiveRetryMaxDelay)
		}
	}
}

// ArchiveStep performs a batch insert of recent queries into SQLite and deletes old ones.
func (s *Store) ArchiveStep(now time.Time) int {
	archived, err := s.archiveStep(context.Background(), now)
	if err != nil {
		metrics := s.ArchiveMetrics()
		log.Printf("SQLite archive failed; retaining %d events: %v", metrics.Pending, err)
	}
	return archived
}

func (s *Store) archiveStep(ctx context.Context, now time.Time) (int, error) {
	s.archiveMu.Lock()
	defer s.archiveMu.Unlock()
	s.dbMu.RLock()
	defer s.dbMu.RUnlock()
	if s.closed || s.db == nil {
		return 0, nil
	}

	archived := 0
	for {
		toInsert := s.claimArchiveBatch()
		if len(toInsert) == 0 {
			break
		}

		insert := s.insertArchiveBatch
		if s.archiveInsert != nil {
			insert = s.archiveInsert
		}
		if err := insert(ctx, toInsert); err != nil {
			s.restoreArchiveBatch(toInsert)
			return archived, err
		}
		s.batchInFlight.Add(-int64(len(toInsert)))
		s.batchFlightBytes.Add(-eventsApproxBytes(toInsert))
		archived += len(toInsert)
	}

	s.pruneOldEvents(ctx, now)
	s.flushArchiveDropWarning()
	return archived, nil
}

func (s *Store) claimArchiveBatch() []models.QueryEvent {
	s.batchMu.Lock()
	defer s.batchMu.Unlock()

	pending := s.pendingBatchLocked()
	chunkSize := min(len(pending), s.archiveBatch)
	if chunkSize == 0 {
		return nil
	}
	claimed := append([]models.QueryEvent(nil), pending[:chunkSize]...)
	claimedBytes := eventsApproxBytes(claimed)
	clear(s.batch[s.batchStart : s.batchStart+chunkSize])
	s.batchStart += chunkSize
	s.batchBytes -= claimedBytes
	s.batchInFlight.Add(int64(chunkSize))
	s.batchFlightBytes.Add(claimedBytes)
	if s.pendingBatchLenLocked() == 0 || s.batchStart >= max(1, s.archiveLimit/4) {
		s.compactBatchLocked()
	}
	return claimed
}

func (s *Store) restoreArchiveBatch(claimed []models.QueryEvent) {
	s.batchMu.Lock()
	pending := append([]models.QueryEvent(nil), s.pendingBatchLocked()...)
	combined := make([]models.QueryEvent, 0, len(claimed)+len(pending))
	combined = append(combined, claimed...)
	combined = append(combined, pending...)

	dropped := max(0, len(combined)-s.archiveLimit)
	clear(s.batch)
	s.batch = append(s.batch[:0], combined[dropped:]...)
	s.batchStart = 0
	s.batchBytes = eventsApproxBytes(s.batch)
	s.batchInFlight.Add(-int64(len(claimed)))
	s.batchFlightBytes.Add(-eventsApproxBytes(claimed))
	if dropped > 0 {
		s.batchDropped.Add(int64(dropped))
		s.batchDropUnreported += int64(dropped)
	}
	s.batchMu.Unlock()

	if dropped > 0 {
		log.Printf("[WARN] SQLite archive retry queue full; dropped %d oldest uncommitted event(s) (%d total)", dropped, s.batchDropped.Load())
	}
}

func (s *Store) insertArchiveBatch(ctx context.Context, events []models.QueryEvent) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction for %d events: %w", len(events), err)
	}

	const insertPrefix = "INSERT INTO queries (unix_time, node, client_ip, domain, type, upstream, latency, dnssec, response_code, client_hostname, blocked, latency_alert, matched_rule, block_reason, cache_status, cache_ttl, negative_soa) VALUES "
	const rowPlaceholders = "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
	for start := 0; start < len(events); start += archiveInsertRows {
		end := min(start+archiveInsertRows, len(events))
		var query strings.Builder
		query.Grow(len(insertPrefix) + (end-start)*(len(rowPlaceholders)+1))
		query.WriteString(insertPrefix)
		args := make([]any, 0, (end-start)*17)
		for index, event := range events[start:end] {
			if index > 0 {
				query.WriteByte(',')
			}
			query.WriteString(rowPlaceholders)
			blocked := 0
			if event.Blocked {
				blocked = 1
			}
			latencyAlert := 0
			if event.LatencyAlert {
				latencyAlert = 1
			}
			args = append(args, event.UnixTime, event.Node, event.ClientIP, event.Domain, event.Type, event.Upstream, event.Latency, event.DNSSEC, event.ResponseCode, event.ClientHostname, blocked, latencyAlert, event.MatchedRule, event.BlockReason, event.CacheStatus, event.CacheTTL, event.NegativeSOA)
		}
		if _, err = tx.ExecContext(ctx, query.String(), args...); err != nil {
			_ = tx.Rollback()
			s.recordDBError(err)
			return fmt.Errorf("insert batch of %d events: %w", len(events), err)
		}
	}
	if err := upsertHourlyAggregates(ctx, tx, events); err != nil {
		_ = tx.Rollback()
		s.recordDBError(err)
		return fmt.Errorf("update hourly aggregates for %d events: %w", len(events), err)
	}
	if err := tx.Commit(); err != nil {
		s.recordDBError(err)
		return fmt.Errorf("commit batch of %d events: %w", len(events), err)
	}
	return nil
}

// ArchiveMetrics returns current queue pressure, configured limits, and the
// lifetime number of events dropped at the hard limit.
func (s *Store) ArchiveMetrics() ArchiveQueueMetrics {
	s.batchMu.Lock()
	pending := s.pendingBatchLenLocked() + int(s.batchInFlight.Load())
	pendingBytes := s.batchBytes + s.batchFlightBytes.Load()
	s.batchMu.Unlock()
	return ArchiveQueueMetrics{
		Pending:      pending,
		PendingBytes: pendingBytes,
		Dropped:      s.batchDropped.Load(),
		Capacity:     s.archiveLimit,
		Trigger:      s.archiveMark,
		WriteBatch:   s.archiveBatch,
	}
}

func (s *Store) flushArchiveDropWarning() {
	s.batchMu.Lock()
	unreported := s.batchDropUnreported
	s.batchDropUnreported = 0
	if unreported > 0 {
		s.batchDropLogAt = time.Now()
	}
	pending := s.pendingBatchLenLocked()
	s.batchMu.Unlock()
	if unreported > 0 {
		log.Printf("[WARN] SQLite archive recovered after dropping %d additional event(s) (%d total); %d event(s) remain pending", unreported, s.batchDropped.Load(), pending)
	}
}

func (s *Store) pruneOldEvents(ctx context.Context, now time.Time) {
	cutoff := now.Add(-s.cfg.HistoryRetention).Unix()
	deleted, err := pruneRetentionBatch(ctx, s.db, cutoff)
	if err != nil {
		s.recordDBError(err)
		log.Printf("Failed to prune old SQLite data: %v", err)
	} else if deleted == retentionDeleteBatch {
		log.Printf("SQLite retention deleted a bounded batch of %d rows; remaining expired rows will be pruned on a later archive pass", deleted)
	}
}

// SetUpstreamHealth updates the latency mapping and history for upstream DNS servers for a specific node.
func (s *Store) SetUpstreamHealth(node string, health map[string]float64) {
	if node == "" {
		node = "local"
	}
	s.nodeStatusMu.RLock()
	if _, tombstoned := s.nodeTombstones[node]; tombstoned {
		s.nodeStatusMu.RUnlock()
		return
	}
	defer s.nodeStatusMu.RUnlock()
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

// SetNodeStatus updates a legacy name-addressed status. New cluster traffic
// should use SetNodeStatusIdentity so equal display names cannot overwrite one
// another.
func (s *Store) SetNodeStatus(name string, status models.NodeStatus) {
	_ = s.SetNodeStatusIdentity(status.ID, name, status)
}

// SetNodeStatusIdentity updates a node keyed by its stable identity. It returns
// false for a tombstoned identity, requiring an explicit restore before a
// decommissioned node can silently rejoin.
func (s *Store) SetNodeStatusIdentity(identity, name string, status models.NodeStatus) bool {
	if name == "" {
		name = "unknown"
	}
	identity = strings.TrimSpace(identity)
	if identity == "" {
		identity = name
	}
	s.nodeStatusMu.Lock()
	defer s.nodeStatusMu.Unlock()
	if _, tombstoned := s.nodeTombstones[identity]; tombstoned {
		return false
	}

	status.ID = identity
	status.Name = name
	status.Online = true
	status.LastSeen = time.Now()
	status.UpstreamHealth = cloneFloatMap(status.UpstreamHealth)
	status.ForwarderEndpointErrors = cloneStringMap(status.ForwarderEndpointErrors)
	s.nodeStatuses[identity] = &status
	s.refreshDuplicateNameWarningsLocked(name)
	return true
}

// GetNodeStatus returns the status of a single node by name.
func (s *Store) GetNodeStatus(name string) *models.NodeStatus {
	s.nodeStatusMu.RLock()
	defer s.nodeStatusMu.RUnlock()

	if ns, ok := s.nodeStatuses[name]; ok {
		return s.cloneNodeStatus(ns)
	}
	for _, ns := range s.nodeStatuses {
		if ns.Name == name {
			return s.cloneNodeStatus(ns)
		}
	}
	return nil
}

// GetNodeStatusByID returns a node only when its stable identity matches.
func (s *Store) GetNodeStatusByID(identity string) *models.NodeStatus {
	s.nodeStatusMu.RLock()
	defer s.nodeStatusMu.RUnlock()
	status := s.nodeStatuses[strings.TrimSpace(identity)]
	if status == nil {
		return nil
	}
	return s.cloneNodeStatus(status)
}

// GetNodeStatuses returns a copy of all node statuses with online state computed.
func (s *Store) GetNodeStatuses() []models.NodeStatus {
	s.nodeStatusMu.RLock()
	defer s.nodeStatusMu.RUnlock()

	result := make([]models.NodeStatus, 0, len(s.nodeStatuses))
	for _, ns := range s.nodeStatuses {
		result = append(result, *s.cloneNodeStatus(ns))
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Name == result[j].Name {
			return result[i].ID < result[j].ID
		}
		return result[i].Name < result[j].Name
	})
	return result
}

// DecommissionNode tombstones a stable identity and removes volatile status
// and health without deleting archived query history.
func (s *Store) DecommissionNode(identity string) (bool, error) {
	identity = strings.TrimSpace(identity)
	s.nodeStatusMu.Lock()
	status := s.nodeStatuses[identity]
	if status == nil {
		s.nodeStatusMu.Unlock()
		return false, nil
	}
	decommissionedAt := time.Now()
	s.dbMu.RLock()
	if s.closed || s.db == nil {
		s.dbMu.RUnlock()
		s.nodeStatusMu.Unlock()
		return false, errors.New("persist node tombstone: database is not available")
	}
	_, err := s.db.Exec(`INSERT INTO node_tombstones(node_id, node_name, decommissioned_at)
		VALUES (?, ?, ?) ON CONFLICT(node_id) DO UPDATE SET
		node_name = excluded.node_name, decommissioned_at = excluded.decommissioned_at`,
		identity, status.Name, decommissionedAt.Unix())
	s.dbMu.RUnlock()
	if err != nil {
		s.recordDBError(err)
		s.nodeStatusMu.Unlock()
		return false, fmt.Errorf("persist node tombstone: %w", err)
	}
	delete(s.nodeStatuses, identity)
	s.nodeTombstones[identity] = decommissionedAt
	s.refreshDuplicateNameWarningsLocked(status.Name)
	s.nodeStatusMu.Unlock()

	s.healthMu.Lock()
	delete(s.nodeUpstreamHealth, identity)
	delete(s.nodeUpstreamHealthHistory, identity)
	s.healthMu.Unlock()
	return true, nil
}

// RestoreNode removes a stable tombstone. The node remains absent until its
// next authenticated heartbeat.
func (s *Store) RestoreNode(identity string) (bool, error) {
	identity = strings.TrimSpace(identity)
	s.nodeStatusMu.Lock()
	_, existed := s.nodeTombstones[identity]
	if !existed {
		s.nodeStatusMu.Unlock()
		return false, nil
	}
	s.dbMu.RLock()
	if s.closed || s.db == nil {
		s.dbMu.RUnlock()
		s.nodeStatusMu.Unlock()
		return false, errors.New("remove node tombstone: database is not available")
	}
	_, err := s.db.Exec("DELETE FROM node_tombstones WHERE node_id = ?", identity)
	s.dbMu.RUnlock()
	if err != nil {
		s.recordDBError(err)
		s.nodeStatusMu.Unlock()
		return false, fmt.Errorf("remove node tombstone: %w", err)
	}
	delete(s.nodeTombstones, identity)
	s.nodeStatusMu.Unlock()
	return true, nil
}

// IsNodeTombstoned reports whether an identity requires explicit restoration.
func (s *Store) IsNodeTombstoned(identity string) bool {
	s.nodeStatusMu.RLock()
	_, ok := s.nodeTombstones[strings.TrimSpace(identity)]
	s.nodeStatusMu.RUnlock()
	return ok
}

func (s *Store) loadNodeTombstones() {
	rows, err := s.db.Query("SELECT node_id, decommissioned_at FROM node_tombstones")
	if err != nil {
		log.Printf("[WARN] Load node tombstones: %v", err)
		return
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var identity string
		var unixTime int64
		if err := rows.Scan(&identity, &unixTime); err != nil {
			log.Printf("[WARN] Read node tombstone: %v", err)
			continue
		}
		s.nodeTombstones[identity] = time.Unix(unixTime, 0)
	}
}

func (s *Store) refreshDuplicateNameWarningsLocked(name string) {
	count := 0
	for _, status := range s.nodeStatuses {
		if status.Name == name {
			count++
		}
	}
	for _, status := range s.nodeStatuses {
		if status.Name == name {
			status.DuplicateNameWarning = count > 1
		}
	}
}

func (s *Store) cloneNodeStatus(status *models.NodeStatus) *models.NodeStatus {
	result := *status
	result.Online = status.IsOnline(s.cfg.NodeOfflineThreshold)
	result.UpstreamHealth = cloneFloatMap(status.UpstreamHealth)
	result.ForwarderEndpointErrors = cloneStringMap(status.ForwarderEndpointErrors)
	return &result
}

func cloneFloatMap(source map[string]float64) map[string]float64 {
	if source == nil {
		return nil
	}
	cloned := make(map[string]float64, len(source))
	for key, value := range source {
		cloned[key] = value
	}
	return cloned
}

func cloneStringMap(source map[string]string) map[string]string {
	if source == nil {
		return nil
	}
	cloned := make(map[string]string, len(source))
	for key, value := range source {
		cloned[key] = value
	}
	return cloned
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

// startVacuum runs bounded incremental vacuum work when the database supports
// it. Existing databases that require a blocking one-time VACUUM migration are
// reported through DBMetrics and never migrated automatically.
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
				start := time.Now()
				var mode int
				err := s.db.QueryRowContext(ctx, "PRAGMA auto_vacuum").Scan(&mode)
				pagesRequested := 0
				if err == nil && mode == 2 {
					pagesRequested = incrementalVacuumPages
					_, err = s.db.ExecContext(ctx, "PRAGMA incremental_vacuum(200)")
				}
				duration := time.Since(start)
				s.maintenanceMu.Lock()
				s.vacuumState = vacuumState{
					At: start, Duration: duration, PagesRequested: pagesRequested,
				}
				if err != nil {
					s.vacuumState.Error = err.Error()
				}
				s.maintenanceMu.Unlock()
				switch {
				case err != nil:
					s.recordDBError(err)
					log.Printf("Incremental database vacuum failed: %v", err)
				case mode == 2:
					log.Printf("Incremental database vacuum completed in %s", duration.Round(time.Millisecond))
				default:
					log.Printf("Database auto_vacuum is not incremental; skipping blocking VACUUM and exposing a maintenance recommendation")
				}
				s.dbMu.RUnlock()
			}
		}
	}()
	log.Printf("Periodic incremental vacuum check started (interval: %s)", s.vacuumInterval)
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
				started := time.Now()
				row := s.db.QueryRowContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE);")
				err := row.Scan(&busy, &logFrames, &checkpointed)
				duration := time.Since(started)
				s.maintenanceMu.Lock()
				s.checkpointState = checkpointState{
					At: started, Duration: duration, Busy: busy,
					LogFrames: logFrames, Checkpointed: checkpointed,
				}
				if err != nil {
					s.checkpointState.Error = err.Error()
				}
				s.maintenanceMu.Unlock()
				if err != nil {
					s.recordDBError(err)
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

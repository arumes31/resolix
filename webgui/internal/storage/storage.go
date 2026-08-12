package storage

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"strconv"
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
	Pending      int   `json:"pending"`
	PendingBytes int64 `json:"pending_bytes"`
	Dropped      int64 `json:"dropped"`
	Capacity     int   `json:"capacity"`
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

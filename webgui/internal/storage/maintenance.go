package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/arumes31/resolix/webgui/internal/db"
	"github.com/arumes31/resolix/webgui/internal/models"
)

const (
	retentionDeleteBatch   = 10_000
	incrementalVacuumPages = 200
)

type checkpointState struct {
	At           time.Time
	Duration     time.Duration
	Busy         int
	LogFrames    int
	Checkpointed int
	Error        string
}

type vacuumState struct {
	At             time.Time
	Duration       time.Duration
	PagesRequested int
	Error          string
}

type optimizeState struct {
	At       time.Time
	Duration time.Duration
	Error    string
}

// DatabaseMetrics reports SQLite files, maintenance state, queue pressure,
// and contention failures without changing database state.
type DatabaseMetrics struct {
	DatabaseBytes            int64               `json:"database_bytes"`
	WALBytes                 int64               `json:"wal_bytes"`
	Archive                  ArchiveQueueMetrics `json:"archive"`
	PageCount                int64               `json:"page_count"`
	FreeListPages            int64               `json:"freelist_pages"`
	PageSize                 int64               `json:"page_size"`
	BusyTimeoutMS            int64               `json:"busy_timeout_ms"`
	BusyErrors               int64               `json:"busy_errors"`
	AutoVacuumMode           string              `json:"auto_vacuum_mode"`
	VacuumRecommended        bool                `json:"vacuum_recommended"`
	VacuumRecommendation     string              `json:"vacuum_recommendation,omitempty"`
	LastVacuumAt             time.Time           `json:"last_vacuum_at,omitempty"`
	LastVacuumDurationMS     int64               `json:"last_vacuum_duration_ms"`
	LastVacuumError          string              `json:"last_vacuum_error,omitempty"`
	LastOptimizeAt           time.Time           `json:"last_optimize_at,omitempty"`
	LastOptimizeDurationMS   int64               `json:"last_optimize_duration_ms"`
	LastOptimizeError        string              `json:"last_optimize_error,omitempty"`
	LastCheckpointAt         time.Time           `json:"last_checkpoint_at,omitempty"`
	CheckpointAgeSeconds     float64             `json:"checkpoint_age_seconds"`
	LastCheckpointDurationMS int64               `json:"last_checkpoint_duration_ms"`
	LastCheckpointBusy       int                 `json:"last_checkpoint_busy"`
	LastCheckpointLogFrames  int                 `json:"last_checkpoint_log_frames"`
	LastCheckpointedFrames   int                 `json:"last_checkpointed_frames"`
	LastCheckpointError      string              `json:"last_checkpoint_error,omitempty"`
}

// DBMetrics returns a consistent snapshot of database maintenance telemetry.
func (s *Store) DBMetrics(ctx context.Context) DatabaseMetrics {
	metrics := DatabaseMetrics{
		Archive:              s.ArchiveMetrics(),
		BusyErrors:           s.dbBusyErrors.Load(),
		CheckpointAgeSeconds: -1,
	}
	if info, err := os.Stat(s.cfg.FullDBPath()); err == nil {
		metrics.DatabaseBytes = info.Size()
	}
	if info, err := os.Stat(s.cfg.FullDBPath() + "-wal"); err == nil {
		metrics.WALBytes = info.Size()
	}

	s.dbMu.RLock()
	databaseAvailable := !s.closed && s.db != nil
	if databaseAvailable {
		readPragmaInt64(ctx, s.db, "PRAGMA page_count", &metrics.PageCount, s.recordDBError)
		readPragmaInt64(ctx, s.db, "PRAGMA freelist_count", &metrics.FreeListPages, s.recordDBError)
		readPragmaInt64(ctx, s.db, "PRAGMA page_size", &metrics.PageSize, s.recordDBError)
		readPragmaInt64(ctx, s.db, "PRAGMA busy_timeout", &metrics.BusyTimeoutMS, s.recordDBError)
		var autoVacuum int64
		readPragmaInt64(ctx, s.db, "PRAGMA auto_vacuum", &autoVacuum, s.recordDBError)
		switch autoVacuum {
		case 1:
			metrics.AutoVacuumMode = "full"
		case 2:
			metrics.AutoVacuumMode = "incremental"
		default:
			metrics.AutoVacuumMode = "none"
		}
	}
	s.dbMu.RUnlock()

	if databaseAvailable && metrics.AutoVacuumMode != "incremental" {
		metrics.VacuumRecommended = true
		metrics.VacuumRecommendation = "schedule one maintenance-window VACUUM after setting auto_vacuum=INCREMENTAL; Resolix will not perform that blocking migration automatically"
	}

	s.maintenanceMu.RLock()
	checkpoint := s.checkpointState
	vacuum := s.vacuumState
	optimize := s.optimizeState
	s.maintenanceMu.RUnlock()
	metrics.LastCheckpointAt = checkpoint.At
	metrics.LastCheckpointDurationMS = checkpoint.Duration.Milliseconds()
	metrics.LastCheckpointBusy = checkpoint.Busy
	metrics.LastCheckpointLogFrames = checkpoint.LogFrames
	metrics.LastCheckpointedFrames = checkpoint.Checkpointed
	metrics.LastCheckpointError = checkpoint.Error
	if !checkpoint.At.IsZero() {
		metrics.CheckpointAgeSeconds = max(0, time.Since(checkpoint.At).Seconds())
	}
	metrics.LastVacuumAt = vacuum.At
	metrics.LastVacuumDurationMS = vacuum.Duration.Milliseconds()
	metrics.LastVacuumError = vacuum.Error
	metrics.LastOptimizeAt = optimize.At
	metrics.LastOptimizeDurationMS = optimize.Duration.Milliseconds()
	metrics.LastOptimizeError = optimize.Error
	return metrics
}

// optimizeDatabase asks SQLite to refresh planner statistics when useful. The
// pragma is deliberately advisory and bounded; SQLite normally returns without
// doing work when its analysis data is already current.
func (s *Store) optimizeDatabase(ctx context.Context) {
	s.dbMu.RLock()
	defer s.dbMu.RUnlock()
	if s.closed || s.db == nil {
		return
	}
	started := time.Now()
	_, err := s.db.ExecContext(ctx, "PRAGMA optimize")
	state := optimizeState{At: started, Duration: time.Since(started)}
	if err != nil {
		state.Error = err.Error()
		s.recordDBError(err)
		log.Printf("SQLite planner optimization failed: %v", err)
	}
	s.maintenanceMu.Lock()
	s.optimizeState = state
	s.maintenanceMu.Unlock()
}

func readPragmaInt64(
	ctx context.Context,
	database *sql.DB,
	query string,
	destination *int64,
	recordError func(error),
) {
	if err := database.QueryRowContext(ctx, query).Scan(destination); err != nil {
		recordError(err)
	}
}

func (s *Store) recordDBError(err error) {
	if err == nil {
		return
	}
	message := strings.ToLower(err.Error())
	if strings.Contains(message, "database is locked") ||
		strings.Contains(message, "database table is locked") ||
		strings.Contains(message, "sqlite_busy") ||
		strings.Contains(message, "sqlite_locked") {
		s.dbBusyErrors.Add(1)
	}
}

func eventApproxBytes(event models.QueryEvent) int64 {
	return int64(96 + len(event.Node) + len(event.ClientIP) + len(event.Domain) +
		len(event.Type) + len(event.Upstream) + len(event.DNSSEC) +
		len(event.ClientHostname) + len(event.ResponseCode) + len(event.MatchedRule) +
		len(event.BlockReason) + len(event.CacheStatus) + len(event.NegativeSOA))
}

func eventsApproxBytes(events []models.QueryEvent) int64 {
	var total int64
	for _, event := range events {
		total += eventApproxBytes(event)
	}
	return total
}

type hourlyTotal struct {
	total     int
	cacheHits int
	replies   int
	blocked   int
}

type hourlyKey struct {
	hour  int64
	value string
}

func isCacheHit(event models.QueryEvent) bool {
	status := strings.ToLower(strings.TrimSpace(event.CacheStatus))
	if db.IsCacheHitStatus(status) {
		return true
	}
	if status == "" {
		return strings.HasPrefix(event.Upstream, "System Cache")
	}
	return false
}

func upsertHourlyAggregates(ctx context.Context, tx *sql.Tx, events []models.QueryEvent) error {
	totals := make(map[int64]hourlyTotal)
	domains := make(map[hourlyKey]int)
	clients := make(map[hourlyKey]int)
	types := make(map[hourlyKey]int)
	for _, event := range events {
		hour := (event.UnixTime / 3600) * 3600
		total := totals[hour]
		total.total++
		if isCacheHit(event) {
			total.cacheHits++
		}
		if event.Upstream != "" {
			total.replies++
		}
		if event.Blocked {
			total.blocked++
		}
		totals[hour] = total
		domains[hourlyKey{hour: hour, value: event.Domain}]++
		clients[hourlyKey{hour: hour, value: event.ClientIP}]++
		types[hourlyKey{hour: hour, value: event.Type}]++
	}
	if err := upsertHourlyTotals(ctx, tx, totals); err != nil {
		return err
	}
	if err := upsertHourlyValues(ctx, tx, "query_hourly_domains", domains); err != nil {
		return err
	}
	if err := upsertHourlyValues(ctx, tx, "query_hourly_clients", clients); err != nil {
		return err
	}
	return upsertHourlyValues(ctx, tx, "query_hourly_types", types)
}

func upsertHourlyTotals(ctx context.Context, tx *sql.Tx, values map[int64]hourlyTotal) error {
	statement, err := tx.PrepareContext(ctx, `INSERT INTO query_hourly_totals
		(hour, total, cache_hits, replies, blocked) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(hour) DO UPDATE SET
		total = total + excluded.total,
		cache_hits = cache_hits + excluded.cache_hits,
		replies = replies + excluded.replies,
		blocked = blocked + excluded.blocked`)
	if err != nil {
		return err
	}
	defer func() { _ = statement.Close() }()
	for hour, value := range values {
		if _, err := statement.ExecContext(
			ctx, hour, value.total, value.cacheHits, value.replies, value.blocked,
		); err != nil {
			return err
		}
	}
	return nil
}

func upsertHourlyValues(
	ctx context.Context,
	tx *sql.Tx,
	table string,
	values map[hourlyKey]int,
) error {
	var query string
	switch table {
	case "query_hourly_domains":
		query = `INSERT INTO query_hourly_domains (hour, domain, count) VALUES (?, ?, ?)
			ON CONFLICT(hour, domain) DO UPDATE SET count = count + excluded.count`
	case "query_hourly_clients":
		query = `INSERT INTO query_hourly_clients (hour, client_ip, count) VALUES (?, ?, ?)
			ON CONFLICT(hour, client_ip) DO UPDATE SET count = count + excluded.count`
	case "query_hourly_types":
		query = `INSERT INTO query_hourly_types (hour, type, count) VALUES (?, ?, ?)
			ON CONFLICT(hour, type) DO UPDATE SET count = count + excluded.count`
	default:
		return errors.New("unsupported hourly aggregate table")
	}
	statement, err := tx.PrepareContext(ctx, query)
	if err != nil {
		return err
	}
	defer func() { _ = statement.Close() }()
	for key, count := range values {
		if _, err := statement.ExecContext(ctx, key.hour, key.value, count); err != nil {
			return err
		}
	}
	return nil
}

func pruneRetentionBatch(ctx context.Context, database *sql.DB, cutoff int64) (int64, error) {
	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, `DELETE FROM queries WHERE id IN (
		SELECT id FROM queries WHERE unix_time < ? ORDER BY id LIMIT ?
	)`, cutoff, retentionDeleteBatch)
	if err != nil {
		return 0, err
	}
	deleted, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}

	cutoffHour := (cutoff / 3600) * 3600
	for _, table := range []string{
		"query_hourly_totals",
		"query_hourly_domains",
		"query_hourly_clients",
		"query_hourly_types",
	} {
		var statement string
		switch table {
		case "query_hourly_totals":
			statement = "DELETE FROM query_hourly_totals WHERE hour <= ?"
		case "query_hourly_domains":
			statement = "DELETE FROM query_hourly_domains WHERE hour <= ?"
		case "query_hourly_clients":
			statement = "DELETE FROM query_hourly_clients WHERE hour <= ?"
		case "query_hourly_types":
			statement = "DELETE FROM query_hourly_types WHERE hour <= ?"
		}
		// Rebuild the cutoff hour below, so deleting it here also removes the
		// expired portion of that hour from aggregate results.
		if _, err := tx.ExecContext(ctx, statement, cutoffHour); err != nil {
			return 0, err
		}
	}
	if _, err := tx.ExecContext(ctx, fmt.Sprintf(`INSERT INTO query_hourly_totals
		(hour, total, cache_hits, replies, blocked)
		SELECT ?, COUNT(*),
		       COALESCE(SUM(CASE WHEN %s THEN 1 ELSE 0 END), 0),
		       COALESCE(SUM(CASE WHEN upstream != '' THEN 1 ELSE 0 END), 0),
		       COALESCE(SUM(blocked), 0)
		FROM queries WHERE unix_time >= ? AND unix_time < ?
		HAVING COUNT(*) > 0`, db.CacheHitSQLExpression), cutoffHour, cutoff, cutoffHour+3600); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO query_hourly_domains (hour, domain, count)
		SELECT ?, domain, COUNT(*) FROM queries
		WHERE unix_time >= ? AND unix_time < ? GROUP BY domain`, cutoffHour, cutoff, cutoffHour+3600); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO query_hourly_clients (hour, client_ip, count)
		SELECT ?, client_ip, COUNT(*) FROM queries
		WHERE unix_time >= ? AND unix_time < ? GROUP BY client_ip`, cutoffHour, cutoff, cutoffHour+3600); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO query_hourly_types (hour, type, count)
		SELECT ?, type, COUNT(*) FROM queries
		WHERE unix_time >= ? AND unix_time < ? GROUP BY type`, cutoffHour, cutoff, cutoffHour+3600); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return deleted, nil
}

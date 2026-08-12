package storage

import (
	"testing"
	"time"

	"github.com/arumes31/resolix/webgui/internal/models"
)

func TestArchiveMaintainsHourlyAggregates(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()
	now := time.Now().UTC().Truncate(time.Hour).Add(5 * time.Minute)
	events := []models.QueryEvent{
		{UnixTime: now.Unix(), Domain: "popular.example", ClientIP: "192.0.2.1", Type: "A", Upstream: "System Cache"},
		{UnixTime: now.Unix(), Domain: "popular.example", ClientIP: "192.0.2.2", Type: "AAAA", Blocked: true},
		{UnixTime: now.Unix(), Domain: "other.example", ClientIP: "192.0.2.1", Type: "A", Upstream: "1.1.1.1"},
	}
	for _, event := range events {
		store.AddEvent(event)
	}
	if archived := store.ArchiveStep(now); archived != len(events) {
		t.Fatalf("archived = %d, want %d", archived, len(events))
	}
	hour := now.Unix() / 3600 * 3600
	var total, cacheHits, replies, blocked int
	if err := store.db.QueryRow(
		"SELECT total, cache_hits, replies, blocked FROM query_hourly_totals WHERE hour = ?",
		hour,
	).Scan(&total, &cacheHits, &replies, &blocked); err != nil {
		t.Fatal(err)
	}
	if total != 3 || cacheHits != 1 || replies != 2 || blocked != 1 {
		t.Fatalf("hourly totals = %d/%d/%d/%d", total, cacheHits, replies, blocked)
	}
	var popular int
	if err := store.db.QueryRow(
		"SELECT count FROM query_hourly_domains WHERE hour = ? AND domain = ?",
		hour,
		"popular.example",
	).Scan(&popular); err != nil {
		t.Fatal(err)
	}
	if popular != 2 {
		t.Fatalf("popular count = %d, want 2", popular)
	}
}

func TestCacheHitPredicateAndArchivedPendingAnalyticsMatch(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()
	now := time.Now().Unix()
	events := []models.QueryEvent{
		{UnixTime: now, Domain: "fresh.example", Type: "A", Upstream: "System Cache", CacheStatus: "fresh"},
		{UnixTime: now, Domain: "stale.example", Type: "A", Upstream: "System Cache (stale)", CacheStatus: "stale"},
		{UnixTime: now, Domain: "prefetched.example", Type: "A", Upstream: "System Cache (prefetched)", CacheStatus: "prefetched"},
		{UnixTime: now, Domain: "negative.example", Type: "A", Upstream: "System Cache (negative)", CacheStatus: "negative"},
		{UnixTime: now, Domain: "servfail.example", Type: "A", Upstream: "System Cache (servfail)", CacheStatus: "servfail"},
		{UnixTime: now, Domain: "legacy.example", Type: "A", Upstream: "System Cache (legacy)"},
		{UnixTime: now, Domain: "coalesced.example", Type: "A", Upstream: "1.1.1.1", CacheStatus: "coalesced"},
		{UnixTime: now, Domain: "unknown.example", Type: "A", Upstream: "System Cache", CacheStatus: "future-state"},
	}
	for _, event := range events {
		store.AddEvent(event)
	}
	pending := store.GetStats()
	if ratio := pending["cache_hit_ratio"].(float64); ratio != 75 {
		t.Fatalf("pending cache ratio = %v, want 75", ratio)
	}
	if saved := pending["bandwidth_saved"].(int64); saved != 600 {
		t.Fatalf("pending bandwidth saved = %d, want 600", saved)
	}
	if archived := store.ArchiveStep(time.Now()); archived != len(events) {
		t.Fatalf("archived = %d, want %d", archived, len(events))
	}
	archived := store.GetStats()
	if ratio := archived["cache_hit_ratio"].(float64); ratio != 75 {
		t.Fatalf("archived cache ratio = %v, want 75", ratio)
	}
	if saved := archived["bandwidth_saved"].(int64); saved != 600 {
		t.Fatalf("archived bandwidth saved = %d, want 600", saved)
	}
	var cacheHits int
	if err := store.db.QueryRow("SELECT SUM(cache_hits) FROM query_hourly_totals").Scan(&cacheHits); err != nil {
		t.Fatal(err)
	}
	if cacheHits != 6 {
		t.Fatalf("hourly cache hits = %d, want 6", cacheHits)
	}
}

func TestRetentionDeletesBoundedBatches(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()
	old := time.Now().Add(-7 * 24 * time.Hour).Unix()
	_, err := store.db.Exec(`WITH RECURSIVE sequence(value) AS (
		SELECT 1 UNION ALL SELECT value + 1 FROM sequence WHERE value < 10005
	) INSERT INTO queries (unix_time, node, client_ip, domain, type)
	SELECT ?, 'node', '192.0.2.1', 'expired.example', 'A' FROM sequence`, old)
	if err != nil {
		t.Fatal(err)
	}
	store.ArchiveStep(time.Now())
	var remaining int
	if err := store.db.QueryRow("SELECT COUNT(*) FROM queries").Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 5 {
		t.Fatalf("remaining after first bounded prune = %d, want 5", remaining)
	}
	store.ArchiveStep(time.Now())
	if err := store.db.QueryRow("SELECT COUNT(*) FROM queries").Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 0 {
		t.Fatalf("remaining after second bounded prune = %d, want 0", remaining)
	}
}

func TestDBMetricsReportsFilesQueueAndMaintenance(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()
	store.AddEvent(models.QueryEvent{
		UnixTime: time.Now().Unix(), Domain: "queued.example", ClientIP: "192.0.2.1", Type: "A",
	})
	checkpointAt := time.Now().Add(-time.Minute)
	store.maintenanceMu.Lock()
	store.checkpointState = checkpointState{
		At: checkpointAt, Duration: 25 * time.Millisecond, Busy: 1, LogFrames: 12, Checkpointed: 10,
	}
	store.maintenanceMu.Unlock()

	metrics := store.DBMetrics(t.Context())
	if metrics.DatabaseBytes <= 0 {
		t.Fatalf("database bytes = %d", metrics.DatabaseBytes)
	}
	if metrics.Archive.Pending != 1 || metrics.Archive.PendingBytes <= 0 {
		t.Fatalf("archive metrics = %+v", metrics.Archive)
	}
	if metrics.BusyTimeoutMS != 5000 || metrics.AutoVacuumMode != "incremental" {
		t.Fatalf("SQLite settings = timeout %d, auto vacuum %q", metrics.BusyTimeoutMS, metrics.AutoVacuumMode)
	}
	if metrics.CheckpointAgeSeconds < 50 || metrics.LastCheckpointBusy != 1 ||
		metrics.LastCheckpointLogFrames != 12 || metrics.LastCheckpointedFrames != 10 {
		t.Fatalf("checkpoint metrics = %+v", metrics)
	}
}

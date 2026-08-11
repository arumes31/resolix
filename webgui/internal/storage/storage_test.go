// Package storage provides unit tests for the Store type, covering
// database initialization, ring buffer operations, batch archiving,
// statistics calculation, and concurrent access patterns.
package storage

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/arumes31/resolix/webgui/internal/config"
	"github.com/arumes31/resolix/webgui/internal/models"
)

// newTestStore creates a Store with an on-disk SQLite database in a temporary
// directory for testing.
func newTestStore(t *testing.T) (*Store, func()) {
	t.Helper()
	cfg := &config.Config{
		MaxEvents:                1000,
		HistoryDir:               t.TempDir(),
		DBPath:                   "test.db",
		HistoryRetention:         72 * time.Hour,
		UpstreamLatencyThreshold: 200,
	}
	s := NewStore(cfg)
	s.Init()
	cleanup := func() {
		s.Close()
	}
	return s, cleanup
}

func TestNewStore(t *testing.T) {
	cfg := &config.Config{
		MaxEvents:                500,
		HistoryDir:               t.TempDir(),
		DBPath:                   "test.db",
		HistoryRetention:         24 * time.Hour,
		UpstreamLatencyThreshold: 200,
	}
	s := NewStore(cfg)
	if s == nil {
		t.Fatal("NewStore returned nil")
	}
	if s.cfg.MaxEvents != 500 {
		t.Errorf("expected MaxEvents 500, got %d", s.cfg.MaxEvents)
	}
	if len(s.events) != 500 {
		t.Errorf("expected events slice length 500, got %d", len(s.events))
	}
}

func TestInitAndSchema(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()

	if s.db == nil {
		t.Fatal("expected database to be initialized")
	}

	// Verify schema by querying the table
	var name string
	err := s.db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='queries'").Scan(&name)
	if err != nil {
		t.Fatalf("queries table not found: %v", err)
	}
	if name != "queries" {
		t.Errorf("expected table name 'queries', got %s", name)
	}
}

func TestAddEvent_EmptyBuffer(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()

	events := s.GetOrderedEvents(10)
	if len(events) != 0 {
		t.Errorf("expected 0 events in empty buffer, got %d", len(events))
	}
}

func TestArchiveStepRetainsBatchOnDatabaseFailure(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()
	s.AddEvent(models.QueryEvent{UnixTime: time.Now().Unix(), Domain: "retry.test", Type: "A"})
	if _, err := s.db.Exec("DROP TABLE queries"); err != nil {
		t.Fatal(err)
	}
	if archived := s.ArchiveStep(time.Now()); archived != 0 {
		t.Fatalf("archived = %d, want 0", archived)
	}
	metrics := s.ArchiveMetrics()
	if metrics.Pending != 1 {
		t.Fatalf("pending batch = %d, want 1", metrics.Pending)
	}
}

func TestArchiveStepPrunesWithoutPendingBatch(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()
	old := time.Now().Add(-7 * 24 * time.Hour).Unix()
	if _, err := s.db.Exec("INSERT INTO queries (unix_time, node, client_ip, domain, type, upstream, latency, dnssec, response_code, client_hostname, blocked, latency_alert, matched_rule, block_reason) VALUES (?, '', '', 'old.test', 'A', '', NULL, '', '', '', 0, 0, '', '')", old); err != nil {
		t.Fatal(err)
	}
	if archived := s.ArchiveStep(time.Now()); archived != 0 {
		t.Fatalf("archived = %d, want 0", archived)
	}
	var count int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM queries WHERE domain = 'old.test'").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("old rows remaining = %d", count)
	}
}

func TestAddEvent_SingleEvent(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()

	now := time.Now().Unix()
	s.AddEvent(models.QueryEvent{
		UnixTime: now,
		Type:     "A",
		Domain:   "example.com",
		ClientIP: "192.168.1.1",
		Node:     "test-node",
	})

	events := s.GetOrderedEvents(10)
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Domain != "example.com" {
		t.Errorf("expected domain 'example.com', got %s", events[0].Domain)
	}
	if events[0].Type != "A" {
		t.Errorf("expected type 'A', got %s", events[0].Type)
	}
	if events[0].ID == "" {
		t.Error("expected non-empty ID")
	}
}

func TestAddEvent_MaxCapacity(t *testing.T) {
	cfg := &config.Config{
		MaxEvents:                5,
		HistoryDir:               t.TempDir(),
		DBPath:                   "test.db",
		HistoryRetention:         72 * time.Hour,
		UpstreamLatencyThreshold: 200,
	}
	s := NewStore(cfg)
	s.Init()
	defer s.Close()

	// Add more events than the buffer can hold
	for i := 0; i < 8; i++ {
		s.AddEvent(models.QueryEvent{
			UnixTime: time.Now().Unix() + int64(i),
			Type:     "A",
			Domain:   fmt.Sprintf("domain%d.com", i),
			ClientIP: "192.168.1.1",
			Node:     "test-node",
		})
	}

	events := s.GetOrderedEvents(10)
	if len(events) != 5 {
		t.Errorf("expected 5 events (max capacity), got %d", len(events))
	}

	// The oldest events should have been overwritten
	if events[0].Domain == "domain0.com" {
		t.Error("expected oldest event to be overwritten")
	}
}

func TestUpdateEvent(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()

	now := time.Now().Unix()
	s.AddEvent(models.QueryEvent{
		UnixTime: now,
		Type:     "A",
		Domain:   "update-test.com",
		ClientIP: "192.168.1.1",
		Node:     "test-node",
	})

	// Update the event with latency and upstream
	updated := s.UpdateEvent("test-node", "update-test.com", 15.5, "8.8.8.8")
	if updated == nil {
		t.Fatal("expected event to be updated, got nil")
	}
	if !updated.Latency.Valid {
		t.Error("expected latency to be valid")
	}
	if updated.Latency.Float64 != 15.5 {
		t.Errorf("expected latency 15.5, got %f", updated.Latency.Float64)
	}
	if updated.Upstream != "8.8.8.8" {
		t.Errorf("expected upstream '8.8.8.8', got %s", updated.Upstream)
	}
}

func TestUpdateEvent_NotFound(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()

	updated := s.UpdateEvent("nonexistent-node", "nonexistent.com", 10.0, "1.1.1.1")
	if updated != nil {
		t.Error("expected nil for nonexistent event update")
	}
}

func TestUpdateEvent_LatencyAlert(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()

	now := time.Now().Unix()
	s.AddEvent(models.QueryEvent{
		UnixTime: now,
		Type:     "A",
		Domain:   "slow-domain.com",
		ClientIP: "192.168.1.1",
		Node:     "test-node",
	})

	// Update with latency above threshold (200ms)
	updated := s.UpdateEvent("test-node", "slow-domain.com", 350.0, "8.8.8.8")
	if updated == nil {
		t.Fatal("expected event to be updated")
	}
	if !updated.LatencyAlert {
		t.Error("expected latency alert to be set for slow upstream")
	}
}

func TestSetBlocked(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()

	now := time.Now().Unix()
	s.AddEvent(models.QueryEvent{
		UnixTime: now,
		Type:     "A",
		Domain:   "blocked-domain.com",
		ClientIP: "192.168.1.1",
		Node:     "test-node",
	})

	s.SetBlocked("test-node", "blocked-domain.com")

	events := s.GetOrderedEvents(10)
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if !events[0].Blocked {
		t.Error("expected event to be marked as blocked")
	}
}

func TestSetClientHostname(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()

	now := time.Now().Unix()
	s.AddEvent(models.QueryEvent{
		UnixTime: now,
		Type:     "A",
		Domain:   "host-test.com",
		ClientIP: "192.168.1.50",
		Node:     "test-node",
	})

	s.SetClientHostname("test-node", "192.168.1.50", "my-laptop")

	events := s.GetOrderedEvents(10)
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].ClientHostname != "my-laptop" {
		t.Errorf("expected hostname 'my-laptop', got %s", events[0].ClientHostname)
	}
}

func TestArchiveStep(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()

	now := time.Now().Unix()
	s.AddEvent(models.QueryEvent{UnixTime: now, Domain: "arch1.com", Node: "n1", Type: "A", ClientIP: "1.1.1.1"})
	s.AddEvent(models.QueryEvent{UnixTime: now, Domain: "arch2.com", Node: "n1", Type: "AAAA", ClientIP: "2.2.2.2"})
	s.AddEvent(models.QueryEvent{UnixTime: now, Domain: "arch3.com", Node: "n1", Type: "TXT", ClientIP: "3.3.3.3"})

	archived := s.ArchiveStep(time.Now())
	if archived != 3 {
		t.Errorf("expected 3 events archived, got %d", archived)
	}

	// Verify data exists in SQLite
	var total int64
	if err := s.db.QueryRow("SELECT COUNT(*) FROM queries").Scan(&total); err != nil {
		t.Fatalf("failed to query total: %v", err)
	}
	if total != 3 {
		t.Errorf("expected 3 rows in SQLite, got %d", total)
	}
}

func TestArchiveStepDrainsMultipleWriteBatches(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()
	s.archiveBatch = 2

	now := time.Now().Unix()
	for i := range 5 {
		s.AddEvent(models.QueryEvent{
			UnixTime: now + int64(i),
			Domain:   fmt.Sprintf("chunk-%d.test", i),
			Type:     "A",
		})
	}
	if archived := s.ArchiveStep(time.Now()); archived != 5 {
		t.Fatalf("archived = %d, want 5", archived)
	}
	if metrics := s.ArchiveMetrics(); metrics.Pending != 0 {
		t.Fatalf("pending after multi-batch drain = %d, want 0", metrics.Pending)
	}
	var total int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM queries").Scan(&total); err != nil {
		t.Fatal(err)
	}
	if total != 5 {
		t.Fatalf("archived rows = %d, want 5", total)
	}
}

func TestArchiveStep_EmptyBatch(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()

	archived := s.ArchiveStep(time.Now())
	if archived != 0 {
		t.Errorf("expected 0 events archived for empty batch, got %d", archived)
	}
}

func TestArchiveStep_WithLatency(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()

	now := time.Now().Unix()
	s.AddEvent(models.QueryEvent{UnixTime: now, Domain: "lat.com", Node: "n1", Type: "A", ClientIP: "1.1.1.1"})
	s.UpdateEvent("n1", "lat.com", 25.0, "8.8.8.8")

	archived := s.ArchiveStep(time.Now())
	if archived != 1 {
		t.Errorf("expected 1 event archived, got %d", archived)
	}

	var latency sql.NullFloat64
	if err := s.db.QueryRow("SELECT latency FROM queries WHERE domain = 'lat.com'").Scan(&latency); err != nil {
		t.Fatalf("failed to query latency: %v", err)
	}
	if !latency.Valid || latency.Float64 != 25.0 {
		t.Errorf("expected latency 25.0, got %v", latency)
	}
}

func TestGetStats(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()

	now := time.Now().Unix()
	s.AddEvent(models.QueryEvent{UnixTime: now, Domain: "stats1.com", Node: "n1", Type: "A", ClientIP: "1.1.1.1"})
	s.AddEvent(models.QueryEvent{UnixTime: now, Domain: "stats2.com", Node: "n1", Type: "A", ClientIP: "2.2.2.2"})
	s.AddEvent(models.QueryEvent{UnixTime: now, Domain: "stats1.com", Node: "n1", Type: "AAAA", ClientIP: "1.1.1.1"})

	s.ArchiveStep(time.Now())

	stats := s.GetStats()
	if stats == nil {
		t.Fatal("expected non-nil stats")
	}

	total, ok := stats["total"].(int64)
	if !ok {
		t.Fatalf("expected int64 for total, got %T", stats["total"])
	}
	if total < 1 {
		t.Errorf("expected total >= 1, got %d", total)
	}

	// Check type counts
	typeCounts, ok := stats["type_counts"].(map[string]int)
	if !ok {
		t.Fatalf("expected map[string]int for type_counts, got %T", stats["type_counts"])
	}
	if typeCounts["A"] < 2 {
		t.Errorf("expected at least 2 A type counts, got %d", typeCounts["A"])
	}
}

func TestGetStatsIncludesPendingTopLists(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()

	now := time.Now().Unix()
	s.AddEvent(models.QueryEvent{UnixTime: now, Domain: "pending.test", Type: "A", ClientIP: "100.64.0.1"})
	if archived := s.ArchiveStep(time.Now()); archived != 1 {
		t.Fatalf("archived = %d, want 1", archived)
	}
	s.AddEvent(models.QueryEvent{UnixTime: now, Domain: "pending.test", Type: "AAAA", ClientIP: "100.64.0.1"})
	s.AddEvent(models.QueryEvent{UnixTime: now, Domain: "pending.test", Type: "A", ClientIP: "100.64.0.1"})
	s.AddEvent(models.QueryEvent{UnixTime: now, Domain: "other.test", Type: "A", ClientIP: "100.64.0.2"})

	stats := s.GetStats()
	topDomains, ok := stats["top_domains"].([]models.StatEntry)
	if !ok {
		t.Fatalf("top_domains type = %T, want []models.StatEntry", stats["top_domains"])
	}
	if len(topDomains) != 2 || topDomains[0].Key != "pending.test" || topDomains[0].Count != 3 {
		t.Fatalf("top_domains = %+v, want pending.test first with count 3", topDomains)
	}

	topClients, ok := stats["top_clients"].([]models.StatEntry)
	if !ok {
		t.Fatalf("top_clients type = %T, want []models.StatEntry", stats["top_clients"])
	}
	if len(topClients) != 2 || topClients[0].Key != "100.64.0.1" || topClients[0].Count != 3 {
		t.Fatalf("top_clients = %+v, want 100.64.0.1 first with count 3", topClients)
	}
}

func TestGetStats_EmptyStore(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()

	stats := s.GetStats()
	if stats == nil {
		t.Fatal("expected non-nil stats even for empty store")
	}

	rpm, ok := stats["rpm"].(int)
	if !ok {
		t.Fatalf("expected int for rpm, got %T", stats["rpm"])
	}
	if rpm != 0 {
		t.Errorf("expected rpm 0 for empty store, got %d", rpm)
	}
}

func BenchmarkGetStatsWithArchivedEvents(b *testing.B) {
	cfg := &config.Config{
		MaxEvents:                10000,
		HistoryDir:               b.TempDir(),
		DBPath:                   "benchmark.db",
		HistoryRetention:         72 * time.Hour,
		UpstreamLatencyThreshold: 200,
		ArchiveQueueCapacity:     10000,
		ArchiveTriggerSize:       5000,
		ArchiveWriteBatchSize:    5000,
	}
	s := NewStore(cfg)
	s.Init()
	b.Cleanup(s.Close)
	now := time.Now().Unix()
	for i := range 10000 {
		s.AddEvent(models.QueryEvent{
			UnixTime: now - int64(i%86400),
			Domain:   fmt.Sprintf("domain-%d.example", i%100),
			Type:     "A",
			ClientIP: fmt.Sprintf("100.64.0.%d", i%100),
			Upstream: "1.1.1.1",
		})
	}
	for s.ArchiveStep(time.Now()) > 0 {
	}

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = s.GetStats()
	}
}

func TestGetRecentEvents(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()

	now := time.Now().Unix()
	s.AddEvent(models.QueryEvent{UnixTime: now - 100, Domain: "old.com", Node: "n1", Type: "A", ClientIP: "1.1.1.1"})
	s.AddEvent(models.QueryEvent{UnixTime: now - 10, Domain: "recent.com", Node: "n1", Type: "A", ClientIP: "1.1.1.1"})
	s.AddEvent(models.QueryEvent{UnixTime: now, Domain: "newest.com", Node: "n1", Type: "A", ClientIP: "1.1.1.1"})

	// Get events newer than (now - 50)
	recent := s.GetRecentEvents(now - 50)
	if len(recent) != 2 {
		t.Errorf("expected 2 recent events, got %d", len(recent))
	}
	if recent[0].Domain != "recent.com" || recent[1].Domain != "newest.com" {
		t.Fatalf("recent events are not oldest-first: %+v", recent)
	}
}

func TestArchiveBatchDropsOldestWhenBounded(t *testing.T) {
	const capacity = 8
	cfg := &config.Config{
		MaxEvents:             10,
		ArchiveQueueCapacity:  capacity,
		ArchiveTriggerSize:    4,
		ArchiveWriteBatchSize: 4,
	}
	s := NewStore(cfg)
	for i := range 3 * capacity {
		s.AddEvent(models.QueryEvent{UnixTime: int64(i + 1), Domain: fmt.Sprintf("event-%d.test", i)})
	}
	s.batchMu.Lock()
	defer s.batchMu.Unlock()
	if got := s.pendingBatchLenLocked(); got != capacity {
		t.Fatalf("batch length = %d, want %d", got, capacity)
	}
	if oldest := s.pendingBatchLocked()[0].Domain; oldest != "event-16.test" {
		t.Fatalf("oldest retained event = %q, want event-16.test", oldest)
	}
	if got := s.batchDropped.Load(); got != 2*capacity {
		t.Fatalf("dropped count = %d, want %d", got, 2*capacity)
	}
	if len(s.batch) > capacity+capacity/4 {
		t.Fatalf("backing queue grew to %d entries for capacity %d", len(s.batch), capacity)
	}
}

func TestArchiveStepPersistsRetainedQueueAfterOverflow(t *testing.T) {
	const capacity = 8
	cfg := &config.Config{
		MaxEvents:                10,
		HistoryDir:               t.TempDir(),
		DBPath:                   "overflow.db",
		HistoryRetention:         72 * time.Hour,
		UpstreamLatencyThreshold: 200,
		ArchiveQueueCapacity:     capacity,
		ArchiveTriggerSize:       4,
		ArchiveWriteBatchSize:    3,
	}
	s := NewStore(cfg)
	s.Init()
	defer s.Close()

	now := time.Now().Unix()
	for i := range capacity + 4 {
		s.AddEvent(models.QueryEvent{
			UnixTime: now + int64(i),
			Domain:   fmt.Sprintf("overflow-%d.test", i),
			Type:     "A",
		})
	}
	if archived := s.ArchiveStep(time.Now()); archived != capacity {
		t.Fatalf("archived = %d, want %d", archived, capacity)
	}
	metrics := s.ArchiveMetrics()
	if metrics.Pending != 0 || metrics.Dropped != 4 {
		t.Fatalf("archive metrics = pending %d, dropped %d; want 0/4", metrics.Pending, metrics.Dropped)
	}

	var count int
	var oldest int64
	if err := s.db.QueryRow("SELECT COUNT(*), MIN(unix_time) FROM queries").Scan(&count, &oldest); err != nil {
		t.Fatal(err)
	}
	if count != capacity || oldest != now+4 {
		t.Fatalf("persisted rows/oldest = %d/%d, want %d/%d", count, oldest, capacity, now+4)
	}
}

func TestArchiveBatchSignalsAtHighWaterMark(t *testing.T) {
	cfg := &config.Config{
		MaxEvents:             10,
		ArchiveQueueCapacity:  10,
		ArchiveTriggerSize:    3,
		ArchiveWriteBatchSize: 3,
	}
	s := NewStore(cfg)

	s.AddEvent(models.QueryEvent{UnixTime: 1, Domain: "event-1.test"})
	s.AddEvent(models.QueryEvent{UnixTime: 2, Domain: "event-2.test"})
	select {
	case <-s.archiveReady:
		t.Fatal("archive signaled before the high-water mark")
	default:
	}

	s.AddEvent(models.QueryEvent{UnixTime: 3, Domain: "event-3.test"})
	select {
	case <-s.archiveReady:
	default:
		t.Fatal("archive was not signaled at the high-water mark")
	}
}

func TestRunArchiverDrainsHighWaterBatch(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()
	s.archiveMark = 3
	s.archiveBatch = 2

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		s.RunArchiver(ctx, time.Hour)
		close(done)
	}()
	defer func() {
		cancel()
		<-done
	}()

	now := time.Now().Unix()
	for i := range 3 {
		s.AddEvent(models.QueryEvent{
			UnixTime: now + int64(i),
			Domain:   fmt.Sprintf("event-%d.test", i+1),
			Type:     "A",
		})
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		metrics := s.ArchiveMetrics()
		if metrics.Pending == 0 {
			if metrics.Dropped != 0 {
				t.Fatalf("dropped events = %d, want 0", metrics.Dropped)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("archive queue did not drain; %d events remain", metrics.Pending)
		}
		time.Sleep(10 * time.Millisecond)
	}

	var total int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM queries").Scan(&total); err != nil {
		t.Fatal(err)
	}
	if total != 3 {
		t.Fatalf("archived rows = %d, want 3", total)
	}
}

func TestRunArchiverConcurrentProducers(t *testing.T) {
	const (
		workers         = 10
		eventsPerWorker = 500
		wantEvents      = workers * eventsPerWorker
	)
	cfg := &config.Config{
		MaxEvents:                1000,
		HistoryDir:               t.TempDir(),
		DBPath:                   "load.db",
		HistoryRetention:         72 * time.Hour,
		UpstreamLatencyThreshold: 200,
		ArchiveQueueCapacity:     20000,
		ArchiveTriggerSize:       100,
		ArchiveWriteBatchSize:    250,
	}
	s := NewStore(cfg)
	s.Init()
	defer s.Close()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		s.RunArchiver(ctx, time.Hour)
		close(done)
	}()
	defer func() {
		cancel()
		<-done
	}()

	now := time.Now().Unix()
	var wg sync.WaitGroup
	for worker := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range eventsPerWorker {
				s.AddEvent(models.QueryEvent{
					UnixTime: now,
					Domain:   fmt.Sprintf("load-%d-%d.test", worker, i),
					Type:     "A",
				})
			}
		}()
	}
	wg.Wait()

	deadline := time.Now().Add(30 * time.Second)
	for {
		metrics := s.ArchiveMetrics()
		if metrics.Pending == 0 {
			if metrics.Dropped != 0 {
				t.Fatalf("dropped events = %d, want 0", metrics.Dropped)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("archive queue did not drain; %d events remain", metrics.Pending)
		}
		time.Sleep(10 * time.Millisecond)
	}

	var total int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM queries").Scan(&total); err != nil {
		t.Fatal(err)
	}
	if total != wantEvents {
		t.Fatalf("archived rows = %d, want %d", total, wantEvents)
	}
}

func TestGetOrderedEvents_Limit(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()

	now := time.Now().Unix()
	for i := 0; i < 10; i++ {
		s.AddEvent(models.QueryEvent{UnixTime: now + int64(i), Domain: fmt.Sprintf("d%d.com", i), Node: "n1", Type: "A", ClientIP: "1.1.1.1"})
	}

	events := s.GetOrderedEvents(5)
	if len(events) != 5 {
		t.Errorf("expected 5 events with limit, got %d", len(events))
	}
}

func TestPendingQueries(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()

	now := time.Now()
	s.SetPending("node1", "example.com", now)

	startTime, upstream, ok := s.GetPending("node1", "example.com")
	if !ok {
		t.Fatal("expected pending query to be found")
	}
	if upstream != "" {
		t.Errorf("expected empty upstream for new pending, got %s", upstream)
	}
	if startTime.IsZero() {
		t.Error("expected non-zero start time")
	}

	// Second get should return false (consumed)
	_, _, ok = s.GetPending("node1", "example.com")
	if ok {
		t.Error("expected pending query to be consumed")
	}
}

func TestSetUpstream(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()

	now := time.Now()
	s.SetPending("node1", "upstream-test.com", now)
	s.SetUpstream("node1", "upstream-test.com", "1.2.3.4")

	_, upstream, ok := s.GetPending("node1", "upstream-test.com")
	if !ok {
		t.Fatal("expected pending query to be found")
	}
	if upstream != "1.2.3.4" {
		t.Errorf("expected upstream '1.2.3.4', got %s", upstream)
	}
}

func TestSetDNSSEC(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()

	now := time.Now().Unix()
	s.AddEvent(models.QueryEvent{UnixTime: now, Domain: "dnssec-test.com", Node: "n1", Type: "A", ClientIP: "1.1.1.1"})

	s.SetDNSSEC("n1", "dnssec-test.com", "secure")

	events := s.GetOrderedEvents(10)
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].DNSSEC != "secure" {
		t.Errorf("expected DNSSEC 'secure', got %s", events[0].DNSSEC)
	}
}

func TestCleanupPending(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()

	// Add a pending query with an old timestamp
	oldTime := time.Now().Add(-60 * time.Second)
	s.SetPending("node1", "stale.com", oldTime)

	// Cleanup should remove stale entries
	s.CleanupPending(time.Now())

	_, _, ok := s.GetPending("node1", "stale.com")
	if ok {
		t.Error("expected stale pending query to be cleaned up")
	}
}

func TestGetClientStats(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()

	now := time.Now().Unix()
	s.AddEvent(models.QueryEvent{UnixTime: now, Domain: "c1.com", Node: "n1", Type: "A", ClientIP: "10.0.0.1"})

	stats := s.GetClientStats("10.0.0.1")
	if stats == nil {
		t.Fatal("expected non-nil client stats")
	}
	if stats["ip"] != "10.0.0.1" {
		t.Errorf("expected ip '10.0.0.1', got %v", stats["ip"])
	}
}

func TestGetUpstreamHealth(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()

	health := map[string]float64{"8.8.8.8": 15.5, "1.1.1.1": 8.2}
	s.SetUpstreamHealth("node1", health)

	result := s.GetUpstreamHealth()
	if len(result) != 1 {
		t.Fatalf("expected 1 node in health data, got %d", len(result))
	}
	if result["node1"]["8.8.8.8"] != 15.5 {
		t.Errorf("expected latency 15.5 for 8.8.8.8, got %f", result["node1"]["8.8.8.8"])
	}
}

func TestGetAlias(t *testing.T) {
	cfg := &config.Config{
		MaxEvents:                100,
		HistoryDir:               t.TempDir(),
		DBPath:                   "test.db",
		HistoryRetention:         72 * time.Hour,
		UpstreamLatencyThreshold: 200,
	}
	cfg.SetClientAliases(map[string]string{"192.168.1.1": "Gateway"})
	s := NewStore(cfg)
	s.Init()
	defer s.Close()

	alias := s.GetAlias("192.168.1.1")
	if alias != "Gateway" {
		t.Errorf("expected alias 'Gateway', got %s", alias)
	}

	alias = s.GetAlias("10.0.0.1")
	if alias != "" {
		t.Errorf("expected empty alias for unknown IP, got %s", alias)
	}
}

func TestClose(t *testing.T) {
	cfg := &config.Config{
		MaxEvents:                100,
		HistoryDir:               t.TempDir(),
		DBPath:                   "test.db",
		HistoryRetention:         72 * time.Hour,
		UpstreamLatencyThreshold: 200,
	}
	s := NewStore(cfg)
	s.Init()

	// Close should not panic
	s.Close()

	// Verify prepared statements are nil after close
	if s.stmtInsertQuery != nil {
		t.Error("expected stmtInsertQuery to be nil after close")
	}
}

func TestConcurrentAddEvent(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()

	var wg sync.WaitGroup
	const workers = 10
	const eventsPerWorker = 100

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < eventsPerWorker; i++ {
				s.AddEvent(models.QueryEvent{
					UnixTime: time.Now().Unix(),
					Type:     "A",
					Domain:   fmt.Sprintf("concurrent-%d-%d.com", id, i),
					ClientIP: "10.0.0.1",
					Node:     "concurrent-node",
				})
			}
		}(w)
	}
	wg.Wait()

	events := s.GetOrderedEvents(workers * eventsPerWorker)
	if len(events) != workers*eventsPerWorker {
		t.Errorf("expected %d events, got %d", workers*eventsPerWorker, len(events))
	}
}

func TestBandwidthSaved(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()

	now := time.Now().Unix()
	s.AddEvent(models.QueryEvent{UnixTime: now, Domain: "bw.com", Node: "n1", Type: "A", ClientIP: "1.1.1.1"})
	s.UpdateEvent("n1", "bw.com", 0.5, "System Cache")

	s.ArchiveStep(time.Now())

	stats := s.GetStats()
	bw, ok := stats["bandwidth_saved"].(int64)
	if !ok {
		t.Fatalf("expected int64 for bandwidth_saved, got %T", stats["bandwidth_saved"])
	}
	if bw < 100 {
		t.Errorf("expected bandwidth_saved >= 100 (1 cached * 100 bytes), got %d", bw)
	}
}

func TestMain(m *testing.M) {
	// Run the storage test suite; log output is not suppressed.
	os.Exit(m.Run())
}

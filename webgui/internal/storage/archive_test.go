package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/arumes31/resolix/webgui/internal/config"
	"github.com/arumes31/resolix/webgui/internal/models"
)

func TestArchiveQueueMetricsUsesFrontendJSONKeys(t *testing.T) {
	data, err := json.Marshal(ArchiveQueueMetrics{Pending: 1, PendingBytes: 2, Dropped: 3, Capacity: 4})
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"pending":1`, `"pending_bytes":2`, `"dropped":3`, `"capacity":4`} {
		if !strings.Contains(string(data), key) {
			t.Fatalf("archive metrics JSON %q is missing %s", data, key)
		}
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

func TestFlushArchiveReturnsDatabaseFailureAndRetainsBatch(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()
	s.AddEvent(models.QueryEvent{UnixTime: time.Now().Unix(), Domain: "retry.test", Type: "A"})
	if _, err := s.db.Exec("DROP TABLE queries"); err != nil {
		t.Fatal(err)
	}

	archived, err := s.FlushArchive(t.Context(), time.Now())
	if err == nil {
		t.Fatal("FlushArchive() error = nil, want database failure")
	}
	if archived != 0 {
		t.Fatalf("FlushArchive() archived = %d, want 0", archived)
	}
	if metrics := s.ArchiveMetrics(); metrics.Pending != 1 {
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

func TestArchiveInFlightEventsAreNotDroppedByProducers(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()
	s.archiveLimit = 2
	s.archiveBatch = 2

	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	s.archiveInsert = func(_ context.Context, _ []models.QueryEvent) error {
		if calls.Add(1) == 1 {
			close(started)
			<-release
		}
		return nil
	}

	s.AddEvent(models.QueryEvent{UnixTime: 1, Domain: "first.test"})
	s.AddEvent(models.QueryEvent{UnixTime: 2, Domain: "second.test"})
	done := make(chan int, 1)
	go func() { done <- s.ArchiveStep(time.Now()) }()
	<-started

	if metrics := s.ArchiveMetrics(); metrics.Pending != 2 {
		t.Fatalf("pending while insert is in flight = %d, want 2", metrics.Pending)
	}
	s.AddEvent(models.QueryEvent{UnixTime: 3, Domain: "third.test"})
	s.AddEvent(models.QueryEvent{UnixTime: 4, Domain: "fourth.test"})
	close(release)
	if archived := <-done; archived != 4 {
		t.Fatalf("archived = %d, want 4", archived)
	}
	if metrics := s.ArchiveMetrics(); metrics.Pending != 0 || metrics.Dropped != 0 {
		t.Fatalf("archive metrics = pending %d, dropped %d; want 0/0", metrics.Pending, metrics.Dropped)
	}
}

func TestArchiveFailureRestoresClaimedEvents(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()
	s.archiveInsert = func(_ context.Context, _ []models.QueryEvent) error {
		return errors.New("test insert failure")
	}
	s.AddEvent(models.QueryEvent{UnixTime: 1, Domain: "retry.test"})

	if archived, err := s.archiveStep(context.Background(), time.Now()); err == nil || archived != 0 {
		t.Fatalf("archive result = %d/%v, want 0/error", archived, err)
	}
	metrics := s.ArchiveMetrics()
	if metrics.Pending != 1 || metrics.Dropped != 0 {
		t.Fatalf("archive metrics = pending %d, dropped %d; want 1/0", metrics.Pending, metrics.Dropped)
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

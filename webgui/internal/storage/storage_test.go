// Package storage provides unit tests for the Store type, covering
// database initialization, ring buffer operations, batch archiving,
// statistics calculation, and concurrent access patterns.
package storage

import (
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

	// Close is idempotent and releases cached statements.
	s.Close()
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

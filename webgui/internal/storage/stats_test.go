package storage

import (
	"fmt"
	"testing"
	"time"

	"github.com/arumes31/resolix/webgui/internal/config"
	"github.com/arumes31/resolix/webgui/internal/models"
)

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

func TestGetStatsMergesArchivedCandidatesBeforeTopLimit(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()

	now := time.Now().Unix()
	archived := 0
	for i := range 10 {
		count := 20 - i
		for range count {
			s.AddEvent(models.QueryEvent{
				UnixTime: now,
				Domain:   fmt.Sprintf("archived-%02d.test", i),
				Type:     "A",
				ClientIP: fmt.Sprintf("192.0.2.%d", i+1),
			})
			archived++
		}
	}
	s.AddEvent(models.QueryEvent{
		UnixTime: now,
		Domain:   "pending-winner.test",
		Type:     "A",
		ClientIP: "198.51.100.1",
	})
	archived++
	if got := s.ArchiveStep(time.Now()); got != archived {
		t.Fatalf("archived = %d, want %d", got, archived)
	}
	for range 20 {
		s.AddEvent(models.QueryEvent{
			UnixTime: now,
			Domain:   "pending-winner.test",
			Type:     "A",
			ClientIP: "198.51.100.1",
		})
	}

	stats := s.GetStats()
	topDomains := stats["top_domains"].([]models.StatEntry)
	if len(topDomains) != 10 || topDomains[0].Key != "pending-winner.test" || topDomains[0].Count != 21 {
		t.Fatalf("top_domains = %+v, want pending-winner.test first with combined count 21", topDomains)
	}
	topClients := stats["top_clients"].([]models.StatEntry)
	if len(topClients) != 10 || topClients[0].Key != "198.51.100.1" || topClients[0].Count != 21 {
		t.Fatalf("top_clients = %+v, want 198.51.100.1 first with combined count 21", topClients)
	}
}

func TestGetStatsMergesArchivedAndPendingHeatmapCounts(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()

	now := time.Now()
	event := models.QueryEvent{
		UnixTime: now.Unix(),
		Domain:   "heatmap.test",
		Type:     "A",
		ClientIP: "192.0.2.1",
	}
	s.AddEvent(event)
	if got := s.ArchiveStep(now); got != 1 {
		t.Fatalf("archived = %d, want 1", got)
	}
	s.AddEvent(event)

	stats := s.GetStats()
	heatmap := stats["heatmap"].(map[string]int)
	hour := now.UTC().Format("15:00")
	if heatmap[hour] != 2 {
		t.Fatalf("heatmap[%q] = %d, want combined count 2", hour, heatmap[hour])
	}
}

func TestGetStatsUsesExactRollingDayAtNonHourBoundary(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()
	now := time.Now().UTC().Truncate(time.Hour).Add(37 * time.Minute)
	cutoff := now.Add(-24 * time.Hour)
	store.AddEvent(models.QueryEvent{
		UnixTime: cutoff.Add(-time.Second).Unix(), Domain: "expired-boundary.example",
		ClientIP: "192.0.2.1", Type: "AAAA", Upstream: "System Cache", CacheStatus: "fresh",
	})
	store.AddEvent(models.QueryEvent{
		UnixTime: cutoff.Add(time.Second).Unix(), Domain: "valid-boundary.example",
		ClientIP: "192.0.2.2", Type: "A", Upstream: "1.1.1.1",
	})
	if archived := store.ArchiveStep(time.Now()); archived != 2 {
		t.Fatalf("archived = %d", archived)
	}
	stats := store.getStatsAt(now)
	if rpd := stats["rpd"].(int); rpd != 1 {
		t.Fatalf("rolling-day queries = %d, want 1", rpd)
	}
	types := stats["type_counts"].(map[string]int)
	if types["A"] != 1 || types["AAAA"] != 0 {
		t.Fatalf("rolling-day types = %+v", types)
	}
	top := stats["top_domains"].([]models.StatEntry)
	if len(top) != 1 || top[0].Key != "valid-boundary.example" {
		t.Fatalf("rolling-day domains = %+v", top)
	}
	if ratio := stats["cache_hit_ratio"].(float64); ratio != 0 {
		t.Fatalf("rolling-day cache ratio = %v, want 0", ratio)
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

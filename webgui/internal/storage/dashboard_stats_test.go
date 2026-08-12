package storage

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/arumes31/resolix/webgui/internal/models"
)

func TestGetDashboardStatsMergesArchivedAndPendingEvents(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	now := time.Now().UTC().Truncate(time.Minute)
	store.AddEvent(models.QueryEvent{
		UnixTime:     now.Add(-45 * time.Minute).Unix(),
		Domain:       "blocked.example",
		ClientIP:     "192.0.2.1",
		Type:         "A",
		Upstream:     "Filtered",
		Blocked:      true,
		ResponseCode: "NXDOMAIN",
	})
	store.AddEvent(models.QueryEvent{
		UnixTime:    now.Add(-30 * time.Minute).Unix(),
		Domain:      "cached.example",
		ClientIP:    "192.0.2.2",
		Type:        "AAAA",
		Upstream:    "System Cache",
		Node:        "edge-a",
		CacheStatus: "fresh",
	})
	if archived := store.ArchiveStep(now); archived != 2 {
		t.Fatalf("archived = %d, want 2", archived)
	}
	store.AddEvent(models.QueryEvent{
		UnixTime:     now.Add(-5 * time.Minute).Unix(),
		Domain:       "failed.example",
		ClientIP:     "192.0.2.3",
		Type:         "A",
		Upstream:     "1.1.1.1",
		Node:         "edge-b",
		ResponseCode: "SERVFAIL",
	})
	store.AddEvent(models.QueryEvent{
		UnixTime:     now.Add(-time.Minute).Unix(),
		Domain:       "forwarded.example",
		ClientIP:     "192.0.2.3",
		Type:         "A",
		Upstream:     "1.1.1.1",
		Node:         "edge-b",
		ResponseCode: "NOERROR",
	})

	stats, err := store.GetDashboardStats(
		t.Context(),
		now.Add(-time.Hour),
		now,
		15*time.Minute,
	)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Summary.Queries != 4 {
		t.Fatalf("queries = %d, want 4", stats.Summary.Queries)
	}
	if stats.Summary.Blocked != 1 || stats.Summary.BlockedRatio != 25 {
		t.Fatalf("blocked summary = %+v, want 1 query and 25%%", stats.Summary)
	}
	if stats.Summary.Errors != 1 || stats.Summary.ErrorRatio != 25 {
		t.Fatalf("error summary = %+v, want 1 operational error and 25%%", stats.Summary)
	}
	if stats.Summary.CacheHits != 1 || stats.Summary.BandwidthSaved != 100 {
		t.Fatalf("cache summary = %+v, want 1 hit and 100 bytes", stats.Summary)
	}
	if stats.NodeTotals["local"] != 1 || stats.NodeTotals["edge-a"] != 1 || stats.NodeTotals["edge-b"] != 2 {
		t.Fatalf("node totals = %+v", stats.NodeTotals)
	}
	if len(stats.TopBlockedDomains) != 1 || stats.TopBlockedDomains[0].Key != "blocked.example" {
		t.Fatalf("top blocked domains = %+v", stats.TopBlockedDomains)
	}
	if stats.ResponseCodes["NXDOMAIN"] != 1 || stats.ResponseCodes["SERVFAIL"] != 1 {
		t.Fatalf("response codes = %+v", stats.ResponseCodes)
	}

	var outcomeTotal int
	for index, point := range stats.Series {
		if index > 0 && point.Start <= stats.Series[index-1].Start {
			t.Fatalf("series is not ascending: %+v", stats.Series)
		}
		outcomeTotal += point.Blocked + point.Cached + point.Errors + point.Forwarded
	}
	if outcomeTotal != stats.Summary.Queries {
		t.Fatalf("stacked outcomes = %d, queries = %d", outcomeTotal, stats.Summary.Queries)
	}
}

func TestGetDashboardStatsUsesExactBoundariesAndZeroFills(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	now := time.Now().UTC().Truncate(time.Minute)
	start := now.Add(-time.Hour)
	for _, timestamp := range []time.Time{
		start.Add(-time.Second),
		start,
		now,
		now.Add(time.Second),
	} {
		store.AddEvent(models.QueryEvent{
			UnixTime: timestamp.Unix(),
			Domain:   "boundary.example",
			ClientIP: "192.0.2.10",
			Type:     "A",
		})
	}
	if archived := store.ArchiveStep(now); archived != 4 {
		t.Fatalf("archived = %d, want 4", archived)
	}

	stats, err := store.GetDashboardStats(t.Context(), start, now, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Summary.Queries != 2 {
		t.Fatalf("queries = %d, want exact boundary events only", stats.Summary.Queries)
	}
	if len(stats.Series) < 6 {
		t.Fatalf("series has %d points, want zero-filled range", len(stats.Series))
	}
	zeroBuckets := 0
	for _, point := range stats.Series {
		if point.Queries == 0 {
			zeroBuckets++
		}
	}
	if zeroBuckets == 0 {
		t.Fatal("series did not include empty buckets")
	}
}

func TestGetDashboardStatsWithComparisonUsesOneNonOverlappingSnapshot(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	now := time.Now().UTC().Truncate(time.Minute)
	currentStart := now.Add(-time.Hour)
	previousStart := currentStart.Add(-time.Hour)
	store.AddEvent(models.QueryEvent{
		UnixTime:     previousStart.Add(10 * time.Minute).Unix(),
		Domain:       "archived-previous.example",
		Type:         "A",
		Upstream:     "1.1.1.1",
		ResponseCode: "NOERROR",
	})
	if archived := store.ArchiveStep(now); archived != 1 {
		t.Fatalf("archived = %d, want 1", archived)
	}
	store.AddEvent(models.QueryEvent{
		UnixTime:     previousStart.Add(20 * time.Minute).Unix(),
		Domain:       "pending-previous.example",
		Type:         "AAAA",
		Upstream:     "System Cache",
		CacheStatus:  "fresh",
		ResponseCode: "NOERROR",
	})
	store.AddEvent(models.QueryEvent{
		UnixTime:     currentStart.Unix(),
		Domain:       "current-boundary.example",
		Type:         "A",
		Blocked:      true,
		ResponseCode: "NXDOMAIN",
	})
	store.AddEvent(models.QueryEvent{
		UnixTime:     now.Add(-time.Minute).Unix(),
		Domain:       "current-failure.example",
		Type:         "A",
		Upstream:     "1.1.1.1",
		ResponseCode: "SERVFAIL",
	})

	stats, err := store.GetDashboardStatsWithComparison(
		t.Context(),
		currentStart,
		now,
		15*time.Minute,
		&previousStart,
	)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Summary.Queries != 2 || stats.Summary.Blocked != 1 || stats.Summary.Errors != 1 {
		t.Fatalf("current summary = %+v", stats.Summary)
	}
	if stats.PreviousSummary == nil {
		t.Fatal("previous summary is nil")
	}
	if stats.PreviousSummary.Queries != 2 || stats.PreviousSummary.CacheHits != 1 || stats.PreviousSummary.CacheHitRatio != 50 {
		t.Fatalf("previous summary = %+v", *stats.PreviousSummary)
	}
	if len(stats.TopDomains) != 2 || stats.TopDomains[0].Key == "archived-previous.example" || stats.TopDomains[1].Key == "pending-previous.example" {
		t.Fatalf("current breakdown contains previous events: %+v", stats.TopDomains)
	}
	var seriesQueries int
	for _, point := range stats.Series {
		seriesQueries += point.Queries
	}
	if seriesQueries != stats.Summary.Queries {
		t.Fatalf("series queries = %d, current queries = %d", seriesQueries, stats.Summary.Queries)
	}
}

func TestGetDashboardStatsWithComparisonReturnsAvailableZeroSummary(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	now := time.Now().UTC().Truncate(time.Minute)
	start := now.Add(-time.Hour)
	previousStart := start.Add(-time.Hour)
	store.AddEvent(models.QueryEvent{UnixTime: now.Add(-time.Minute).Unix(), Domain: "current.example", Type: "A"})

	stats, err := store.GetDashboardStatsWithComparison(t.Context(), start, now, 15*time.Minute, &previousStart)
	if err != nil {
		t.Fatal(err)
	}
	if stats.PreviousSummary == nil || stats.PreviousSummary.Queries != 0 {
		t.Fatalf("previous summary = %+v, want available zero summary", stats.PreviousSummary)
	}
}

func TestGetDashboardStatsRejectsInvalidInput(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()
	now := time.Now()

	tests := []struct {
		name   string
		ctx    context.Context
		start  time.Time
		end    time.Time
		bucket time.Duration
	}{
		{name: "nil context", start: now.Add(-time.Hour), end: now, bucket: time.Minute},
		{name: "reversed range", ctx: t.Context(), start: now, end: now.Add(-time.Hour), bucket: time.Minute},
		{name: "zero bucket", ctx: t.Context(), start: now.Add(-time.Hour), end: now},
		{name: "comparison overlaps current", ctx: t.Context(), start: now.Add(-time.Hour), end: now, bucket: time.Minute},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var err error
			if test.name == "comparison overlaps current" {
				comparisonStart := test.start
				_, err = store.GetDashboardStatsWithComparison(test.ctx, test.start, test.end, test.bucket, &comparisonStart)
			} else {
				_, err = store.GetDashboardStats(test.ctx, test.start, test.end, test.bucket)
			}
			if err == nil {
				t.Fatal("expected validation error")
			}
		})
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := store.GetDashboardStats(ctx, now.Add(-time.Hour), now, time.Minute)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context cancellation", err)
	}
}

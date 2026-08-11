package storage

import (
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/arumes31/resolix/webgui/internal/models"
)

func TestQueryHistoryKeysetAndFilters(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	now := time.Now().UTC().Unix()
	events := []models.QueryEvent{
		{UnixTime: now - 4, Domain: "one.example", ClientIP: "192.0.2.1", Type: "A"},
		{UnixTime: now - 3, Domain: "two.example", ClientIP: "192.0.2.2", Type: "AAAA"},
		{UnixTime: now - 2, Domain: "blocked.example", ClientIP: "192.0.2.1", Type: "A", Blocked: true, ResponseCode: "NXDOMAIN"},
		{UnixTime: now - 1, Domain: "cache.example", ClientIP: "192.0.2.3", Type: "A", Upstream: "System Cache (stale)", ResponseCode: "NOERROR", CacheStatus: "stale", CacheTTL: 42, NegativeSOA: "example."},
		{UnixTime: now, Domain: "newest.example", ClientIP: "192.0.2.4", Type: "TXT", ResponseCode: "SERVFAIL"},
	}
	for _, event := range events {
		store.AddEvent(event)
	}
	if archived := store.ArchiveStep(time.Now()); archived != len(events) {
		t.Fatalf("archived = %d, want %d", archived, len(events))
	}

	page, err := store.QueryHistory(t.Context(), HistoryFilter{Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if !page.HasMore || page.NextCursor == "" || len(page.Events) != 2 ||
		page.Events[0].Domain != "newest.example" || page.Events[1].Domain != "cache.example" {
		t.Fatalf("first page = %+v", page)
	}
	cacheEvent := page.Events[1]
	if cacheEvent.CacheStatus != "stale" || cacheEvent.CacheTTL != 42 || cacheEvent.NegativeSOA != "example." {
		t.Fatalf("cache metadata = %+v", cacheEvent)
	}
	cursor, err := strconv.ParseInt(page.NextCursor, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	page, err = store.QueryHistory(t.Context(), HistoryFilter{Cursor: cursor, Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Events) != 2 || page.Events[0].Domain != "blocked.example" || page.Events[1].Domain != "two.example" {
		t.Fatalf("second page = %+v", page)
	}

	tests := []struct {
		name   string
		filter HistoryFilter
		want   string
		count  int
	}{
		{name: "domain", filter: HistoryFilter{Domain: "BLOCKED.EXAMPLE"}, want: "blocked.example"},
		{name: "client", filter: HistoryFilter{ClientIP: "192.0.2.2"}, want: "two.example"},
		{name: "type", filter: HistoryFilter{Type: "txt"}, want: "newest.example"},
		{name: "blocked", filter: HistoryFilter{Status: "blocked"}, want: "blocked.example"},
		{name: "cache", filter: HistoryFilter{Status: "cache"}, want: "cache.example"},
		{name: "error", filter: HistoryFilter{Status: "error"}, want: "newest.example", count: 2},
		{name: "rcode", filter: HistoryFilter{Status: "nxdomain"}, want: "blocked.example"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			wantCount := test.count
			if wantCount == 0 {
				wantCount = 1
			}
			page, err := store.QueryHistory(t.Context(), test.filter)
			if err != nil {
				t.Fatal(err)
			}
			if len(page.Events) != wantCount || page.Events[0].Domain != test.want {
				t.Fatalf("events = %+v, want %q", page.Events, test.want)
			}
		})
	}
}

func TestQueryHistoryRejectsInvalidTokens(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()
	_, err := store.QueryHistory(t.Context(), HistoryFilter{Type: "A' OR 1=1"})
	if !errors.Is(err, ErrInvalidHistoryFilter) {
		t.Fatalf("error = %v, want ErrInvalidHistoryFilter", err)
	}
}

func TestQueryHistoryCacheFilterExcludesCoalescedMisses(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()
	now := time.Now().Unix()
	for _, event := range []models.QueryEvent{
		{UnixTime: now, Domain: "fresh.example", Type: "A", Upstream: "System Cache", CacheStatus: "fresh"},
		{UnixTime: now, Domain: "legacy.example", Type: "A", Upstream: "System Cache (legacy)"},
		{UnixTime: now, Domain: "coalesced.example", Type: "A", Upstream: "1.1.1.1", CacheStatus: "coalesced"},
	} {
		store.AddEvent(event)
	}
	if archived := store.ArchiveStep(time.Now()); archived != 3 {
		t.Fatalf("archived = %d", archived)
	}
	page, err := store.QueryHistory(t.Context(), HistoryFilter{Status: "cache"})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Events) != 2 {
		t.Fatalf("cache-filtered events = %+v", page.Events)
	}
	for _, event := range page.Events {
		if event.Domain == "coalesced.example" {
			t.Fatal("coalesced miss was classified as a cache hit")
		}
	}
}

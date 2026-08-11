package filter

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestSubscriptionStoreSeedsPersistsAndCopies(t *testing.T) {
	path := filepath.Join(t.TempDir(), "filter-subscriptions.json")
	seeds := []Subscription{{Name: "seed", URL: "https://example.com/list.txt", Enabled: true}}
	store, err := LoadSubscriptionStore(path, seeds)
	if err != nil {
		t.Fatal(err)
	}
	items := store.List()
	if len(items) != 1 || items[0].ID == "" {
		t.Fatalf("seeded subscriptions = %+v", items)
	}
	items[0].Name = "mutated"
	if store.List()[0].Name != "seed" {
		t.Fatal("List exposed internal state")
	}
	if err := store.RequestRefresh(); err != nil {
		t.Fatal(err)
	}
	refreshGeneration := store.List()[0].RefreshGeneration
	if refreshGeneration == "" {
		t.Fatal("refresh request did not persist a generation")
	}

	reloaded, err := LoadSubscriptionStore(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := reloaded.List(); len(got) != 1 || got[0].Name != "seed" || got[0].RefreshGeneration != refreshGeneration {
		t.Fatalf("reloaded subscriptions = %+v", got)
	}
}

func TestSubscriptionRefreshAtUTCValidation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "filter-subscriptions.json")
	if _, err := LoadSubscriptionStore(path, []Subscription{{
		URL: "https://example.com/list.txt", Enabled: true, RefreshAtUTC: "24:00",
	}}); err == nil || !strings.Contains(err.Error(), "HH:MM UTC") {
		t.Fatalf("invalid refresh schedule error = %v", err)
	}
}

func TestScheduledSubscriptionRefreshesOncePerUTCDay(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte("scheduled.example\n"))
	}))
	defer server.Close()
	engine := New()
	engine.AddURLSourceWithOptions(Subscription{
		ID: "scheduled", URL: server.URL, Enabled: true, AllowPrivate: true, RefreshAtUTC: "12:00",
	})
	engine.updateScheduledSources(context.Background(), time.Date(2026, time.August, 12, 11, 59, 0, 0, time.UTC))
	if got := hits.Load(); got != 0 {
		t.Fatalf("hits before schedule = %d", got)
	}
	engine.updateScheduledSources(context.Background(), time.Date(2026, time.August, 12, 12, 0, 0, 0, time.UTC))
	engine.mu.Lock()
	engine.sources[0].LastChecked = time.Date(2026, time.August, 12, 12, 0, 0, 0, time.UTC)
	engine.mu.Unlock()
	engine.updateScheduledSources(context.Background(), time.Date(2026, time.August, 12, 16, 0, 0, 0, time.UTC))
	engine.updateScheduledSources(context.Background(), time.Date(2026, time.August, 13, 12, 0, 0, 0, time.UTC))
	if got := hits.Load(); got != 2 {
		t.Fatalf("scheduled hits = %d, want 2", got)
	}
}

func TestSubscriptionStoreRejectsCredentialURL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "filter-subscriptions.json")
	credentialURL := (&url.URL{
		Scheme: "https",
		Host:   "example.com",
		Path:   "/list",
		User:   url.UserPassword("user", "embedded-value"),
	}).String()
	_, err := LoadSubscriptionStore(path, []Subscription{{URL: credentialURL, Enabled: true}})
	if err == nil {
		t.Fatal("credential-bearing subscription URL accepted")
	}
}

func TestSubscriptionStoreRejectsNormalizedDuplicateURL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "filter-subscriptions.json")
	_, err := LoadSubscriptionStore(path, []Subscription{
		{ID: "first", URL: "HTTPS://Example.com:443/list.txt#one", Enabled: true},
		{ID: "second", URL: "https://example.com/list.txt#two", Enabled: true},
	})
	if err == nil || !strings.Contains(err.Error(), "duplicates subscription") {
		t.Fatalf("normalized duplicate error = %v", err)
	}
}

func TestSubscriptionStoreRefreshesOnlyRequestedSource(t *testing.T) {
	path := filepath.Join(t.TempDir(), "filter-subscriptions.json")
	store, err := LoadSubscriptionStore(path, []Subscription{
		{ID: "first", URL: "https://one.example/list.txt", Enabled: true},
		{ID: "second", URL: "https://two.example/list.txt", Enabled: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RequestSourceRefresh("second"); err != nil {
		t.Fatal(err)
	}
	items := store.List()
	if items[0].RefreshGeneration != "" || items[1].RefreshGeneration == "" {
		t.Fatalf("targeted refresh generations = %+v", items)
	}
	if err := store.RequestSourceRefresh("missing"); !errors.Is(err, ErrSubscriptionNotFound) {
		t.Fatalf("missing refresh error = %v", err)
	}
}

func TestSubscriptionStoreBulkIsAtomic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "filter-subscriptions.json")
	store, err := LoadSubscriptionStore(path, []Subscription{
		{ID: "first", URL: "https://one.example/list.txt", Enabled: true},
		{ID: "second", URL: "https://two.example/list.txt", Enabled: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Bulk("disable", []string{"first", "missing"}); !errors.Is(err, ErrSubscriptionNotFound) {
		t.Fatalf("missing bulk item error = %v", err)
	}
	if items := store.List(); !items[0].Enabled || !items[1].Enabled {
		t.Fatalf("failed bulk action partially applied: %+v", items)
	}
	if err := store.Bulk("disable", []string{"first", "second"}); err != nil {
		t.Fatal(err)
	}
	if items := store.List(); items[0].Enabled || items[1].Enabled {
		t.Fatalf("bulk disable = %+v", items)
	}
}

func TestReplaceURLSourcesPreservesFiles(t *testing.T) {
	engine := New()
	engine.AddFileSource(filepath.Join(t.TempDir(), "missing.txt"), false)
	engine.AddURLSource("https://old.example/list", false)
	engine.ReplaceURLSources([]Subscription{
		{ID: "new", Name: "New", URL: "https://new.example/list", Enabled: true},
		{ID: "disabled", Name: "Disabled", URL: "https://disabled.example/list", Enabled: false},
	})
	sources := engine.Sources()
	if len(sources) != 2 || sources[0].Kind != "file" || sources[1].ID != "new" {
		t.Fatalf("sources = %+v", sources)
	}
	for _, source := range sources {
		if source.ID == "disabled" {
			t.Fatalf("disabled source remained registered: %+v", sources)
		}
	}
}

func TestAllowOnlySubscriptionOverridesBlocklist(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("trusted.blocked.example\n"))
	}))
	t.Cleanup(server.Close)

	engine := New()
	engine.AddFileSource(writeTempList(t, "||blocked.example^\n"), false)
	engine.ReplaceURLSources([]Subscription{{
		ID:           "allow-list",
		Name:         "Trusted domains",
		URL:          server.URL,
		AllowOnly:    true,
		Enabled:      true,
		AllowPrivate: true,
	}})
	engine.UpdateAll(context.Background())

	result := engine.Match("trusted.blocked.example")
	if !result.Allowed || result.Blocked {
		t.Fatalf("allowlist result = %+v", result)
	}
	sources := engine.Sources()
	if len(sources) != 2 || sources[1].AllowRuleCount != 1 || sources[1].RuleCount != 0 {
		t.Fatalf("sources = %+v", sources)
	}
}

func TestReplaceURLSourcesPreservesRulesForRefreshGeneration(t *testing.T) {
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		_, _ = w.Write([]byte("||stable.example^\n"))
	}))
	t.Cleanup(server.Close)

	engine := New()
	subscription := Subscription{
		ID: "stable", Name: "Stable", URL: server.URL, Enabled: true, AllowPrivate: true,
	}
	engine.ReplaceURLSources([]Subscription{subscription})
	engine.UpdateAll(context.Background())
	if !engine.Match("stable.example").Blocked {
		t.Fatal("initial subscription did not block")
	}

	subscription.RefreshGeneration = "next"
	engine.ReplaceURLSources([]Subscription{subscription})
	if !engine.Match("stable.example").Blocked {
		t.Fatal("refresh-only replacement dropped the last good rules")
	}
	if requests != 1 {
		t.Fatalf("replacement performed %d requests, want 1 before scheduled update", requests)
	}
}

package filter

import (
	"net/url"
	"path/filepath"
	"testing"
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

	reloaded, err := LoadSubscriptionStore(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := reloaded.List(); len(got) != 1 || got[0].Name != "seed" {
		t.Fatalf("reloaded subscriptions = %+v", got)
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

func TestReplaceURLSourcesPreservesFiles(t *testing.T) {
	engine := New()
	engine.AddFileSource(filepath.Join(t.TempDir(), "missing.txt"), false)
	engine.AddURLSource("https://old.example/list", false)
	engine.ReplaceURLSources([]Subscription{{ID: "new", Name: "New", URL: "https://new.example/list", Enabled: true}})
	sources := engine.Sources()
	if len(sources) != 2 || sources[0].Kind != "file" || sources[1].ID != "new" {
		t.Fatalf("sources = %+v", sources)
	}
}

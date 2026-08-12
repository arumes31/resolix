package filter

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// writeTempList writes list content to a temp file and returns its path.
func writeTempList(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "list.txt")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadLocalUpdatesLastChangedOnlyForRuleChanges(t *testing.T) {
	path := writeTempList(t, "||one.test^\n")
	engine := New()
	source := engine.AddFileSource(path, false)
	firstChanged := source.LastChanged
	time.Sleep(time.Millisecond)
	engine.LoadLocal()
	if !source.LastChanged.Equal(firstChanged) {
		t.Fatalf("LastChanged moved for identical rules: %v -> %v", firstChanged, source.LastChanged)
	}
	if !source.LastUpdate.After(firstChanged) {
		t.Fatalf("LastUpdate was not refreshed: changed=%v update=%v", firstChanged, source.LastUpdate)
	}
	if err := os.WriteFile(path, []byte("||two.test^\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Millisecond)
	engine.LoadLocal()
	if !source.LastChanged.After(firstChanged) {
		t.Fatalf("LastChanged did not move after a rule change: %v", source.LastChanged)
	}
}

func TestFileSourceLoadAndKeepLastGood(t *testing.T) {
	path := writeTempList(t, "||ads.example.com^\n")
	e := New()
	src := e.AddFileSource(path, false)

	if src.RuleCount != 1 || src.LastError != "" {
		t.Fatalf("source after load: %+v", src)
	}
	if !e.Match("ads.example.com").Blocked {
		t.Fatal("file source rule not active")
	}

	// Corrupt the file and reload: last good rules must be kept on error.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	e.LoadLocal()

	src = e.findSource(path)
	if src.LastError == "" {
		t.Error("expected LastError after failed reload")
	}
	if !e.Match("ads.example.com").Blocked {
		t.Error("last good rules were lost after failed reload")
	}
}

func TestSubscriptionUpdate(t *testing.T) {
	var requests atomic.Int32
	const etag = `"v1"`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etag)
		_, _ = fmt.Fprintln(w, "||subscribed.example.com^")
	}))
	defer server.Close()

	e := New()
	e.AddURLSource(server.URL, false)

	// First fetch: rules loaded, ETag captured.
	e.UpdateAll(context.Background())
	if !e.Match("subscribed.example.com").Blocked {
		t.Fatal("subscription rules not active after first fetch")
	}
	src := e.findSource(server.URL)
	if src.RuleCount != 1 || src.etag != etag || src.LastError != "" {
		t.Fatalf("source after first fetch: %+v", src)
	}

	// Second fetch: conditional GET → 304, rules unchanged.
	e.UpdateAll(context.Background())
	if requests.Load() != 2 {
		t.Errorf("expected 2 requests, got %d", requests.Load())
	}
	if !e.Match("subscribed.example.com").Blocked {
		t.Error("rules lost after 304")
	}
	src = e.findSource(server.URL)
	if src.LastError != "" {
		t.Errorf("unexpected error after 304: %s", src.LastError)
	}
}

func TestManagedSubscriptionBlocksPrivateTargetsByDefault(t *testing.T) {
	var hits atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = fmt.Fprintln(w, "||private.example^")
	}))
	t.Cleanup(server.Close)

	engine := New()
	engine.AddURLSourceWithOptions(Subscription{ID: "private", URL: server.URL, Enabled: true})
	engine.UpdateAll(context.Background())
	source := engine.Sources()[0]
	if source.LastError != "blocked by private-network download protection" || hits.Load() != 0 {
		t.Fatalf("private target status = error %q, hits %d", source.LastError, hits.Load())
	}
}

func TestManagedSubscriptionReportsRedirectAndContentMetadata(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.Redirect(w, r, server.URL+"/list", http.StatusFound)
			return
		}
		_, _ = fmt.Fprintln(w, "! comment\n||metadata.example^\nunsupported option##selector")
	}))
	t.Cleanup(server.Close)

	engine := New()
	engine.AddURLSourceWithOptions(Subscription{
		ID: "metadata", URL: server.URL + "/start", Enabled: true, AllowPrivate: true,
		TimeoutSeconds: 2, RedirectLimit: 2,
	})
	engine.UpdateAll(context.Background())
	source := engine.Sources()[0]
	if source.LastError != "" || source.RuleCount != 1 || source.RuleCountDelta != 1 {
		t.Fatalf("metadata source status = %+v", source)
	}
	if source.RedirectCount != 1 || source.FinalHostname != "127.0.0.1" || source.DownloadedBytes == 0 {
		t.Fatalf("download metadata = %+v", source)
	}
	if source.IgnoredCount != 2 || len(source.Checksum) != 64 || source.LastChecked.IsZero() || source.LastUpdate.IsZero() {
		t.Fatalf("rule metadata = %+v", source)
	}
}

func TestUpdateAllPublishesOneRuleBatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var rule string
		switch r.URL.Path {
		case "/first":
			rule = "||first.example^\n"
		case "/second":
			rule = "||second.example^\n"
		default:
			http.NotFound(w, r)
			return
		}
		_, _ = fmt.Fprint(w, rule)
	}))
	t.Cleanup(server.Close)

	engine := New()
	engine.AddURLSource(server.URL+"/first", false)
	engine.AddURLSource(server.URL+"/second", false)
	var publications atomic.Int32
	engine.SetRulesChangedCallback(func() { publications.Add(1) })
	engine.UpdateAll(context.Background())

	if got := publications.Load(); got != 1 {
		t.Fatalf("rules-changed publications = %d, want 1", got)
	}
	for _, domain := range []string{"first.example", "second.example"} {
		if result := engine.Match(domain); !result.Blocked {
			t.Fatalf("%s was not active after batch publication: %+v", domain, result)
		}
	}
}

func TestSubscriptionFailureKeepsLastGood(t *testing.T) {
	var fail atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if fail.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = fmt.Fprintln(w, "||stable.example.com^")
	}))
	defer server.Close()

	e := New()
	e.AddURLSource(server.URL, false)
	e.UpdateAll(context.Background())
	if !e.Match("stable.example.com").Blocked {
		t.Fatal("initial fetch failed")
	}

	fail.Store(true)
	e.UpdateAll(context.Background())
	src := e.findSource(server.URL)
	if src.LastError == "" {
		t.Error("expected LastError after failed fetch")
	}
	if !e.Match("stable.example.com").Blocked {
		t.Error("last good rules lost after failed fetch")
	}
}

func TestOversizedSubscriptionKeepsLastGoodAndMetadata(t *testing.T) {
	var oversized atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if oversized.Load() {
			w.Header().Set("ETag", `"v2"`)
			_, _ = w.Write([]byte(strings.Repeat("x", maxFetchBytes+1)))
			return
		}
		w.Header().Set("ETag", `"v1"`)
		_, _ = fmt.Fprintln(w, "||stable.example.com^")
	}))
	defer server.Close()

	e := New()
	e.AddURLSource(server.URL, false)
	e.UpdateAll(context.Background())
	src := e.findSource(server.URL)
	lastUpdate, etag := src.LastUpdate, src.etag
	oversized.Store(true)
	e.UpdateAll(context.Background())

	if src.LastError == "" {
		t.Fatal("oversized response did not record an error")
	}
	if !e.Match("stable.example.com").Blocked {
		t.Fatal("oversized response replaced the last good rules")
	}
	if !src.LastUpdate.Equal(lastUpdate) || src.etag != etag {
		t.Fatalf("success metadata changed: update=%v/%v etag=%q/%q", src.LastUpdate, lastUpdate, src.etag, etag)
	}
}

func TestStartUpdateLoopInitialLoad(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintln(w, "||loop.example.com^")
	}))
	defer server.Close()

	e := New()
	e.AddURLSource(server.URL, false)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	e.StartUpdateLoop(ctx, time.Hour) // initial load happens immediately

	deadline := time.Now().Add(2 * time.Second)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for !e.Match("loop.example.com").Blocked {
		if time.Now().After(deadline) {
			t.Fatal("initial subscription load did not happen")
		}
		<-ticker.C
	}
}

func TestStartUpdateLoopSeedsTodaysScheduledRefresh(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = fmt.Fprintln(w, "||scheduled-startup.example.com^")
	}))
	t.Cleanup(server.Close)

	engine := New()
	engine.AddURLSourceWithOptions(Subscription{
		ID: "scheduled-startup", URL: server.URL, Enabled: true, AllowPrivate: true, RefreshAtUTC: "00:00",
	})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	engine.StartUpdateLoop(ctx, time.Hour)

	deadline := time.Now().Add(2 * time.Second)
	seededDay := ""
	for {
		engine.mu.RLock()
		seededDay = engine.sources[0].lastScheduledDay
		engine.mu.RUnlock()
		if seededDay != "" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("initial scheduled source was not marked checked today")
		}
		time.Sleep(10 * time.Millisecond)
	}

	seededDate, err := time.Parse(time.DateOnly, seededDay)
	if err != nil {
		t.Fatal(err)
	}
	engine.updateScheduledSources(context.Background(), seededDate.Add(12*time.Hour))
	if got := requests.Load(); got != 1 {
		t.Fatalf("scheduled source fetched %d times on startup day, want 1", got)
	}
}

func TestStartUpdateLoopHandlesRequestedUpdate(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = fmt.Fprintln(w, "||requested.example.com^")
	}))
	defer server.Close()

	e := New()
	e.AddURLSource(server.URL, false)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	e.StartUpdateLoop(ctx, time.Hour)

	waitForRequests := func(want int64) {
		t.Helper()
		deadline := time.Now().Add(2 * time.Second)
		for requests.Load() < want {
			if time.Now().After(deadline) {
				t.Fatalf("subscription requests = %d, want at least %d", requests.Load(), want)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	waitForRequests(1)
	e.RequestUpdate()
	waitForRequests(2)
}

func TestRefreshGenerationUpdatesOnlyRequestedSubscription(t *testing.T) {
	var firstHits, secondHits atomic.Int64
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		firstHits.Add(1)
		_, _ = fmt.Fprintln(w, "||first.example^")
	}))
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		secondHits.Add(1)
		_, _ = fmt.Fprintln(w, "||second.example^")
	}))
	t.Cleanup(first.Close)
	t.Cleanup(second.Close)

	engine := New()
	subscriptions := []Subscription{
		{ID: "first", URL: first.URL, Enabled: true, AllowPrivate: true},
		{ID: "second", URL: second.URL, Enabled: true, AllowPrivate: true},
	}
	engine.ReplaceURLSources(subscriptions)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	engine.StartUpdateLoop(ctx, time.Hour)
	waitForHitCount(t, &firstHits, 1)
	waitForHitCount(t, &secondHits, 1)

	subscriptions[1].RefreshGeneration = "next"
	engine.ReplaceURLSources(subscriptions)
	waitForHitCount(t, &secondHits, 2)
	time.Sleep(50 * time.Millisecond)
	if firstHits.Load() != 1 {
		t.Fatalf("unrequested subscription fetched %d times", firstHits.Load())
	}
}

func waitForHitCount(t *testing.T, counter *atomic.Int64, want int64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for counter.Load() < want {
		if time.Now().After(deadline) {
			t.Fatalf("subscription requests = %d, want at least %d", counter.Load(), want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

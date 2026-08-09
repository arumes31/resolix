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
	e.UpdateAll()
	if !e.Match("subscribed.example.com").Blocked {
		t.Fatal("subscription rules not active after first fetch")
	}
	src := e.findSource(server.URL)
	if src.RuleCount != 1 || src.etag != etag || src.LastError != "" {
		t.Fatalf("source after first fetch: %+v", src)
	}

	// Second fetch: conditional GET → 304, rules unchanged.
	e.UpdateAll()
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
	e.UpdateAll()
	if !e.Match("stable.example.com").Blocked {
		t.Fatal("initial fetch failed")
	}

	fail.Store(true)
	e.UpdateAll()
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
	e.UpdateAll()
	src := e.findSource(server.URL)
	lastUpdate, etag := src.LastUpdate, src.etag
	oversized.Store(true)
	e.UpdateAll()

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
	for !e.Match("loop.example.com").Blocked {
		if time.Now().After(deadline) {
			t.Fatal("initial subscription load did not happen")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

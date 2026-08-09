package api

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"tailscale-dnsrewrite/webgui/internal/config"
	"tailscale-dnsrewrite/webgui/internal/models"
)

func testServer(cfg *config.Config) *Server {
	return &Server{
		cfg:         cfg,
		sessions:    make(map[string]time.Time),
		subscribers: make(map[chan models.QueryEvent]int),
		rateLimits:  make(map[string]*rateLimitEntry),
		metrics:     &Metrics{StartTime: time.Now()},
	}
}

func TestForwardedHeadersRequireTrustedProxy(t *testing.T) {
	s := testServer(&config.Config{TrustedProxies: []string{"10.0.0.0/8"}})
	r := httptest.NewRequest(http.MethodGet, "http://example.test", nil)
	r.RemoteAddr = "192.0.2.10:1234"
	r.Header.Set("X-Forwarded-For", "203.0.113.9")
	r.Header.Set("X-Forwarded-Proto", "https")
	if got := s.clientIP(r); got != "192.0.2.10" {
		t.Fatalf("untrusted client IP = %q", got)
	}
	if s.isHTTPS(r) {
		t.Fatal("untrusted X-Forwarded-Proto was accepted")
	}

	r.RemoteAddr = "10.1.2.3:1234"
	if got := s.clientIP(r); got != "203.0.113.9" {
		t.Fatalf("trusted client IP = %q", got)
	}
	if !s.isHTTPS(r) {
		t.Fatal("trusted X-Forwarded-Proto was ignored")
	}
}

func TestSessionLifecycle(t *testing.T) {
	s := testServer(&config.Config{})
	token, err := s.newSession()
	if err != nil {
		t.Fatal(err)
	}
	if token == "" || !s.validSession(token) {
		t.Fatal("new session is not valid")
	}
	s.deleteSession(token)
	if s.validSession(token) {
		t.Fatal("deleted session remains valid")
	}
}

func TestInternalRoutesUseWebAuthWithoutIngestSecret(t *testing.T) {
	s := testServer(&config.Config{
		WebUsername: "admin",
		WebPassword: "configured",
		BaseURL:     "/",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/ingest", nil)
	rec := httptest.NewRecorder()
	s.SetupMux().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d; want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestBroadcastAndUnsubscribeAreSerialized(t *testing.T) {
	s := testServer(&config.Config{})
	ch := s.Subscribe()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for range 100 {
			s.BroadcastEvent(models.QueryEvent{})
		}
	}()
	go func() {
		defer wg.Done()
		s.Unsubscribe(ch)
	}()
	wg.Wait()
}

func TestEscapePrometheusLabel(t *testing.T) {
	if got, want := escapePrometheusLabel("a\\b\n\"c"), `a\\b\n\"c`; got != want {
		t.Fatalf("escapePrometheusLabel() = %q; want %q", got, want)
	}
}

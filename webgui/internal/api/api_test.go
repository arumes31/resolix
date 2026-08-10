package api

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/arumes31/resolix/webgui/internal/blocklist"
	"github.com/arumes31/resolix/webgui/internal/config"
	"github.com/arumes31/resolix/webgui/internal/models"
	"github.com/arumes31/resolix/webgui/internal/storage"
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

func TestMetricMethodUsesFixedAllowlist(t *testing.T) {
	tests := []struct {
		name   string
		method string
		want   string
	}{
		{name: "get", method: http.MethodGet, want: http.MethodGet},
		{name: "patch", method: http.MethodPatch, want: http.MethodPatch},
		{name: "unknown", method: "CUSTOM-METHOD", want: "OTHER"},
		{name: "empty", method: "", want: "OTHER"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := metricMethod(test.method); got != test.want {
				t.Fatalf("metricMethod(%q) = %q, want %q", test.method, got, test.want)
			}
		})
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

	r.Header.Set("X-Forwarded-Proto", "https, http")
	if s.isHTTPS(r) {
		t.Fatal("client-supplied HTTPS proto before the trusted proxy hop was accepted")
	}
	r.Header.Set("X-Forwarded-Proto", "http, https")
	if !s.isHTTPS(r) {
		t.Fatal("HTTPS proto from the trusted proxy hop was ignored")
	}
}

func TestStandardForwardedHeaderRequiresTrustedProxy(t *testing.T) {
	s := testServer(&config.Config{TrustedProxies: []string{"127.0.0.1"}})
	r := httptest.NewRequest(http.MethodGet, "http://example.test", nil)
	r.RemoteAddr = "127.0.0.1:1234"
	r.Header.Set("Forwarded", `for="[2001:db8::10]";proto=https`)
	if got := s.clientIP(r); got != "2001:db8::10" {
		t.Fatalf("forwarded client IP = %q", got)
	}
	if !s.isHTTPS(r) {
		t.Fatal("trusted Forwarded proto was ignored")
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
	req.TLS = &tls.ConnectionState{}
	rec := httptest.NewRecorder()
	s.SetupMux().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d; want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestWebAuthBehindTLSReverseProxy(t *testing.T) {
	tmpl := template.Must(template.New("login.html").Parse(`{{define "login.html"}}login{{end}}`))
	s := testServer(&config.Config{
		BaseURL:        "/",
		WebUsername:    "admin",
		WebPassword:    "configured",
		TrustedProxies: []string{"127.0.0.1"},
	})
	s.tmpl = tmpl

	backend := httptest.NewServer(s.SetupMux())
	t.Cleanup(backend.Close)

	directResponse, err := backend.Client().Get(backend.URL + "/login")
	if err != nil {
		t.Fatal(err)
	}
	directStatus := directResponse.StatusCode
	if err := directResponse.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if directStatus != http.StatusUpgradeRequired {
		t.Fatalf("direct HTTP status = %d; want %d", directStatus, http.StatusUpgradeRequired)
	}

	target, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxy := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(target)
			r.SetXForwarded()
			r.Out.Header.Set("X-Forwarded-Proto", "https")
		},
	}
	frontend := httptest.NewTLSServer(proxy)
	t.Cleanup(frontend.Close)

	response, err := frontend.Client().Get(frontend.URL + "/login")
	if err != nil {
		t.Fatal(err)
	}
	responseStatus := response.StatusCode
	cookies := response.Cookies()
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if responseStatus != http.StatusOK {
		t.Fatalf("proxied HTTPS status = %d; want %d", responseStatus, http.StatusOK)
	}
	for _, cookie := range cookies {
		if cookie.Name != csrfCookieName {
			continue
		}
		if !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
			t.Fatalf("CSRF cookie flags = Secure:%t HttpOnly:%t SameSite:%v", cookie.Secure, cookie.HttpOnly, cookie.SameSite)
		}
		return
	}
	t.Fatal("proxied HTTPS response did not set the CSRF cookie")
}

func TestInternalRoutesFailClosedWithoutAnyAuthentication(t *testing.T) {
	s := testServer(&config.Config{BaseURL: "/"})
	req := httptest.NewRequest(http.MethodPost, "/api/ingest", nil)
	rec := httptest.NewRecorder()
	s.SetupMux().ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d; want %d", rec.Code, http.StatusServiceUnavailable)
	}
}

func TestReadRequestBodyLimitsDecompressedSize(t *testing.T) {
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write(bytes.Repeat([]byte("a"), 2048)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(compressed.Bytes()))
	req.Header.Set("Content-Encoding", "gzip")
	_, err := readRequestBody(httptest.NewRecorder(), req, 1024)
	var tooLarge *http.MaxBytesError
	if !errors.As(err, &tooLarge) {
		t.Fatalf("error = %v, want MaxBytesError", err)
	}
}

func TestEventsRejectInvalidSinceAndReturnCursor(t *testing.T) {
	cfg := &config.Config{MaxEvents: 10}
	s := testServer(cfg)
	s.store = storage.NewStore(cfg)
	s.store.AddEvent(models.QueryEvent{UnixTime: time.Now().Unix(), Domain: "cursor.test"})

	recorder := httptest.NewRecorder()
	s.handleEvents(recorder, httptest.NewRequest(http.MethodGet, "/api/events?since=bad", nil))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("invalid since status = %d", recorder.Code)
	}

	recorder = httptest.NewRecorder()
	s.handleEvents(recorder, httptest.NewRequest(http.MethodGet, "/api/events?limit=1", nil))
	if recorder.Code != http.StatusOK || recorder.Header().Get("X-Next-Cursor") == "" {
		t.Fatalf("events status/cursor = %d/%q", recorder.Code, recorder.Header().Get("X-Next-Cursor"))
	}
}

func BenchmarkHandleRootWithFullEventBuffer(b *testing.B) {
	tmpl, err := template.ParseFiles("../../templates/index.html")
	if err != nil {
		b.Fatal(err)
	}
	cfg := &config.Config{MaxEvents: config.DefaultScanLimit, ScanLimit: config.DefaultScanLimit}
	s := testServer(cfg)
	s.store = storage.NewStore(cfg)
	s.tmpl = tmpl
	now := time.Now().Unix()
	for i := range config.DefaultScanLimit {
		s.store.AddEvent(models.QueryEvent{
			UnixTime: now,
			Domain:   fmt.Sprintf("query-%d.example", i),
			Type:     "A",
			ClientIP: "100.64.0.1",
		})
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	b.ReportAllocs()
	b.ResetTimer()
	responseBytes := 0
	for b.Loop() {
		recorder := httptest.NewRecorder()
		s.handleRoot(recorder, req)
		responseBytes = recorder.Body.Len()
	}
	b.ReportMetric(float64(responseBytes), "response-B")
}

func TestHandleRootDoesNotEmbedQueryHistory(t *testing.T) {
	tmpl, err := template.ParseFiles("../../templates/index.html")
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{MaxEvents: 10, ScanLimit: config.DefaultScanLimit}
	s := testServer(cfg)
	s.store = storage.NewStore(cfg)
	s.tmpl = tmpl
	s.store.AddEvent(models.QueryEvent{
		UnixTime: time.Now().Unix(),
		Domain:   "must-not-be-in-page.example",
		Type:     "A",
		ClientIP: "100.64.0.1",
	})

	recorder := httptest.NewRecorder()
	s.handleRoot(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d", recorder.Code)
	}
	if strings.Contains(recorder.Body.String(), "must-not-be-in-page.example") {
		t.Fatal("root response embedded query history that the events API loads separately")
	}
}

func TestHandleStatsCachesShortLivedResponse(t *testing.T) {
	cfg := &config.Config{MaxEvents: 10}
	s := testServer(cfg)
	s.store = storage.NewStore(cfg)
	now := time.Now().Unix()
	s.store.AddEvent(models.QueryEvent{UnixTime: now, Domain: "first.example", Type: "A"})

	readTotal := func() int64 {
		t.Helper()
		recorder := httptest.NewRecorder()
		s.handleStats(recorder, httptest.NewRequest(http.MethodGet, "/api/stats", nil))
		if recorder.Code != http.StatusOK {
			t.Fatalf("status = %d", recorder.Code)
		}
		if got := recorder.Header().Get("Cache-Control"); got != "no-store" {
			t.Fatalf("Cache-Control = %q", got)
		}
		var response struct {
			Total int64 `json:"total"`
		}
		if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
			t.Fatal(err)
		}
		return response.Total
	}

	if got := readTotal(); got != 1 {
		t.Fatalf("initial total = %d", got)
	}
	s.store.AddEvent(models.QueryEvent{UnixTime: now, Domain: "second.example", Type: "A"})
	if got := readTotal(); got != 1 {
		t.Fatalf("cached total = %d, want 1", got)
	}
	s.statsCacheAt = time.Now().Add(-statsResponseTTL)
	if got := readTotal(); got != 2 {
		t.Fatalf("refreshed total = %d, want 2", got)
	}
}

func TestStaticAssetsAreCompressedAndCacheable(t *testing.T) {
	asset := strings.Repeat("const value = 'compressible';\n", 100)
	s := testServer(&config.Config{BaseURL: "/"})
	s.staticHandler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Header().Set("Content-Length", fmt.Sprint(len(asset)))
		_, _ = io.WriteString(w, asset)
	})
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/static/js/app.js", nil)
	req.Header.Set("Accept-Encoding", "gzip")

	s.SetupMux().ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d", recorder.Code)
	}
	if got := recorder.Header().Get("Cache-Control"); got != staticAssetCaching {
		t.Fatalf("Cache-Control = %q", got)
	}
	if got := recorder.Header().Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("Content-Encoding = %q", got)
	}
	if got := recorder.Header().Get("Content-Length"); got != "" {
		t.Fatalf("compressed response retained Content-Length %q", got)
	}
	if got := recorder.Header().Values("Vary"); len(got) != 1 || got[0] != "Accept-Encoding" {
		t.Fatalf("Vary = %v", got)
	}
	reader, err := gzip.NewReader(recorder.Body)
	if err != nil {
		t.Fatal(err)
	}
	decompressed, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if string(decompressed) != asset {
		t.Fatal("decompressed static asset does not match original")
	}
}

func BenchmarkHandleStatsCached(b *testing.B) {
	cfg := &config.Config{MaxEvents: 10}
	s := testServer(cfg)
	s.store = storage.NewStore(cfg)
	s.store.AddEvent(models.QueryEvent{UnixTime: time.Now().Unix(), Domain: "cached.example", Type: "A"})
	s.statsCacheBody = []byte(`{"rpm":1,"rph":1,"rpd":1,"total":1}`)
	s.statsCacheAt = time.Now()
	req := httptest.NewRequest(http.MethodGet, "/api/stats", nil)

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		recorder := httptest.NewRecorder()
		s.handleStats(recorder, req)
	}
}

func TestBroadcastAndUnsubscribeAreSerialized(_ *testing.T) {
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

func TestHandleMetricsIncludesArchivePressure(t *testing.T) {
	cfg := &config.Config{MaxEvents: 10}
	s := testServer(cfg)
	s.store = storage.NewStore(cfg)
	s.store.AddEvent(models.QueryEvent{UnixTime: time.Now().Unix(), Domain: "pending.test"})

	recorder := httptest.NewRecorder()
	s.handleMetrics(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := recorder.Body.String()
	if !strings.Contains(body, "sqlite_archive_pending_events 1\n") {
		t.Fatalf("archive pending metric missing from response:\n%s", body)
	}
	if !strings.Contains(body, "sqlite_archive_dropped_events_total 0\n") {
		t.Fatalf("archive dropped metric missing from response:\n%s", body)
	}
	if !strings.Contains(body, "sqlite_archive_queue_capacity 100000\n") ||
		!strings.Contains(body, "sqlite_archive_trigger_events 5000\n") ||
		!strings.Contains(body, "sqlite_archive_write_batch_events 5000\n") {
		t.Fatalf("archive limit metrics missing from response:\n%s", body)
	}
}

func TestHandleIngestEventsNormalizesInvalidTimestamps(t *testing.T) {
	cfg := &config.Config{MaxEvents: 10}
	s := testServer(cfg)
	s.store = storage.NewStore(cfg)
	now := time.Now().Unix()
	events := []models.QueryEvent{
		{Domain: "negative.example", UnixTime: -1},
		{Domain: "future.example", UnixTime: now + int64((24 * time.Hour).Seconds())},
		{Domain: "valid.example", UnixTime: now - 60},
	}
	body, err := json.Marshal(events)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/ingest", bytes.NewReader(body))
	s.handleIngestEvents(rec, req, body)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d", rec.Code)
	}
	got := s.store.GetOrderedEvents(10)
	byDomain := make(map[string]int64, len(got))
	for _, event := range got {
		byDomain[event.Domain] = event.UnixTime
	}
	if byDomain["negative.example"] < now || byDomain["future.example"] < now {
		t.Fatalf("invalid timestamps were not normalized: %v", byDomain)
	}
	if byDomain["valid.example"] != now-60 {
		t.Fatalf("valid timestamp changed to %d", byDomain["valid.example"])
	}
}

func TestModifyUserRuleConcurrentUpdatesDoNotOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "user_rules.txt")
	const count = 32
	var wg sync.WaitGroup
	for i := range count {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rule := fmt.Sprintf("||domain-%d.example^", i)
			if _, err := modifyUserRule(path, rule, false); err != nil {
				t.Errorf("modifyUserRule: %v", err)
			}
		}()
	}
	wg.Wait()
	data, err := os.ReadFile(path) // #nosec G304 -- path is created under t.TempDir by this test
	if err != nil {
		t.Fatal(err)
	}
	for i := range count {
		rule := fmt.Sprintf("||domain-%d.example^", i)
		if !strings.Contains(string(data), rule+"\n") {
			t.Errorf("missing rule %q", rule)
		}
	}
}

// TestSubpathRouting verifies request-level routing when BaseURL is a prefix
// such as /dns: static assets are served under the prefix, the SSE stream
// enforces authentication, and unauthenticated HTML requests redirect to the
// prefixed login route.
func TestSubpathRouting(t *testing.T) {
	s := testServer(&config.Config{
		BaseURL:        "/dns",
		WebUsername:    "admin",
		WebPassword:    "secret",
		MaxRequestSize: 1048576,
	})
	s.SetStaticHandler(http.FileServer(http.FS(fstest.MapFS{
		"css/test.css": &fstest.MapFile{Data: []byte("body{}")},
	})), nil, nil)
	mux := s.SetupMux()

	// Static assets are served under /dns/static/
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/dns/static/css/test.css", nil))
	if rec.Code != http.StatusOK || rec.Body.String() != "body{}" {
		t.Fatalf("static under /dns/static/: code=%d body=%q", rec.Code, rec.Body.String())
	}

	// The SSE stream under the prefix enforces authentication
	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/dns/api/stream", nil)
	req.TLS = &tls.ConnectionState{}
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated /dns/api/stream: code=%d, want %d", rec.Code, http.StatusUnauthorized)
	}

	// Unauthenticated HTML requests redirect to the prefixed login route
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/dns/", nil)
	req.TLS = &tls.ConnectionState{}
	req.Header.Set("Accept", "text/html")
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/dns/login" {
		t.Fatalf("HTML redirect: code=%d location=%q, want %d /dns/login",
			rec.Code, rec.Header().Get("Location"), http.StatusSeeOther)
	}
}

// TestBroadcastEventBehavior exercises the real broadcast implementation:
// blocklist enrichment, Prometheus metrics, delivery to subscribers, and
// slow-subscriber removal after 10 consecutive drops.
func TestBroadcastEventBehavior(t *testing.T) {
	s := testServer(&config.Config{})

	// Blocklist with a parent-domain entry
	blPath := filepath.Join(t.TempDir(), "blocklist.txt")
	if err := os.WriteFile(blPath, []byte("ads.example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s.SetBlocklist(blocklist.New(blPath))

	// A subscriber receives the enriched event
	ch := s.Subscribe()
	s.BroadcastEvent(models.QueryEvent{Domain: "www.ads.example.com", ClientIP: "192.0.2.1", Type: "A"})
	select {
	case ev := <-ch:
		if !ev.Blocked {
			t.Error("expected event to be marked blocked via parent-domain blocklist entry")
		}
	case <-time.After(time.Second):
		t.Fatal("subscriber did not receive broadcast event")
	}
	if got := s.metrics.QueriesTotal.Load(); got != 1 {
		t.Errorf("QueriesTotal = %d, want 1", got)
	}
	if got := s.metrics.QueriesBlocked.Load(); got != 1 {
		t.Errorf("QueriesBlocked = %d, want 1", got)
	}
	s.Unsubscribe(ch)

	// A slow subscriber (never drained) is removed after 10 consecutive drops
	// and its channel is closed.
	slow := s.Subscribe()
	for range 112 { // 100 buffer capacity + 12 drops
		s.BroadcastEvent(models.QueryEvent{Domain: "example.org"})
	}
	drained := make(chan struct{})
	go func() {
		for range slow { //nolint:revive // drain until closed
		}
		close(drained)
	}()
	select {
	case <-drained:
	case <-time.After(2 * time.Second):
		t.Fatal("slow subscriber channel was not closed after 10 consecutive drops")
	}
	s.subMu.Lock()
	remaining := len(s.subscribers)
	s.subMu.Unlock()
	if remaining != 0 {
		t.Errorf("expected slow subscriber to be removed, %d subscribers remain", remaining)
	}
}

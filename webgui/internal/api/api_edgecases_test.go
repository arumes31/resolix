package api

import (
	"bytes"
	"context"
	"encoding/json"
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/arumes31/resolix/webgui/internal/blocklist"
	"github.com/arumes31/resolix/webgui/internal/clients"
	"github.com/arumes31/resolix/webgui/internal/config"
	"github.com/arumes31/resolix/webgui/internal/dnsroutes"
	"github.com/arumes31/resolix/webgui/internal/filter"
	"github.com/arumes31/resolix/webgui/internal/models"
	"github.com/arumes31/resolix/webgui/internal/rewrites"
	"github.com/arumes31/resolix/webgui/internal/storage"
)

func newAPIStateTestServer(t *testing.T) *Server {
	t.Helper()
	cfg := &config.Config{
		Mode:                     config.ModeController,
		BaseURL:                  "/",
		ConfigDir:                t.TempDir(),
		MaxEvents:                100,
		MaxRequestSize:           1 << 20,
		FilterUpdateInterval:     time.Hour,
		UpstreamLatencyThreshold: 100,
	}
	server := testServer(cfg)
	server.store = storage.NewStore(cfg)
	return server
}

func TestMetricsRecordLatencyAndQueryType(t *testing.T) {
	metrics := &Metrics{StartTime: time.Now()}
	for _, latency := range []float64{1, 10, 50, 100, 500} {
		metrics.RecordUpstreamLatency("resolver", latency)
	}
	metrics.RecordUpstreamLatency("resolver", 5)
	metrics.IncQueriesByType("A")
	metrics.IncQueriesByType("A")

	value, ok := metrics.upstreamLatencies.Load("resolver")
	if !ok {
		t.Fatal("latency bucket was not created")
	}
	bucket := value.(*latencyBucket)
	if bucket.count != 6 || bucket.buckets != [5]int64{2, 1, 1, 1, 1} {
		t.Fatalf("latency bucket = %+v", bucket)
	}
	queries, _ := metrics.queriesByType.Load("A")
	if got := queries.(*atomic.Int64).Load(); got != 2 {
		t.Fatalf("A query count = %d, want 2", got)
	}
}

func TestAuthenticationHelpersAndRateLimit(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("correct"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if !isBcryptHash(string(hash)) || isBcryptHash("plain") {
		t.Fatal("bcrypt hash detection returned an unexpected result")
	}
	if !checkPassword(string(hash), "correct") || checkPassword(string(hash), "wrong") {
		t.Fatal("password comparison returned an unexpected result")
	}
	if got := sanitizeLogValue("a\r\nb"); got != "ab" {
		t.Fatalf("sanitizeLogValue = %q", got)
	}

	backoffs := map[int]time.Duration{
		0: 0, 1: 0, 2: time.Second, 3: 2 * time.Second, 4: 4 * time.Second, 8: 8 * time.Second,
	}
	for count, want := range backoffs {
		if got := getRateLimitBackoff(count); got != want {
			t.Errorf("getRateLimitBackoff(%d) = %s, want %s", count, got, want)
		}
	}

	server := testServer(&config.Config{})
	server.recordFailedLogin("192.0.2.1")
	if limited, _ := server.checkRateLimit("192.0.2.1"); limited {
		t.Fatal("first failed login should not be delayed")
	}
	server.recordFailedLogin("192.0.2.1")
	if limited, remaining := server.checkRateLimit("192.0.2.1"); !limited || remaining <= 0 {
		t.Fatalf("second failed login limited=%t remaining=%s", limited, remaining)
	}
	server.resetRateLimit("192.0.2.1")
	if limited, _ := server.checkRateLimit("192.0.2.1"); limited {
		t.Fatal("reset rate limit remained active")
	}
	server.rateLimits["stale"] = &rateLimitEntry{count: 5, lastSeen: time.Now().Add(-6 * time.Minute)}
	if limited, _ := server.checkRateLimit("stale"); limited {
		t.Fatal("stale rate limit remained active")
	}
}

func TestNodeIdentityHelpers(t *testing.T) {
	tests := []struct {
		value string
		want  string
	}{
		{value: "node-1.example:53", want: "node-1.example:53"},
		{value: "", want: "fallback"},
		{value: "bad/node", want: "fallback"},
		{value: strings.Repeat("a", 129), want: "fallback"},
	}
	for _, test := range tests {
		if got := normalizeNodeIdentity(test.value, "fallback"); got != test.want {
			t.Errorf("normalizeNodeIdentity(%q) = %q, want %q", test.value, got, test.want)
		}
	}
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("X-Node-ID", "stable_id")
	if got := requestNodeIdentity(request, "fallback"); got != "stable_id" {
		t.Fatalf("requestNodeIdentity = %q", got)
	}
}

func TestLoginAndLogoutLifecycle(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("correct"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := template.Must(template.New("login.html").Parse(`{{define "login.html"}}{{if .Error}}{{.Error}}{{else}}login{{end}}{{end}}`))
	server := testServer(&config.Config{BaseURL: "/dns", WebUsername: "admin", WebPassword: "configured"})
	server.tmpl = tmpl
	server.hashedPassword = string(hash)

	getRequest := httptest.NewRequest(http.MethodGet, "https://example.test/dns/login", nil)
	getRecorder := httptest.NewRecorder()
	server.handleLogin(getRecorder, getRequest)
	if getRecorder.Code != http.StatusOK || len(getRecorder.Result().Cookies()) != 1 {
		t.Fatalf("GET login = %d, cookies=%v", getRecorder.Code, getRecorder.Result().Cookies())
	}
	csrf := getRecorder.Result().Cookies()[0].Value

	form := url.Values{"username": {"admin"}, "password": {"wrong"}, "csrf_token": {csrf}}
	badRequest := httptest.NewRequest(http.MethodPost, "https://example.test/dns/login", strings.NewReader(form.Encode()))
	badRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	badRequest.AddCookie(server.newSecureCookie(csrfCookieName, csrf, 60))
	badRecorder := httptest.NewRecorder()
	server.handleLogin(badRecorder, badRequest)
	if badRecorder.Code != http.StatusOK || !strings.Contains(badRecorder.Body.String(), "Invalid username") {
		t.Fatalf("failed login = %d %q", badRecorder.Code, badRecorder.Body.String())
	}

	form.Set("password", "correct")
	goodRequest := httptest.NewRequest(http.MethodPost, "https://example.test/dns/login", strings.NewReader(form.Encode()))
	goodRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	goodRequest.AddCookie(server.newSecureCookie(csrfCookieName, csrf, 60))
	goodRecorder := httptest.NewRecorder()
	server.handleLogin(goodRecorder, goodRequest)
	if goodRecorder.Code != http.StatusSeeOther || goodRecorder.Header().Get("Location") != "/dns/" {
		t.Fatalf("successful login = %d location=%q", goodRecorder.Code, goodRecorder.Header().Get("Location"))
	}
	var session *http.Cookie
	for _, cookie := range goodRecorder.Result().Cookies() {
		if cookie.Name == sessionCookieName {
			session = cookie
		}
	}
	if session == nil || !server.validSession(session.Value) {
		t.Fatal("successful login did not create a valid session")
	}

	logoutForm := url.Values{"csrf_token": {csrf}}
	logoutRequest := httptest.NewRequest(http.MethodPost, "https://example.test/dns/logout", strings.NewReader(logoutForm.Encode()))
	logoutRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	logoutRequest.AddCookie(server.newSecureCookie(csrfCookieName, csrf, 60))
	logoutRequest.AddCookie(session)
	logoutRecorder := httptest.NewRecorder()
	server.handleLogout(logoutRecorder, logoutRequest)
	if logoutRecorder.Code != http.StatusSeeOther || server.validSession(session.Value) {
		t.Fatalf("logout status=%d session still valid=%t", logoutRecorder.Code, server.validSession(session.Value))
	}
}

func TestIngestStructuredEventValidationAndSuccess(t *testing.T) {
	server := newAPIStateTestServer(t)
	server.cfg.IngestSecret = "shared"
	subscriber := server.Subscribe()
	defer server.Unsubscribe(subscriber)

	tests := []struct {
		name   string
		method string
		body   string
		auth   string
		want   int
	}{
		{name: "method", method: http.MethodGet, body: "[]", auth: "Bearer shared", want: http.StatusMethodNotAllowed},
		{name: "auth", method: http.MethodPost, body: "[]", want: http.StatusUnauthorized},
		{name: "malformed", method: http.MethodPost, body: "[", auth: "Bearer shared", want: http.StatusBadRequest},
		{name: "mixed nodes", method: http.MethodPost, body: `[{"node":"a"},{"node":"b"}]`, auth: "Bearer shared", want: http.StatusBadRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(test.method, "/api/ingest", strings.NewReader(test.body))
			request.Header.Set("Authorization", test.auth)
			server.handleIngest(recorder, request)
			if recorder.Code != test.want {
				t.Fatalf("status = %d, want %d; body=%q", recorder.Code, test.want, recorder.Body.String())
			}
		})
	}

	events := []models.QueryEvent{{Node: "agent-one", Domain: "example.test", Type: "A", UnixTime: time.Now().Unix()}}
	body, err := json.Marshal(events)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/ingest", bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer shared")
	request.Header.Set("X-Node-ID", "stable-agent")
	request.Header.Set("X-Node-Version", "2.4.25")
	recorder := httptest.NewRecorder()
	server.handleIngest(recorder, request)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("success status = %d body=%q", recorder.Code, recorder.Body.String())
	}
	status := server.store.GetNodeStatusByID("stable-agent")
	stored := server.store.GetOrderedEvents(10)
	if status == nil || status.Version != "2.4.25" || len(stored) != 1 {
		t.Fatalf("node status=%+v events=%v", status, stored)
	}
	select {
	case event := <-subscriber:
		if event.ID == "" || event.ID != stored[0].ID {
			t.Fatalf("broadcast ID = %q, stored ID = %q", event.ID, stored[0].ID)
		}
	case <-time.After(time.Second):
		t.Fatal("subscriber did not receive ingested event")
	}
}

func TestBroadcastEventAssignsIDWithoutStoring(t *testing.T) {
	server := newAPIStateTestServer(t)
	subscriber := server.Subscribe()
	defer server.Unsubscribe(subscriber)

	server.BroadcastEvent(models.QueryEvent{Domain: "stream-only.example"})
	select {
	case event := <-subscriber:
		if event.ID == "" {
			t.Fatal("broadcast event has an empty ID")
		}
	case <-time.After(time.Second):
		t.Fatal("subscriber did not receive event")
	}
	if events := server.store.GetOrderedEvents(10); len(events) != 0 {
		t.Fatalf("broadcast-only event was stored: %+v", events)
	}
}

func TestIngestLegacyPayloadValidationAndHealth(t *testing.T) {
	server := newAPIStateTestServer(t)
	tooMany := make([]string, 101)
	body, err := json.Marshal(map[string]interface{}{"node": "agent", "batch": tooMany})
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	server.handleIngest(recorder, httptest.NewRequest(http.MethodPost, "/api/ingest", bytes.NewReader(body)))
	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("large batch status = %d", recorder.Code)
	}

	payload := `{"node":"agent-one","health":{"1.1.1.1":12.5}}`
	request := httptest.NewRequest(http.MethodPost, "/api/ingest", strings.NewReader(payload))
	request.Header.Set("X-Node-ID", "stable-agent")
	request.Header.Set("X-Go-Version", "go1.26.5")
	recorder = httptest.NewRecorder()
	server.handleIngest(recorder, request)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("legacy ingest status = %d body=%q", recorder.Code, recorder.Body.String())
	}
	status := server.store.GetNodeStatusByID("stable-agent")
	if status == nil || status.GoVersion != "go1.26.5" {
		t.Fatalf("legacy ingest node status = %+v", status)
	}
	if health := server.store.GetUpstreamHealth(); health["stable-agent"]["1.1.1.1"] != 12.5 {
		t.Fatalf("legacy ingest health = %v", health)
	}
}

func TestIngestRejectsTombstonedNodeBeforeEventsAndHealth(t *testing.T) {
	server, cleanup := newHistoryTestServer(t)
	defer cleanup()
	server.store.SetNodeStatusIdentity("stable-agent", "agent-one", models.NodeStatus{})
	removed, err := server.store.DecommissionNode("stable-agent")
	if err != nil || !removed {
		t.Fatalf("decommission node = %t, %v", removed, err)
	}

	legacy := `{"node":"agent-one","line":"query[A] blocked.test from 192.0.2.1","health":{"1.1.1.1":5}}`
	request := httptest.NewRequest(http.MethodPost, "/api/ingest", strings.NewReader(legacy))
	request.Header.Set("X-Node-ID", "stable-agent")
	recorder := httptest.NewRecorder()
	server.handleIngest(recorder, request)
	if recorder.Code != http.StatusGone {
		t.Fatalf("legacy tombstone status = %d", recorder.Code)
	}

	events, err := json.Marshal([]models.QueryEvent{{Node: "agent-one", Domain: "blocked.test", UnixTime: time.Now().Unix()}})
	if err != nil {
		t.Fatal(err)
	}
	request = httptest.NewRequest(http.MethodPost, "/api/ingest", bytes.NewReader(events))
	request.Header.Set("X-Node-ID", "stable-agent")
	recorder = httptest.NewRecorder()
	server.handleIngest(recorder, request)
	if recorder.Code != http.StatusGone {
		t.Fatalf("structured tombstone status = %d", recorder.Code)
	}
	if got := server.store.GetOrderedEvents(10); len(got) != 0 {
		t.Fatalf("tombstoned ingest stored events: %+v", got)
	}
	if health := server.store.GetUpstreamHealth(); len(health) != 0 {
		t.Fatalf("tombstoned ingest stored health: %+v", health)
	}
}

func TestIngestRejectsOverlongFallbackIdentity(t *testing.T) {
	server := newAPIStateTestServer(t)
	node := strings.Repeat("n", maxNodeIdentityLength+1)
	body, err := json.Marshal([]models.QueryEvent{{Node: node, Domain: "identity.test", UnixTime: time.Now().Unix()}})
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	server.handleIngest(recorder, httptest.NewRequest(http.MethodPost, "/api/ingest", bytes.NewReader(body)))
	if recorder.Code != http.StatusBadRequest || len(server.store.GetOrderedEvents(10)) != 0 {
		t.Fatalf("overlong fallback ingest = %d, events=%v", recorder.Code, server.store.GetOrderedEvents(10))
	}
}

func TestStatusAndSimpleHandlerResponses(t *testing.T) {
	server := newAPIStateTestServer(t)
	server.SetBuildInfo("2.4.25", "abc123")
	server.dnsLoopDetected = true
	server.dnsLoopDetails = "recursive path"
	server.store.SetUpstreamHealth("node-a", map[string]float64{"fast": 10, "slow": 150})

	blockPath := filepath.Join(t.TempDir(), "blocklist.txt")
	if err := os.WriteFile(blockPath, []byte("blocked.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	server.SetBlocklist(blocklist.New(blockPath))

	tests := []struct {
		name    string
		handler http.HandlerFunc
		target  string
		want    string
	}{
		{name: "version", handler: server.handleVersion, target: "/api/version", want: `"version":"2.4.25"`},
		{name: "dns loop", handler: server.handleDNSLoopStatus, target: "/api/dns-loop", want: `"loop_detected":true`},
		{name: "blocklist", handler: server.handleBlocklistStatus, target: "/api/blocklist", want: `"count":1`},
		{name: "latency", handler: server.handleUpstreamLatency, target: "/api/upstreams/latency", want: `"upstream":"slow"`},
		{name: "clients invalid", handler: server.handleClientStats, target: "/api/client-stats?ip=nope", want: "invalid ip"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			test.handler(recorder, httptest.NewRequest(http.MethodGet, test.target, nil))
			if !strings.Contains(recorder.Body.String(), test.want) {
				t.Fatalf("body = %q, want %q", recorder.Body.String(), test.want)
			}
		})
	}
	server.store.AddEvent(models.QueryEvent{ClientIP: "192.0.2.10", Domain: "client.example", UnixTime: time.Now().Unix()})
	clientStats := httptest.NewRecorder()
	server.handleClientStats(clientStats, httptest.NewRequest(http.MethodGet, "/api/client-stats?ip=192.0.2.10", nil))
	if clientStats.Code != http.StatusOK || !strings.Contains(clientStats.Body.String(), `"rph":1`) {
		t.Fatalf("client stats = %d %q", clientStats.Code, clientStats.Body.String())
	}
}

func TestDNSLoopDetectionLifecycle(t *testing.T) {
	server := newAPIStateTestServer(t)
	server.cfg.UpstreamDNS = "192.0.2.53:53"
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	server.StartDNSLoopDetection(ctx)
	server.dnsLoopMu.Lock()
	detected := server.dnsLoopDetected
	server.dnsLoopMu.Unlock()
	if detected {
		t.Fatal("documentation-only upstream unexpectedly matched a local interface")
	}
	server.Broadcast(models.QueryEvent{Domain: "broadcast.example"})
	if server.metrics.QueriesTotal.Load() != 1 {
		t.Fatal("Broadcast did not delegate to BroadcastEvent")
	}
}

func TestFilteringPauseStatusAndClientCRUD(t *testing.T) {
	server := newAPIStateTestServer(t)
	engine := filter.New()
	server.SetFilter(engine)

	pauseRecorder := httptest.NewRecorder()
	server.handleFilteringPause(pauseRecorder, httptest.NewRequest(http.MethodPost, "/api/filtering/pause", strings.NewReader(`{"minutes":1}`)))
	if pauseRecorder.Code != http.StatusOK || !engine.Paused() {
		t.Fatalf("pause response = %d %q", pauseRecorder.Code, pauseRecorder.Body.String())
	}
	statusRecorder := httptest.NewRecorder()
	server.handleFilteringStatus(statusRecorder, httptest.NewRequest(http.MethodGet, "/api/filtering/status", nil))
	if !strings.Contains(statusRecorder.Body.String(), `"enabled":false`) || !strings.Contains(statusRecorder.Body.String(), "paused_until") {
		t.Fatalf("filter status = %q", statusRecorder.Body.String())
	}
	engine.Pause(0)

	registry, err := clients.Load(filepath.Join(server.cfg.ConfigDir, "clients.json"))
	if err != nil {
		t.Fatal(err)
	}
	server.SetClients(registry)
	post := httptest.NewRecorder()
	server.handleClients(post, httptest.NewRequest(http.MethodPost, "/api/clients", strings.NewReader(`{"name":"laptop","ids":["192.0.2.10"]}`)))
	if post.Code != http.StatusOK {
		t.Fatalf("client POST = %d %q", post.Code, post.Body.String())
	}
	put := httptest.NewRecorder()
	server.handleClients(put, httptest.NewRequest(http.MethodPut, "/api/clients", strings.NewReader(`{"name":"laptop","ids":["192.0.2.11"]}`)))
	if put.Code != http.StatusOK {
		t.Fatalf("client PUT = %d %q", put.Code, put.Body.String())
	}
	get := httptest.NewRecorder()
	server.handleClients(get, httptest.NewRequest(http.MethodGet, "/api/clients", nil))
	if !strings.Contains(get.Body.String(), "192.0.2.11") {
		t.Fatalf("client GET = %q", get.Body.String())
	}
	remove := httptest.NewRecorder()
	server.handleClients(remove, httptest.NewRequest(http.MethodDelete, "/api/clients?name=laptop", nil))
	if remove.Code != http.StatusOK || len(registry.List()) != 0 {
		t.Fatalf("client DELETE = %d %q; list=%v", remove.Code, remove.Body.String(), registry.List())
	}
}

func TestFilteringPauseAndClientFailurePaths(t *testing.T) {
	server := newAPIStateTestServer(t)

	method := httptest.NewRecorder()
	server.handleFilteringPause(method, httptest.NewRequest(http.MethodGet, "/api/filtering/pause", nil))
	if method.Code != http.StatusMethodNotAllowed {
		t.Fatalf("pause GET = %d", method.Code)
	}
	unavailable := httptest.NewRecorder()
	server.handleFilteringPause(unavailable, httptest.NewRequest(http.MethodPost, "/api/filtering/pause", strings.NewReader(`{"minutes":1}`)))
	if unavailable.Code != http.StatusServiceUnavailable {
		t.Fatalf("pause without engine = %d %q", unavailable.Code, unavailable.Body.String())
	}
	server.SetFilter(filter.New())
	invalid := httptest.NewRecorder()
	server.handleFilteringPause(invalid, httptest.NewRequest(http.MethodPost, "/api/filtering/pause", strings.NewReader("{")))
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("pause invalid body = %d", invalid.Code)
	}

	server.SetClients(nil)
	clientsUnavailable := httptest.NewRecorder()
	server.handleClients(clientsUnavailable, httptest.NewRequest(http.MethodGet, "/api/clients", nil))
	if clientsUnavailable.Code != http.StatusServiceUnavailable {
		t.Fatalf("clients without registry = %d", clientsUnavailable.Code)
	}
}

func TestRewriteDeleteAndFailurePaths(t *testing.T) {
	server := newAPIStateTestServer(t)
	unavailable := httptest.NewRecorder()
	server.handleRewrites(unavailable, httptest.NewRequest(http.MethodGet, "/api/rewrites", nil))
	if unavailable.Code != http.StatusServiceUnavailable {
		t.Fatalf("rewrites without store = %d", unavailable.Code)
	}

	store, err := rewrites.Load(filepath.Join(server.cfg.ConfigDir, "rewrites.json"), "")
	if err != nil {
		t.Fatal(err)
	}
	created, err := store.Add("remove.example", "A", "192.0.2.10")
	if err != nil {
		t.Fatal(err)
	}
	server.SetRewritesStore(store)

	missingID := httptest.NewRecorder()
	server.handleRewrites(missingID, httptest.NewRequest(http.MethodDelete, "/api/rewrites", nil))
	if missingID.Code != http.StatusBadRequest {
		t.Fatalf("rewrite DELETE without id = %d", missingID.Code)
	}
	missingUpdateID := httptest.NewRecorder()
	server.handleRewrites(missingUpdateID, httptest.NewRequest(http.MethodPut, "/api/rewrites", strings.NewReader(`{"domain":"example.test","type":"A","value":"192.0.2.1"}`)))
	if missingUpdateID.Code != http.StatusBadRequest {
		t.Fatalf("rewrite PUT without id = %d", missingUpdateID.Code)
	}
	missing := httptest.NewRecorder()
	server.handleRewrites(missing, httptest.NewRequest(http.MethodDelete, "/api/rewrites?id=missing", nil))
	if missing.Code != http.StatusNotFound {
		t.Fatalf("rewrite DELETE missing = %d", missing.Code)
	}
	deleted := httptest.NewRecorder()
	server.handleRewrites(deleted, httptest.NewRequest(http.MethodDelete, "/api/rewrites?id="+created.ID, nil))
	if deleted.Code != http.StatusOK || len(store.List()) != 0 {
		t.Fatalf("rewrite DELETE = %d %q list=%v", deleted.Code, deleted.Body.String(), store.List())
	}
	invalid := httptest.NewRecorder()
	server.handleRewrites(invalid, httptest.NewRequest(http.MethodPost, "/api/rewrites", strings.NewReader(`{"domain":"bad domain","type":"A","value":"192.0.2.1"}`)))
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("invalid rewrite POST = %d %q", invalid.Code, invalid.Body.String())
	}
	method := httptest.NewRecorder()
	server.handleRewrites(method, httptest.NewRequest(http.MethodPatch, "/api/rewrites", nil))
	if method.Code != http.StatusMethodNotAllowed {
		t.Fatalf("rewrite PATCH = %d", method.Code)
	}
}

func TestQueryLogBlockAndUnblockActions(t *testing.T) {
	server := newAPIStateTestServer(t)
	engine := filter.New()
	engine.AddFileSource(server.cfg.FullUserRulesPath(), false)
	server.SetFilter(engine)

	call := func(block bool) *httptest.ResponseRecorder {
		t.Helper()
		recorder := httptest.NewRecorder()
		server.handleQuerylogAction(recorder, httptest.NewRequest(
			http.MethodPost, "/api/querylog/action", strings.NewReader(`{"domain":"Ads.Example."}`),
		), block)
		return recorder
	}
	blocked := call(true)
	if blocked.Code != http.StatusOK || !strings.Contains(blocked.Body.String(), `"action":"blocked"`) {
		t.Fatalf("block action = %d %q", blocked.Code, blocked.Body.String())
	}
	unblocked := call(false)
	if unblocked.Code != http.StatusOK || !strings.Contains(unblocked.Body.String(), `"action":"unblocked"`) {
		t.Fatalf("unblock action = %d %q", unblocked.Code, unblocked.Body.String())
	}
	exception := call(false)
	if exception.Code != http.StatusOK || !strings.Contains(exception.Body.String(), `"action":"exception_added"`) {
		t.Fatalf("exception action = %d %q", exception.Code, exception.Body.String())
	}
}

func TestUpstreamAndDNSRouteHandlers(t *testing.T) {
	server := newAPIStateTestServer(t)
	server.cfg.UpstreamsFile = "upstreams.json"
	server.cfg.DNSRoutesFile = "dnsroutes.json"
	reloads := 0
	server.SetUpstreamReloadFunc(func() { reloads++ })
	routes := dnsroutes.New(server.cfg.FullDNSRoutesPath())
	server.SetDNSRoutes(routes)

	settingsRequest := httptest.NewRequest(http.MethodPost, "/api/upstream-settings", strings.NewReader(`{"upstreams":["1.1.1.1"," tls://dns.example "],"bootstrap_servers":["9.9.9.9"]}`))
	settingsRecorder := httptest.NewRecorder()
	server.handleUpstreamSettings(settingsRecorder, settingsRequest)
	if settingsRecorder.Code != http.StatusOK || reloads != 1 {
		t.Fatalf("upstream settings POST = %d %q reloads=%d", settingsRecorder.Code, settingsRecorder.Body.String(), reloads)
	}
	getSettings := httptest.NewRecorder()
	server.handleUpstreamSettings(getSettings, httptest.NewRequest(http.MethodGet, "/api/upstream-settings", nil))
	if !strings.Contains(getSettings.Body.String(), `"scheme":"tls"`) || !strings.Contains(getSettings.Body.String(), "9.9.9.9") {
		t.Fatalf("upstream settings GET = %q", getSettings.Body.String())
	}

	postRoutes := httptest.NewRecorder()
	server.handleDNSRoutes(postRoutes, httptest.NewRequest(http.MethodPost, "/api/dns-routes", strings.NewReader(`{"*.example.test":"1.1.1.1","host.example.test":"tls://dns.example"}`)))
	if postRoutes.Code != http.StatusOK || routes.Count() != 2 {
		t.Fatalf("routes POST = %d %q count=%d", postRoutes.Code, postRoutes.Body.String(), routes.Count())
	}
	testRoute := httptest.NewRecorder()
	server.handleDNSRouteTest(testRoute, httptest.NewRequest(http.MethodGet, "/api/dns-routes/test?domain=host.example.test", nil))
	if !strings.Contains(testRoute.Body.String(), `"matched":true`) || !strings.Contains(testRoute.Body.String(), `"exact":true`) {
		t.Fatalf("route test = %q", testRoute.Body.String())
	}
	getRoutes := httptest.NewRecorder()
	server.handleDNSRoutes(getRoutes, httptest.NewRequest(http.MethodGet, "/api/dns-routes", nil))
	if !strings.Contains(getRoutes.Body.String(), `"count":2`) {
		t.Fatalf("routes GET = %q", getRoutes.Body.String())
	}
}

func TestLegacyUpstreamHandlersAndProbeValidation(t *testing.T) {
	server := newAPIStateTestServer(t)
	server.cfg.UpstreamsFile = "upstreams.json"
	server.cfg.UpstreamDNS = "1.1.1.1"

	get := httptest.NewRecorder()
	server.handleUpstreams(get, httptest.NewRequest(http.MethodGet, "/api/upstreams", nil))
	if get.Code != http.StatusOK || !strings.Contains(get.Body.String(), "1.1.1.1") {
		t.Fatalf("upstreams GET = %d %q", get.Code, get.Body.String())
	}
	post := httptest.NewRecorder()
	server.handleUpstreams(post, httptest.NewRequest(http.MethodPost, "/api/upstreams", strings.NewReader(`[{"address":"9.9.9.9"}]`)))
	if post.Code != http.StatusOK || !strings.Contains(post.Body.String(), "9.9.9.9") {
		t.Fatalf("upstreams POST = %d %q", post.Code, post.Body.String())
	}
	method := httptest.NewRecorder()
	server.handleUpstreams(method, httptest.NewRequest(http.MethodDelete, "/api/upstreams", nil))
	if method.Code != http.StatusMethodNotAllowed {
		t.Fatalf("upstreams DELETE = %d", method.Code)
	}

	tests := []struct {
		name   string
		method string
		body   string
		want   int
	}{
		{name: "method", method: http.MethodGet, want: http.StatusMethodNotAllowed},
		{name: "json", method: http.MethodPost, body: "{", want: http.StatusBadRequest},
		{name: "domain", method: http.MethodPost, body: `{"spec":"1.1.1.1","domain":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example"}`, want: http.StatusBadRequest},
		{name: "bootstrap", method: http.MethodPost, body: `{"spec":"tls://dns.example","domain":"example.test","bootstrap_servers":["bad"]}`, want: http.StatusBadRequest},
		{name: "spec", method: http.MethodPost, body: `{"spec":"bad://resolver","domain":"example.test","bootstrap_servers":["1.1.1.1"]}`, want: http.StatusBadRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			server.handleUpstreamTest(recorder, httptest.NewRequest(test.method, "/api/upstreams/test", strings.NewReader(test.body)))
			if recorder.Code != test.want {
				t.Fatalf("status = %d, want %d; body=%q", recorder.Code, test.want, recorder.Body.String())
			}
		})
	}
}

func TestStreamValidationAndCanceledConnection(t *testing.T) {
	server := newAPIStateTestServer(t)
	invalid := httptest.NewRecorder()
	invalidRequest := httptest.NewRequest(http.MethodGet, "/api/stream", nil)
	invalidRequest.Header.Set("Last-Event-ID", "invalid")
	server.handleStream(invalid, invalidRequest)
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("invalid stream cursor status = %d", invalid.Code)
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	request := httptest.NewRequest(http.MethodGet, "/api/stream", nil).WithContext(ctx)
	recorder := httptest.NewRecorder()
	server.handleStream(recorder, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "retry: 3000") {
		t.Fatalf("canceled stream = %d %q", recorder.Code, recorder.Body.String())
	}
}

func TestReadyAndNodeHandlerFailurePaths(t *testing.T) {
	server := newAPIStateTestServer(t)
	server.cfg.NodeOfflineThreshold = time.Hour
	ready := httptest.NewRecorder()
	server.handleReadyz(ready, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if ready.Code != http.StatusServiceUnavailable || !strings.Contains(ready.Body.String(), "not_ready") {
		t.Fatalf("ready response = %d %q", ready.Code, ready.Body.String())
	}

	server.store.SetNodeStatusIdentity("online-id", "online", models.NodeStatus{})
	get := httptest.NewRecorder()
	server.handleNodes(get, httptest.NewRequest(http.MethodGet, "/api/nodes", nil))
	if get.Code != http.StatusOK || !strings.Contains(get.Body.String(), "online-id") {
		t.Fatalf("nodes GET = %d %q", get.Code, get.Body.String())
	}
	conflict := httptest.NewRecorder()
	server.handleNodes(conflict, httptest.NewRequest(http.MethodDelete, "/api/nodes?id=online-id", nil))
	if conflict.Code != http.StatusConflict {
		t.Fatalf("online node DELETE = %d %q", conflict.Code, conflict.Body.String())
	}
	restore := httptest.NewRecorder()
	server.handleNodes(restore, httptest.NewRequest(http.MethodPost, "/api/nodes?action=restore&id=missing", nil))
	if restore.Code != http.StatusNotFound {
		t.Fatalf("missing node restore = %d %q", restore.Code, restore.Body.String())
	}
	method := httptest.NewRecorder()
	server.handleNodes(method, httptest.NewRequest(http.MethodPatch, "/api/nodes", nil))
	if method.Code != http.StatusMethodNotAllowed {
		t.Fatalf("nodes PATCH = %d", method.Code)
	}
	unsupported := httptest.NewRecorder()
	server.handleNodes(unsupported, httptest.NewRequest(http.MethodPost, "/api/nodes?action=invalid&id=online-id", nil))
	if unsupported.Code != http.StatusBadRequest {
		t.Fatalf("unsupported node action = %d", unsupported.Code)
	}
	missingNode := httptest.NewRecorder()
	server.handleNodes(missingNode, httptest.NewRequest(http.MethodDelete, "/api/nodes?id=missing", nil))
	if missingNode.Code != http.StatusNotFound {
		t.Fatalf("missing node DELETE = %d", missingNode.Code)
	}
}

func TestCacheStatusAndSimulationValidation(t *testing.T) {
	server := newAPIStateTestServer(t)
	tests := []struct {
		name    string
		handler http.HandlerFunc
		method  string
		target  string
		want    int
	}{
		{name: "cache method", handler: server.handleCacheStatus, method: http.MethodPost, target: "/api/cache", want: http.StatusMethodNotAllowed},
		{name: "cache unavailable", handler: server.handleCacheStatus, method: http.MethodGet, target: "/api/cache", want: http.StatusServiceUnavailable},
		{name: "simulate missing", handler: server.handleSimulate, method: http.MethodGet, target: "/api/simulate", want: http.StatusBadRequest},
		{name: "simulate invalid", handler: server.handleSimulate, method: http.MethodGet, target: "/api/simulate?domain=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example", want: http.StatusBadRequest},
		{name: "simulate unavailable", handler: server.handleSimulate, method: http.MethodGet, target: "/api/simulate?domain=example.test", want: http.StatusServiceUnavailable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			test.handler(recorder, httptest.NewRequest(test.method, test.target, nil))
			if recorder.Code != test.want {
				t.Fatalf("status = %d, want %d; body=%q", recorder.Code, test.want, recorder.Body.String())
			}
		})
	}
}

func TestNodeDecommissionAndRestoreLifecycle(t *testing.T) {
	server, cleanup := newHistoryTestServer(t)
	defer cleanup()
	server.cfg.Mode = config.ModeController
	server.cfg.NodeOfflineThreshold = -time.Second
	server.nodeSyncGenerations = map[string]uint64{"stable-agent": 4}
	server.store.SetNodeStatusIdentity("stable-agent", "agent", models.NodeStatus{})

	remove := httptest.NewRecorder()
	server.handleNodes(remove, httptest.NewRequest(http.MethodDelete, "/api/nodes?id=stable-agent", nil))
	if remove.Code != http.StatusOK || !server.store.IsNodeTombstoned("stable-agent") {
		t.Fatalf("node DELETE = %d %q tombstoned=%t", remove.Code, remove.Body.String(), server.store.IsNodeTombstoned("stable-agent"))
	}
	restore := httptest.NewRecorder()
	server.handleNodes(restore, httptest.NewRequest(http.MethodPost, "/api/nodes?action=restore&id=stable-agent", nil))
	if restore.Code != http.StatusOK || server.store.IsNodeTombstoned("stable-agent") {
		t.Fatalf("node restore = %d %q tombstoned=%t", restore.Code, restore.Body.String(), server.store.IsNodeTombstoned("stable-agent"))
	}
}

func TestHeartbeatAndSyncEndpoints(t *testing.T) {
	server := newAPIStateTestServer(t)
	server.cfg.IngestSecret = "shared"
	server.cfg.NodeName = "controller"
	server.nodeSyncGenerations = make(map[string]uint64)
	heartbeat := models.HeartbeatPayload{
		Node: "agent-one", NodeID: "stable-agent", Version: "2.4.25", MemoryMB: 42,
		Goroutines: 12, Health: map[string]float64{"1.1.1.1": 5}, SentAt: time.Now().Add(-time.Second),
	}
	body, err := json.Marshal(heartbeat)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/heartbeat", bytes.NewReader(body))
	request.RemoteAddr = "100.64.0.2:53000"
	request.Header.Set("Authorization", "Bearer shared")
	request.Header.Set("X-Node-ID", "stable-agent")
	recorder := httptest.NewRecorder()
	server.handleHeartbeat(recorder, request)
	if recorder.Code != http.StatusNoContent || recorder.Header().Get("X-Config-Sync-Generation") != "0:0" {
		t.Fatalf("heartbeat = %d headers=%v body=%q", recorder.Code, recorder.Header(), recorder.Body.String())
	}
	status := server.store.GetNodeStatusByID("stable-agent")
	if status == nil || status.SourceAddress != "100.64.0.2" || status.MemoryMB != 42 {
		t.Fatalf("node status = %+v", status)
	}

	tests := []struct {
		name    string
		handler http.HandlerFunc
		want    string
	}{
		{name: "aliases", handler: server.handleSyncAliases, want: "{}"},
		{name: "routes", handler: server.handleSyncDNSRoutes, want: `"routes":{}`},
		{name: "health", handler: server.handleSyncUpstreamHealth, want: "stable-agent"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/api/sync", nil)
			request.Header.Set("Authorization", "Bearer shared")
			recorder := httptest.NewRecorder()
			test.handler(recorder, request)
			if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), test.want) {
				t.Fatalf("response = %d %q, want %q", recorder.Code, recorder.Body.String(), test.want)
			}
		})
	}
}

package api

import (
	"encoding/json"
	"html/template"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tailscale-dnsrewrite/webgui/internal/clients"
	"tailscale-dnsrewrite/webgui/internal/config"
	"tailscale-dnsrewrite/webgui/internal/configsync"
	"tailscale-dnsrewrite/webgui/internal/dnsroutes"
	"tailscale-dnsrewrite/webgui/internal/filter"
	"tailscale-dnsrewrite/webgui/internal/rewrites"
)

func TestConfigPageIsDedicatedAndRootRejectsUnknownPaths(t *testing.T) {
	tmpl, err := template.ParseFiles("../../templates/index.html", "../../templates/config.html")
	if err != nil {
		t.Fatal(err)
	}
	server := testServer(&config.Config{BaseURL: "/", Mode: "master", MaxRequestSize: 1 << 20})
	server.tmpl = tmpl
	mux := server.SetupMux()

	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/config", nil))
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `id="configAuthority"`) {
		t.Fatalf("config response = %d %q", recorder.Code, recorder.Body.String())
	}

	recorder = httptest.NewRecorder()
	mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/not-a-route", nil))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("unknown route status = %d", recorder.Code)
	}
}

func TestSlaveRejectsConfigurationMutation(t *testing.T) {
	server := testServer(&config.Config{Mode: "slave"})
	recorder := httptest.NewRecorder()
	server.handlePostUpstreams(recorder, httptest.NewRequest(http.MethodPost, "/api/upstreams", strings.NewReader("[]")))
	if recorder.Code != http.StatusForbidden || !strings.Contains(recorder.Body.String(), "read-only") {
		t.Fatalf("response = %d %q", recorder.Code, recorder.Body.String())
	}
}

func TestMasterRejectsEmptyUpstreamList(t *testing.T) {
	server := testServer(&config.Config{Mode: "master", WebUsername: "admin", WebPassword: "password"})
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/upstreams", strings.NewReader("[]"))
	request.AddCookie(&http.Cookie{
		Name: csrfCookieName, Value: "token", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
	request.Header.Set("X-CSRF-Token", "token")
	server.handlePostUpstreams(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("response = %d %q", recorder.Code, recorder.Body.String())
	}
}

func TestSyncDNSConfigRequiresBearerAndReturnsValidRevision(t *testing.T) {
	dir := t.TempDir()
	server := testServer(&config.Config{
		Mode:         "master",
		IngestSecret: "cluster-secret",
		HistoryDir:   dir,
		UpstreamDNS:  "1.1.1.1",
	})
	recorder := httptest.NewRecorder()
	server.handleSyncDNSConfig(recorder, httptest.NewRequest(http.MethodGet, "/api/sync/dns-config", nil))
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d", recorder.Code)
	}

	recorder = httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/sync/dns-config", nil)
	request.Header.Set("Authorization", "Bearer cluster-secret")
	server.handleSyncDNSConfig(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("authenticated status = %d body=%q", recorder.Code, recorder.Body.String())
	}
	var snapshot configsync.Snapshot
	if err := json.Unmarshal(recorder.Body.Bytes(), &snapshot); err != nil {
		t.Fatal(err)
	}
	validRevision, err := snapshot.ValidRevision()
	if err != nil {
		t.Fatal(err)
	}
	if !validRevision || len(snapshot.Upstreams) != 1 {
		t.Fatalf("snapshot = %+v", snapshot)
	}
}

func TestApplyConfigSnapshotPersistsAllManagedSettings(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{Mode: "slave", HistoryDir: dir, UpstreamsFile: "upstreams.json"}
	server := testServer(cfg)
	engine := filter.New()
	userRulesPath := filepath.Join(dir, "user_rules.txt")
	if err := os.WriteFile(userRulesPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	engine.AddFileSource(userRulesPath, false)
	subscriptions, err := filter.LoadSubscriptionStore(filepath.Join(dir, "filter-subscriptions.json"), nil)
	if err != nil {
		t.Fatal(err)
	}
	rewriteStore, err := rewrites.Load(filepath.Join(dir, "rewrites.json"), "")
	if err != nil {
		t.Fatal(err)
	}
	clientRegistry, err := clients.Load(filepath.Join(dir, "clients.json"))
	if err != nil {
		t.Fatal(err)
	}
	server.SetFilter(engine)
	server.SetSubscriptionStore(subscriptions)
	server.SetRewritesStore(rewriteStore)
	server.SetClients(clientRegistry)
	dnsRoutes := dnsroutes.New(filepath.Join(dir, "dns-routes.json"))
	server.SetDNSRoutes(dnsRoutes)

	snapshot, err := configsync.NewSnapshot(
		[]string{"1.1.1.1"}, map[string]string{"internal": "9.9.9.9"}, nil, "||blocked.example^\n",
		[]rewrites.Rewrite{{ID: "rewrite-1", Domain: "printer.internal", Type: "A", Value: "192.0.2.10"}},
		[]clients.Client{{Name: "office", IDs: []string{"192.0.2.0/24"}, UseGlobalSettings: true}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.ApplyConfigSnapshot(snapshot); err != nil {
		t.Fatal(err)
	}
	if got := server.configuredUpstreams(); len(got) != 1 || got[0] != "1.1.1.1" {
		t.Fatalf("upstreams = %v", got)
	}
	if len(rewriteStore.List()) != 1 || len(clientRegistry.List()) != 1 {
		t.Fatalf("rewrites/clients = %d/%d", len(rewriteStore.List()), len(clientRegistry.List()))
	}
	if got := dnsRoutes.GetRoutesMap(); got["internal"] != "9.9.9.9" {
		t.Fatalf("DNS routes = %v", got)
	}
	if result := engine.Match("blocked.example"); !result.Blocked {
		t.Fatalf("synced user rule did not block: %+v", result)
	}
}

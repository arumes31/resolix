package api

import (
	"bytes"
	"encoding/json"
	"html/template"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/arumes31/resolix/webgui/internal/clients"
	"github.com/arumes31/resolix/webgui/internal/config"
	"github.com/arumes31/resolix/webgui/internal/configsync"
	"github.com/arumes31/resolix/webgui/internal/dnsroutes"
	"github.com/arumes31/resolix/webgui/internal/dnssettings"
	"github.com/arumes31/resolix/webgui/internal/filter"
	"github.com/arumes31/resolix/webgui/internal/rewrites"
)

func TestDedicatedPagesAndRootRejectsUnknownPaths(t *testing.T) {
	tmpl, err := template.ParseFiles(
		"../../templates/index.html",
		"../../templates/querylog.html",
		"../../templates/cluster.html",
		"../../templates/config.html",
	)
	if err != nil {
		t.Fatal(err)
	}
	server := testServer(&config.Config{BaseURL: "/", Mode: config.ModeController, MaxRequestSize: 1 << 20})
	server.tmpl = tmpl
	mux := server.SetupMux()

	assertPage(t, mux, "/config", http.StatusOK, []string{
		`class="app-page config-page compact"`,
		`data-page="config"`,
		`id="configAuthority"`,
		`id="bootstrapList"`,
		`id="allowlistForm"`,
		`id="allowlistList"`,
		`id="filterTestClient"`,
		`id="filterTestType"`,
		`id="dnsSettingsForm"`,
		`id="magicDNSSummary"`,
		`id="syncMagicDNSBtn"`,
		`id="syncAllNodesBtn"`,
		`id="configSyncProgress"`,
		`id="configEditBar"`,
		`id="rewriteDeleteDialog"`,
	}, nil)

	pageTests := []struct {
		path       string
		marker     string
		notPresent []string
	}{
		{path: "/", marker: `id="dashboardRange"`, notPresent: []string{`id="eventTable"`, `id="nodeCards"`}},
		{path: "/querylog", marker: `id="eventTable"`, notPresent: []string{`id="dashboardRange"`, `id="nodeCards"`}},
		{path: "/cluster", marker: `id="nodeCards"`, notPresent: []string{`id="dashboardRange"`, `id="eventTable"`}},
	}
	for _, test := range pageTests {
		t.Run(test.path, func(t *testing.T) {
			assertPage(t, mux, test.path, http.StatusOK, []string{test.marker}, test.notPresent)
		})
	}
	assertPage(t, mux, "/", http.StatusOK, []string{`id="dashboardSyncAllBtn"`}, nil)

	agent := testServer(&config.Config{BaseURL: "/", Mode: config.ModeAgent, MaxRequestSize: 1 << 20})
	agent.tmpl = tmpl
	agentMux := agent.SetupMux()
	assertPage(t, agentMux, "/config", http.StatusOK, nil, []string{
		`id="configSyncProgress"`,
		`id="configEditBar"`,
	})
	assertPage(t, agentMux, "/", http.StatusOK, nil, []string{`id="dashboardSyncAllBtn"`})
	assertPage(t, agentMux, "/cluster", http.StatusNotFound, nil, nil)
	assertPage(t, mux, "/not-a-route", http.StatusNotFound, nil, nil)
}

func assertPage(
	t *testing.T,
	handler http.Handler,
	path string,
	wantStatus int,
	present []string,
	absent []string,
) {
	t.Helper()
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
	if recorder.Code != wantStatus {
		t.Fatalf("response for %s = %d %q, want status %d", path, recorder.Code, recorder.Body.String(), wantStatus)
	}
	body := recorder.Body.String()
	for _, marker := range present {
		if !strings.Contains(body, marker) {
			t.Fatalf("response for %s is missing %s: %q", path, marker, body)
		}
	}
	for _, marker := range absent {
		if strings.Contains(body, marker) {
			t.Fatalf("response for %s unexpectedly contains %s", path, marker)
		}
	}
}

func TestFrontendAssetsRespectStyleCSP(t *testing.T) {
	for _, path := range []string{
		"../../static/js/index.js",
		"../../static/js/dashboard.js",
		"../../static/js/querylog.js",
		"../../static/js/settings.js",
		"../../static/js/interactions.js",
		"../../static/js/config.js",
		"../../static/js/config_upstreams.js",
		"../../static/js/config_subscriptions.js",
		"../../static/js/config_rules.js",
		"../../static/js/config_clients.js",
		"../../static/js/config_bootstrap.js",
		"../../static/js/shell.js",
		"../../templates/index.html",
		"../../templates/querylog.html",
		"../../templates/cluster.html",
		"../../templates/config.html",
	} {
		content, err := os.ReadFile(path) // #nosec G304 -- paths are fixed test fixtures listed above
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(content, []byte("style=")) || bytes.Contains(content, []byte(".style.")) {
			t.Fatalf("%s contains an inline style that style-src blocks", path)
		}
	}
	for _, path := range []string{
		"../../static/css/style.css",
		"../../static/css/querylog.css",
		"../../static/css/control_plane.css",
		"../../static/css/operations.css",
		"../../static/css/querylog_workbench.css",
		"../../static/css/login.css",
	} {
		content, err := os.ReadFile(path) // #nosec G304 -- paths are fixed test fixtures listed above
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(content, []byte("'Inter'")) || bytes.Contains(content, []byte("'Outfit'")) {
			t.Fatalf("%s references the repository's incomplete webfont bundle", path)
		}
	}
}

func TestFrontendStatusAndVirtualizationMarkers(t *testing.T) {
	cluster, err := os.ReadFile("../../templates/cluster.html") // #nosec G304 -- fixed test fixture
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{
		"storageWALSize", "storageCheckpointAge", "storageQueueDepth",
		"storageQueueCapacity", "storageDroppedEvents", "storageVacuumState",
	} {
		if count := bytes.Count(cluster, []byte(`id="`+id+`"`)); count != 1 {
			t.Fatalf("cluster metric id %s appears %d times, want 1", id, count)
		}
	}

	queryTemplate, err := os.ReadFile("../../templates/querylog.html") // #nosec G304 -- fixed test fixture
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{
		`id="queryResultCount" class="section-chip healthy" role="status" aria-live="polite" aria-atomic="true"`,
		`id="viewClearedBanner" class="view-cleared-banner is-hidden" role="status" aria-live="polite" aria-atomic="true"`,
		`id="queryDetailDrawer" class="query-detail-drawer"`,
		`id="queryUndoToast" class="query-undo-toast"`,
		`aria-hidden="true" inert`,
	} {
		if !bytes.Contains(queryTemplate, []byte(marker)) {
			t.Fatalf("query-log template is missing accessibility marker %q", marker)
		}
	}

	queryScripts := bytes.Buffer{}
	for _, path := range []string{
		"../../static/js/index.js",
		"../../static/js/dashboard.js",
		"../../static/js/querylog.js",
		"../../static/js/settings.js",
		"../../static/js/interactions.js",
	} {
		content, err := os.ReadFile(path) // #nosec G304 -- fixed test fixtures listed above
		if err != nil {
			t.Fatal(err)
		}
		queryScripts.Write(content)
	}
	for _, marker := range []string{`aria-rowindex=`, `headers="query-column-`, `focus({ preventScroll: true })`, `drawer.inert = true`} {
		if !bytes.Contains(queryScripts.Bytes(), []byte(marker)) {
			t.Fatalf("query-log script is missing virtualization marker %q", marker)
		}
	}
}

func TestDashboardQuickWinMarkers(t *testing.T) {
	templateContent, err := os.ReadFile("../../templates/index.html") // #nosec G304 -- fixed test fixture
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{
		`id="appFavicon"`,
		`data-alert-href="static/favicon-alert.svg"`,
		`id="runtimeVersion"`,
		`id="runtimeRole"`,
		`id="clusterNodeCount"`,
		`id="versionSkew"`,
		`id="queriesDelta"`,
		`id="dashboardZoomReset"`,
		`data-outcome-mode="percentage"`,
		`id="filterResumeBtn"`,
		`id="dashboardSyncAllBtn"`,
	} {
		if !bytes.Contains(templateContent, []byte(marker)) {
			t.Fatalf("dashboard template is missing quick-win marker %q", marker)
		}
	}

	scriptContent, err := os.ReadFile("../../static/js/dashboard.js") // #nosec G304 -- fixed test fixture
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{
		"renderDashboardComparison",
		"renderDashboardRuntime",
		"inspectDashboardBucket",
		"startDashboardZoom",
		"resumeDashboardFiltering",
		"dashboardWarningCount",
		"updateDashboardAttention",
		"syncAllDashboardNodes",
	} {
		if !bytes.Contains(scriptContent, []byte(marker)) {
			t.Fatalf("dashboard script is missing quick-win behavior %q", marker)
		}
	}

	alertFavicon, err := os.ReadFile("../../static/favicon-alert.svg") // #nosec G304 -- fixed test fixture
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(alertFavicon, []byte(`<svg`)) || !bytes.Contains(alertFavicon, []byte(`aria-label="System warning"`)) {
		t.Fatal("alert favicon is missing its SVG or warning marker")
	}
}

func TestConfigurationQuickWinMarkers(t *testing.T) {
	templateContent, err := os.ReadFile("../../templates/config.html") // #nosec G304 -- fixed test fixture
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{
		`id="configSyncProgress"`,
		`id="configSyncProgressMeter"`,
		`id="configEditBar"`,
		`id="configRevertBtn"`,
		`id="configSaveBtn"`,
	} {
		if !bytes.Contains(templateContent, []byte(marker)) {
			t.Fatalf("configuration template is missing quick-win marker %q", marker)
		}
	}

	var scripts bytes.Buffer
	for _, path := range []string{
		"../../static/js/config.js",
		"../../static/js/config_upstreams.js",
		"../../static/js/config_clients.js",
		"../../static/js/config_bootstrap.js",
	} {
		content, readErr := os.ReadFile(path) // #nosec G304 -- fixed test fixtures listed above
		if readErr != nil {
			t.Fatal(readErr)
		}
		scripts.Write(content)
	}
	for _, marker := range []string{
		"updateConfigDirtyUI",
		"restoreCleanForm",
		"upstream-protocol-badge",
		"configSyncState",
		"startConfigSyncMonitor",
	} {
		if !bytes.Contains(scripts.Bytes(), []byte(marker)) {
			t.Fatalf("configuration scripts are missing quick-win behavior %q", marker)
		}
	}
}

func TestFrontendAssetsKeepDependencyOrder(t *testing.T) {
	styleAssets := []string{
		"static/css/style.css",
		"static/css/querylog.css",
		"static/css/control_plane.css",
		"static/css/operations.css",
		"static/css/querylog_workbench.css",
	}
	for _, path := range []string{
		"../../templates/index.html",
		"../../templates/querylog.html",
		"../../templates/cluster.html",
		"../../templates/config.html",
	} {
		assertAssetOrder(t, path, styleAssets)
	}

	pageScripts := []string{
		"static/js/index.js",
		"static/js/dashboard.js",
		"static/js/querylog.js",
		"static/js/settings.js",
		"static/js/interactions.js",
	}
	for _, path := range []string{
		"../../templates/index.html",
		"../../templates/querylog.html",
		"../../templates/cluster.html",
	} {
		assertAssetOrder(t, path, pageScripts)
	}
	assertAssetOrder(t, "../../templates/config.html", []string{
		"static/js/config.js",
		"static/js/config_upstreams.js",
		"static/js/config_subscriptions.js",
		"static/js/config_rules.js",
		"static/js/config_clients.js",
		"static/js/config_bootstrap.js",
	})
}

func assertAssetOrder(t *testing.T, path string, assets []string) {
	t.Helper()
	content, err := os.ReadFile(path) // #nosec G304 -- callers pass fixed repository fixtures
	if err != nil {
		t.Fatal(err)
	}
	previous := -1
	for _, asset := range assets {
		index := bytes.Index(content, []byte(asset))
		if index < 0 {
			t.Fatalf("%s does not load %s", path, asset)
		}
		if index <= previous {
			t.Fatalf("%s loads %s out of dependency order", path, asset)
		}
		previous = index
	}
}

func TestAgentRejectsConfigurationMutation(t *testing.T) {
	server := testServer(&config.Config{Mode: config.ModeAgent})
	recorder := httptest.NewRecorder()
	server.handlePostUpstreams(recorder, httptest.NewRequest(http.MethodPost, "/api/upstreams", strings.NewReader("[]")))
	if recorder.Code != http.StatusForbidden || !strings.Contains(recorder.Body.String(), "read-only") {
		t.Fatalf("response = %d %q", recorder.Code, recorder.Body.String())
	}
}

func TestControllerRejectsEmptyUpstreamList(t *testing.T) {
	server := testServer(&config.Config{Mode: config.ModeController, WebUsername: "admin", WebPassword: "password"})
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

func TestFilteringTestEvaluatesTypeRewriteAndClientPolicy(t *testing.T) {
	dir := t.TempDir()
	server := testServer(&config.Config{
		Mode:         config.ModeController,
		AAAADisabled: true,
		RefuseANY:    true,
	})
	engine := filter.New()
	listPath := filepath.Join(dir, "rules.txt")
	if err := os.WriteFile(listPath, []byte("||blocked.example^\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	engine.AddFileSource(listPath, false)
	server.SetFilter(engine)

	registry, err := clients.Load(filepath.Join(dir, "clients.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Replace([]clients.Client{{
		Name: "unfiltered-laptop", IDs: []string{"100.64.0.12"},
		UseGlobalSettings: false, FilteringEnabled: false,
	}}); err != nil {
		t.Fatal(err)
	}
	server.SetClients(registry)

	rewriteStore, err := rewrites.Load(filepath.Join(dir, "rewrites.json"), "")
	if err != nil {
		t.Fatal(err)
	}
	if err := rewriteStore.Replace([]rewrites.Rewrite{{
		Domain: "printer.internal", Type: rewrites.TypeA, Value: "192.0.2.10",
		SourceCIDRs: []string{"100.64.0.0/10"},
	}}); err != nil {
		t.Fatal(err)
	}
	server.SetRewritesStore(rewriteStore)

	tests := []struct {
		name         string
		target       string
		wantStatus   int
		wantDecision string
	}{
		{name: "block rule", target: "/api/filtering/test?domain=blocked.example&type=A", wantStatus: http.StatusOK, wantDecision: "blocked"},
		{name: "client bypass", target: "/api/filtering/test?domain=blocked.example&type=A&client=unfiltered-laptop", wantStatus: http.StatusOK, wantDecision: "filtering_disabled"},
		{name: "source scoped rewrite", target: "/api/filtering/test?domain=printer.internal&type=A&client=100.64.0.12", wantStatus: http.StatusOK, wantDecision: "rewrite"},
		{name: "AAAA policy", target: "/api/filtering/test?domain=example.com&type=AAAA", wantStatus: http.StatusOK, wantDecision: "nodata"},
		{name: "invalid type", target: "/api/filtering/test?domain=example.com&type=AXFR", wantStatus: http.StatusBadRequest},
		{name: "unknown client", target: "/api/filtering/test?domain=example.com&type=A&client=missing", wantStatus: http.StatusBadRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			server.handleFilteringTest(recorder, httptest.NewRequest(http.MethodGet, test.target, nil))
			if recorder.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d; body=%q", recorder.Code, test.wantStatus, recorder.Body.String())
			}
			if test.wantDecision != "" && !strings.Contains(recorder.Body.String(), `"decision":"`+test.wantDecision+`"`) {
				t.Fatalf("body = %q, want decision %q", recorder.Body.String(), test.wantDecision)
			}
		})
	}
}

func TestDNSSettingsAPIValidatesPersistsAndApplies(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{Mode: config.ModeController, HistoryDir: dir, ConfigDir: dir}
	server := testServer(cfg)
	defaults := dnssettings.Settings{
		UpstreamMode: "load_balance", BlockingMode: "nxdomain", BlockCustomIPv4: "0.0.0.0",
		BlockCustomIPv6: "::", RefuseANY: true, PrivatePTR: true,
	}.Normalize()
	store, err := dnssettings.Load(cfg.FullDNSSettingsPath(), defaults)
	if err != nil {
		t.Fatal(err)
	}
	server.SetDNSSettingsStore(store)
	applied := 0
	server.SetDNSSettingsApplyFunc(func(settings dnssettings.Settings) {
		applied++
		if settings.UpstreamMode != "parallel" || !settings.DNSSEC {
			t.Errorf("applied settings = %+v", settings)
		}
	})

	body := `{
		"upstream_mode":"parallel","fallback_dns":["9.9.9.9"],"ecs_client_subnet":"",
		"blocking_mode":"nxdomain","block_custom_ipv4":"0.0.0.0","block_custom_ipv6":"::",
		"blocked_response_ttl":60,"safe_search":["google"],"bogus_nxdomain":[],
		"aaaa_disabled":false,"refuse_any":true,"dnssec":true,"private_ptr":true,
		"allowed_clients":["100.64.0.0/10"],"disallowed_clients":[],
		"rate_limit_qps":80,"internal_rate_limit_qps":1000,"rate_limit_ede":false,
		"cache_size":25000,"cache_min_ttl":60,"cache_max_ttl":600,
		"cache_optimistic":true,"cache_prefetch":true,"cache_prefetch_window_ms":30000,
		"cache_prefetch_hits":3,"cache_servfail_ttl_ms":500
	}`
	request := httptest.NewRequest(http.MethodPut, "/api/config/dns-settings", strings.NewReader(body))
	request.AddCookie(&http.Cookie{
		Name: csrfCookieName, Value: "token", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
	request.Header.Set("X-CSRF-Token", "token")
	recorder := httptest.NewRecorder()
	server.handleDNSSettings(recorder, request)
	if recorder.Code != http.StatusOK || applied != 1 {
		t.Fatalf("response = %d %q, applied=%d", recorder.Code, recorder.Body.String(), applied)
	}
	reloaded, err := dnssettings.Load(cfg.FullDNSSettingsPath(), defaults)
	if err != nil {
		t.Fatal(err)
	}
	if got := reloaded.Get(); got.UpstreamMode != "parallel" || !got.DNSSEC || got.CacheSERVFAILTTLMS != 500 {
		t.Fatalf("persisted settings = %+v", got)
	}

	request = httptest.NewRequest(http.MethodPut, "/api/config/dns-settings", strings.NewReader(`{"upstream_mode":"fastest"}`))
	request.AddCookie(&http.Cookie{
		Name: csrfCookieName, Value: "token", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
	request.Header.Set("X-CSRF-Token", "token")
	recorder = httptest.NewRecorder()
	server.handleDNSSettings(recorder, request)
	if recorder.Code != http.StatusBadRequest || applied != 1 {
		t.Fatalf("invalid response = %d %q, applied=%d", recorder.Code, recorder.Body.String(), applied)
	}
}

func TestValidateSnapshotResolversRequiresBootstrapForHostname(t *testing.T) {
	tests := []struct {
		name             string
		upstreams        []string
		bootstrapServers []string
		wantError        bool
	}{
		{name: "IP upstream", upstreams: []string{"1.1.1.1"}},
		{
			name:      "hostname upstream without bootstrap",
			upstreams: []string{"tls://dns.example:853"},
			wantError: true,
		},
		{
			name:             "hostname upstream with bootstrap",
			upstreams:        []string{"tls://dns.example:853"},
			bootstrapServers: []string{"192.0.2.53"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot, err := configsync.NewSnapshot(
				test.upstreams, test.bootstrapServers, nil, nil, "", nil, nil,
			)
			if err != nil {
				t.Fatal(err)
			}
			err = validateSnapshotResolvers(snapshot)
			if (err != nil) != test.wantError {
				t.Fatalf("validateSnapshotResolvers() error = %v, wantError %v", err, test.wantError)
			}
		})
	}
}

func TestSyncDNSConfigRequiresBearerAndReturnsValidRevision(t *testing.T) {
	dir := t.TempDir()
	server := testServer(&config.Config{
		Mode:         config.ModeController,
		IngestSecret: "cluster-secret",
		HistoryDir:   dir,
		UpstreamDNS:  "1.1.1.1",
		BootstrapDNS: "9.9.9.9",
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
	if !validRevision || len(snapshot.Upstreams) != 1 || len(snapshot.BootstrapServers) != 1 {
		t.Fatalf("snapshot = %+v", snapshot)
	}
}

func TestUpstreamSettingsPersistBootstrapResolvers(t *testing.T) {
	dir := t.TempDir()
	server := testServer(&config.Config{
		Mode:          config.ModeController,
		HistoryDir:    dir,
		UpstreamsFile: "upstreams.json",
	})
	reloads := 0
	server.SetUpstreamReloadFunc(func() { reloads++ })

	request := httptest.NewRequest(http.MethodPost, "/api/upstream-settings", strings.NewReader(`{
		"upstreams":["tls://dns.example:853","https://doh.example/dns-query"],
		"bootstrap_servers":["192.0.2.53"]
	}`))
	request.AddCookie(&http.Cookie{
		Name: csrfCookieName, Value: "token", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
	request.Header.Set("X-CSRF-Token", "token")
	recorder := httptest.NewRecorder()
	server.handleUpstreamSettings(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("save status = %d body=%q", recorder.Code, recorder.Body.String())
	}
	if reloads != 1 {
		t.Fatalf("reloads = %d, want 1", reloads)
	}
	if got := server.configuredBootstrapServers(); len(got) != 1 || got[0] != "192.0.2.53" {
		t.Fatalf("bootstrap resolvers = %v", got)
	}

	request = httptest.NewRequest(http.MethodPost, "/api/upstream-settings", strings.NewReader(`{
		"upstreams":["tls://dns.example:853"],
		"bootstrap_servers":[]
	}`))
	request.AddCookie(&http.Cookie{
		Name: csrfCookieName, Value: "token", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
	request.Header.Set("X-CSRF-Token", "token")
	recorder = httptest.NewRecorder()
	server.handleUpstreamSettings(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("empty bootstrap status = %d body=%q", recorder.Code, recorder.Body.String())
	}
	if got := server.configuredBootstrapServers(); len(got) != 1 || got[0] != "192.0.2.53" {
		t.Fatalf("bootstrap resolvers after rejected request = %v", got)
	}

	request = httptest.NewRequest(http.MethodPost, "/api/upstream-settings", strings.NewReader(`{
		"upstreams":["tls://dns.example:853"],
		"bootstrap_servers":["tls://bootstrap.example:853"]
	}`))
	request.AddCookie(&http.Cookie{
		Name: csrfCookieName, Value: "token", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
	request.Header.Set("X-CSRF-Token", "token")
	recorder = httptest.NewRecorder()
	server.handleUpstreamSettings(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("invalid bootstrap status = %d body=%q", recorder.Code, recorder.Body.String())
	}
}

//nolint:gocyclo // This integration-style test intentionally verifies one complete atomic snapshot workflow.
func TestApplyConfigSnapshotPersistsAllManagedSettings(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{Mode: config.ModeAgent, HistoryDir: dir, UpstreamsFile: "upstreams.json"}
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
	managedDefaults := dnssettings.Settings{
		UpstreamMode: "load_balance", BlockingMode: "nxdomain", BlockCustomIPv4: "0.0.0.0",
		BlockCustomIPv6: "::", RefuseANY: true, PrivatePTR: true,
	}.Normalize()
	dnsSettingsStore, err := dnssettings.Load(filepath.Join(dir, "dns-settings.json"), managedDefaults)
	if err != nil {
		t.Fatal(err)
	}
	server.SetDNSSettingsStore(dnsSettingsStore)
	var appliedSettings dnssettings.Settings
	server.SetDNSSettingsApplyFunc(func(settings dnssettings.Settings) { appliedSettings = settings })
	managed := managedDefaults
	managed.UpstreamMode = "parallel"
	managed.DNSSEC = true
	managed.AllowedClients = []string{"100.64.0.0/10"}

	snapshot, err := configsync.NewSnapshotWithDNSSettings(
		[]string{"1.1.1.1"}, []string{"8.8.8.8"}, map[string]string{"internal": "9.9.9.9"},
		[]filter.Subscription{{
			ID: "trusted-domains", Name: "Trusted domains", URL: "https://allow.example/list.txt", AllowOnly: true, Enabled: true,
		}},
		"||blocked.example^\n",
		[]rewrites.Rewrite{{
			ID:          "rewrite-1",
			Domain:      "printer.internal",
			Type:        "A",
			Value:       "192.0.2.10",
			SourceCIDRs: []string{"100.64.0.0/10"},
		}},
		[]clients.Client{{Name: "office", IDs: []string{"192.0.2.0/24"}, UseGlobalSettings: true}},
		&managed,
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
	if got := server.configuredBootstrapServers(); len(got) != 1 || got[0] != "8.8.8.8" {
		t.Fatalf("bootstrap resolvers = %v", got)
	}
	rewriteItems := rewriteStore.List()
	if len(rewriteItems) != 1 || len(clientRegistry.List()) != 1 {
		t.Fatalf("rewrites/clients = %d/%d", len(rewriteStore.List()), len(clientRegistry.List()))
	}
	if len(rewriteItems[0].SourceCIDRs) != 1 || rewriteItems[0].SourceCIDRs[0] != "100.64.0.0/10" {
		t.Fatalf("rewrite source CIDRs = %v", rewriteItems[0].SourceCIDRs)
	}
	if got := dnsRoutes.GetRoutesMap(); got["internal"] != "9.9.9.9" {
		t.Fatalf("DNS routes = %v", got)
	}
	if got := subscriptions.List(); len(got) != 1 || !got[0].AllowOnly || got[0].ID != "trusted-domains" {
		t.Fatalf("subscriptions = %+v", got)
	}
	if got := dnsSettingsStore.Get(); got.UpstreamMode != "parallel" || !got.DNSSEC ||
		len(got.AllowedClients) != 1 || appliedSettings.UpstreamMode != "parallel" {
		t.Fatalf("DNS settings not persisted/applied: stored=%+v applied=%+v", got, appliedSettings)
	}
	if result := engine.Match("blocked.example"); !result.Blocked {
		t.Fatalf("synced user rule did not block: %+v", result)
	}

	candidate := snapshot.Clone()
	candidate.Revision = ""
	candidate.Routes = map[string]string{"preview.internal": "8.8.4.4"}
	body, err := json.Marshal(candidate)
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	server.handleConfigDiff(recorder, httptest.NewRequest(http.MethodPost, "/api/config/diff", strings.NewReader(string(body))))
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"field":"routes"`) {
		t.Fatalf("diff preview = %d %q", recorder.Code, recorder.Body.String())
	}
	if got := dnsRoutes.GetRoutesMap(); got["internal"] != "9.9.9.9" || got["preview.internal"] != "" {
		t.Fatalf("diff preview mutated routes: %v", got)
	}

	before, err := server.currentConfigSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	previousBefore, err := os.ReadFile(server.previousConfigSnapshotPath())
	if err != nil {
		t.Fatal(err)
	}
	invalid, err := configsync.NewSnapshot(
		before.Upstreams, before.BootstrapServers, before.Routes, before.Subscriptions,
		"*unsupported-wildcard*\n", before.Rewrites, before.Clients,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.ApplyConfigSnapshot(invalid); err == nil || !strings.Contains(err.Error(), "user rule line 1") {
		t.Fatalf("invalid user-rule apply error = %v", err)
	}
	after, err := server.currentConfigSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if after.Revision != before.Revision {
		t.Fatalf("revision changed after rejected rules: before=%q after=%q", before.Revision, after.Revision)
	}
	previousAfter, err := os.ReadFile(server.previousConfigSnapshotPath())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(previousAfter, previousBefore) {
		t.Fatal("previous snapshot changed after rejected rules")
	}
}

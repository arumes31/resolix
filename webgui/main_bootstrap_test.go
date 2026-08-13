package main

import (
	"context"
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/arumes31/resolix/webgui/internal/config"
	"github.com/arumes31/resolix/webgui/internal/rewrites"
)

func TestGenerateNonce(t *testing.T) {
	nonce, err := generateNonce()
	if err != nil {
		t.Fatalf("generateNonce() error = %v", err)
	}
	decoded, err := base64.StdEncoding.DecodeString(nonce)
	if err != nil {
		t.Fatalf("decode nonce: %v", err)
	}
	if len(decoded) != 16 {
		t.Fatalf("decoded nonce length = %d, want 16", len(decoded))
	}

	second, err := generateNonce()
	if err != nil {
		t.Fatalf("second generateNonce() error = %v", err)
	}
	if nonce == second {
		t.Fatal("two generated nonces unexpectedly matched")
	}
}

func TestCSPMiddleware(t *testing.T) {
	var observedNonce string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observedNonce = nonceFromContext(r.Context())
		w.WriteHeader(http.StatusNoContent)
	})
	recorder := httptest.NewRecorder()
	cspMiddleware(next).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))

	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusNoContent)
	}
	if observedNonce == "" {
		t.Fatal("middleware did not inject a CSP nonce")
	}
	csp := recorder.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "script-src 'nonce-"+observedNonce+"'") ||
		!strings.Contains(csp, "style-src 'self' 'nonce-"+observedNonce+"'") ||
		!strings.Contains(csp, "frame-ancestors 'none'") {
		t.Fatalf("CSP does not contain the required directives: %q", csp)
	}
	wantHeaders := map[string]string{
		"X-Content-Type-Options":       "nosniff",
		"X-Frame-Options":              "DENY",
		"Referrer-Policy":              "same-origin",
		"X-XSS-Protection":             "0",
		"Permissions-Policy":           "camera=(), microphone=(), geolocation=()",
		"Cross-Origin-Opener-Policy":   "same-origin",
		"Cross-Origin-Resource-Policy": "same-origin",
	}
	for name, want := range wantHeaders {
		if got := recorder.Header().Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
}

func TestNonceFromContextMissingOrWrongType(t *testing.T) {
	tests := []struct {
		name string
		ctx  context.Context
	}{
		{name: "missing", ctx: context.Background()},
		{name: "wrong type", ctx: context.WithValue(context.Background(), nonceKey{}, 42)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := nonceFromContext(tt.ctx); got != "" {
				t.Fatalf("nonceFromContext() = %q, want empty", got)
			}
		})
	}
}

func TestMigrateTLSState(t *testing.T) {
	root := t.TempDir()
	historyDir := filepath.Join(root, "history")
	legacyDir := filepath.Join(historyDir, "tls")
	stateDir := filepath.Join(root, "tls-state")
	if err := os.MkdirAll(legacyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	const pinName = "custom-pin.json"
	if err := os.WriteFile(filepath.Join(legacyDir, pinName), []byte("legacy pin"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		HistoryDir:           historyDir,
		TLSStateDir:          stateDir,
		ControllerTLSPinFile: pinName,
	}

	migrateTLSState(cfg)
	if _, err := os.Stat(filepath.Join(stateDir, pinName)); !os.IsNotExist(err) {
		t.Fatalf("disabled TLS migration created a destination: %v", err)
	}

	cfg.WebTLSMode = "auto"
	migrateTLSState(cfg)
	data, err := os.ReadFile(filepath.Join(stateDir, pinName)) // #nosec G304 -- fixed test path under t.TempDir.
	if err != nil {
		t.Fatalf("read migrated pin: %v", err)
	}
	if string(data) != "legacy pin" {
		t.Fatalf("migrated pin = %q, want %q", data, "legacy pin")
	}
}

func TestMigrateConfigState(t *testing.T) {
	root := t.TempDir()
	historyDir := filepath.Join(root, "history")
	configDir := filepath.Join(root, "config")
	if err := os.MkdirAll(historyDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(historyDir, "user_rules.txt"), []byte("||ads.example^\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	migrateConfigState(&config.Config{HistoryDir: historyDir, ConfigDir: configDir})
	data, err := os.ReadFile(filepath.Join(configDir, "user_rules.txt")) // #nosec G304 -- fixed test path under t.TempDir.
	if err != nil {
		t.Fatalf("read migrated user rules: %v", err)
	}
	if string(data) != "||ads.example^\n" {
		t.Fatalf("migrated rules = %q", data)
	}
}

func TestGenerateEnvFile(t *testing.T) {
	t.Run("copies example", func(t *testing.T) {
		t.Chdir(t.TempDir())
		if err := os.WriteFile(".env.example", []byte("MODE=controller\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		generateEnvFile()
		data, err := os.ReadFile(".env")
		if err != nil {
			t.Fatal(err)
		}
		if string(data) != "MODE=controller\n" {
			t.Fatalf("generated .env = %q", data)
		}
	})

	t.Run("uses defaults", func(t *testing.T) {
		t.Chdir(t.TempDir())
		generateEnvFile()
		data, err := os.ReadFile(".env")
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(data), "MODE=controller") ||
			!strings.Contains(string(data), "DNS_LISTEN_PORT=53") {
			t.Fatalf("generated defaults are incomplete: %q", data)
		}
	})

	t.Run("preserves existing file", func(t *testing.T) {
		t.Chdir(t.TempDir())
		if err := os.WriteFile(".env", []byte("KEEP=true\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		generateEnvFile()
		data, err := os.ReadFile(".env")
		if err != nil {
			t.Fatal(err)
		}
		if string(data) != "KEEP=true\n" {
			t.Fatalf("existing .env was replaced: %q", data)
		}
	})
}

func TestTemplateAndStaticBootstrap(t *testing.T) {
	tmpl := parseTemplates()
	for _, name := range []string{"index.html", "config.html"} {
		if tmpl.Lookup(name) == nil {
			t.Errorf("embedded template %q was not parsed", name)
		}
	}

	recorder := httptest.NewRecorder()
	newStaticHandler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/css/style.css", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("static CSS status = %d, want %d", recorder.Code, http.StatusOK)
	}
	if !strings.Contains(recorder.Body.String(), ":root") {
		t.Fatal("embedded stylesheet response does not contain its root variables")
	}
}

func TestDashboardAssetsExposeLocalResponsesAndRewriteOutcome(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		required []string
	}{
		{
			name: "template",
			path: "templates/index.html",
			required: []string{
				`id="localResponseRatio"`,
				`id="rewriteHitCount"`,
				`class="legend-swatch rewritten"`,
				`>Forwarded<`,
			},
		},
		{
			name: "javascript",
			path: "static/js/dashboard.js",
			required: []string{
				"summary.local_response_ratio",
				"summary.rewrite_hits",
				"point.rewritten",
				"segment('rewritten'",
			},
		},
		{
			name:     "stylesheet",
			path:     "static/css/operations.css",
			required: []string{".legend-swatch.rewritten", ".outcome-segment.rewritten"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data, err := embedFS.ReadFile(test.path)
			if err != nil {
				t.Fatal(err)
			}
			content := string(data)
			for _, required := range test.required {
				if !strings.Contains(content, required) {
					t.Errorf("%s is missing %q", test.path, required)
				}
			}
		})
	}
}

func TestDashboardAssetsExposeResponsiveLoadingState(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		required []string
	}{
		{
			name: "template",
			path: "templates/index.html",
			required: []string{
				`id="dashboardContent"`,
				`id="dashboardLoadingStatus"`,
				`id="dashboardRetry"`,
				`href="static/css/dashboard_loading.css"`,
				`src="static/js/dashboard_loader.js"`,
				`dashboard-skeleton`,
			},
		},
		{
			name: "javascript",
			path: "static/js/dashboard.js",
			required: []string{
				"ResolixDashboardLoader.create",
				"ResolixDashboardLoader.createView",
				"dashboardRetry",
			},
		},
		{
			name: "loader",
			path: "static/js/dashboard_loader.js",
			required: []string{
				"AbortController",
				"generation",
				"cache = new Map",
			},
		},
		{
			name: "stylesheet",
			path: "static/css/dashboard_loading.css",
			required: []string{
				".dashboard-loading-status",
				".dashboard-skeleton.skeleton-card",
				".is-dashboard-loading",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data, err := embedFS.ReadFile(test.path)
			if err != nil {
				t.Fatal(err)
			}
			content := string(data)
			for _, required := range test.required {
				if !strings.Contains(content, required) {
					t.Errorf("%s is missing %q", test.path, required)
				}
			}
		})
	}
}

func TestSetupFilterEngineLoadsLocalRules(t *testing.T) {
	cfg, store, _, srv := setupTest()
	t.Cleanup(func() {
		store.Close()
		_ = os.RemoveAll(cfg.HistoryDir)
	})
	blockPath := filepath.Join(cfg.ConfigDir, "block.txt")
	allowPath := filepath.Join(cfg.ConfigDir, "allow.txt")
	if err := os.WriteFile(blockPath, []byte("||ads.example^\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(allowPath, []byte("ads.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.BlocklistFile = blockPath
	cfg.AllowlistFile = allowPath
	cfg.FilterUpdateInterval = time.Hour
	ctx, cancel := context.WithCancel(context.Background())
	eng, subscriptions := setupFilterEngine(ctx, cfg, srv)
	cancel()

	if subscriptions == nil {
		t.Fatal("setupFilterEngine() returned a nil subscription store")
	}
	if _, err := os.Stat(cfg.FullUserRulesPath()); err != nil {
		t.Fatalf("managed user rules were not created: %v", err)
	}
	if result := eng.Match("ads.example"); result.Blocked || !result.Allowed {
		t.Fatalf("allowlist did not override blocklist: %+v", result)
	}
}

func TestSetupClientsRegistryFallsBackFromInvalidFile(t *testing.T) {
	cfg, store, _, srv := setupTest()
	t.Cleanup(func() {
		store.Close()
		_ = os.RemoveAll(cfg.HistoryDir)
	})
	cfg.ClientsFile = "clients.json"
	if err := os.WriteFile(cfg.FullClientsPath(), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	reg := setupClientsRegistry(ctx, cfg, srv)
	cancel()
	if reg == nil || len(reg.List()) != 0 {
		t.Fatalf("fallback registry = %#v, want an empty non-nil registry", reg)
	}
}

func TestLoadRewritesStoreSeedsAndFallsBack(t *testing.T) {
	root := t.TempDir()
	cfg := &config.Config{
		HistoryDir:   root,
		ConfigDir:    root,
		RewritesFile: "rewrites.json",
		Domains:      "app.example:192.0.2.10",
	}
	if err := os.WriteFile(cfg.FullRewritesPath(), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	store := loadRewritesStore(cfg)
	items := store.Lookup("app.example")
	if len(items) != 1 || items[0].Type != rewrites.TypeA || items[0].Value != "192.0.2.10" {
		t.Fatalf("fallback seeded rewrites = %+v", items)
	}
}

func TestDefaultDNSSettings(t *testing.T) {
	cfg := &config.Config{
		UpstreamMode:         "parallel",
		FallbackDNS:          "1.1.1.1, 9.9.9.9",
		SafeSearch:           "google bing",
		BogusNXDOMAIN:        "192.0.2.0/24",
		BlockingMode:         "nxdomain",
		RefuseANY:            true,
		DNSSEC:               true,
		PrivatePTR:           true,
		DNSAllowedClients:    "100.64.0.0/10 192.168.0.0/16",
		DNSDisallowedClients: "203.0.113.10",
		RateLimitQPS:         20,
		InternalRateLimitQPS: 100,
		CacheMinTTL:          60,
		CacheMaxTTL:          600,
		CachePrefetchWindow:  2 * time.Second,
		CachePrefetchHits:    3,
		CacheSERVFAILTTL:     500 * time.Millisecond,
	}
	got := defaultDNSSettings(cfg)
	if got.UpstreamMode != "parallel" || got.BlockingMode != "nxdomain" {
		t.Fatalf("defaultDNSSettings() modes = %q/%q", got.UpstreamMode, got.BlockingMode)
	}
	if len(got.FallbackDNS) != 2 || len(got.AllowedClients) != 2 || len(got.DisallowedClients) != 1 {
		t.Fatalf("defaultDNSSettings() lists = %+v", got)
	}
	if got.CachePrefetchWindowMS != 2000 || got.CacheSERVFAILTTLMS != 500 {
		t.Fatalf("defaultDNSSettings() cache durations = %d/%d", got.CachePrefetchWindowMS, got.CacheSERVFAILTTLMS)
	}
}

func TestSplitListEnv(t *testing.T) {
	got := splitListEnv("alpha, beta\tgamma\ndelta\r epsilon")
	want := []string{"alpha", "beta", "gamma", "delta", "epsilon"}
	if !equalStringSlices(got, want) {
		t.Fatalf("splitListEnv() = %v, want %v", got, want)
	}
}

func TestEqualStringSlices(t *testing.T) {
	tests := []struct {
		name string
		a    []string
		b    []string
		want bool
	}{
		{name: "both nil", want: true},
		{name: "equal", a: []string{"a", "b"}, b: []string{"a", "b"}, want: true},
		{name: "different length", a: []string{"a"}, b: []string{"a", "b"}},
		{name: "different value", a: []string{"a", "b"}, b: []string{"a", "c"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := equalStringSlices(tt.a, tt.b); got != tt.want {
				t.Fatalf("equalStringSlices(%v, %v) = %t, want %t", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestWaitForHTTPServer(t *testing.T) {
	cfg := &config.Config{HTTPShutdownTimeout: 10 * time.Millisecond}
	tests := []struct {
		name string
		err  error
		send bool
	}{
		{name: "clean completion", send: true},
		{name: "expected closure", err: http.ErrServerClosed, send: true},
		{name: "unexpected error", err: syscall.ECONNRESET, send: true},
		{name: "timeout"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(_ *testing.T) {
			done := make(chan error, 1)
			if tt.send {
				done <- tt.err
			}
			waitForHTTPServer(cfg, done)
		})
	}
}

func TestRunApplicationStartsAndStopsOnInjectedSignal(t *testing.T) {
	t.Setenv("MODE", config.ModeController)
	t.Setenv("CONTROLLER_URL", "")
	t.Setenv("INGEST_SECRET", "coverage-test-secret")
	t.Setenv("WEB_USERNAME", "")
	t.Setenv("WEB_PASSWORD", "")
	t.Setenv("WEB_TLS_MODE", "off")
	t.Setenv("CONTROLLER_TLS_TRUST", "system")
	t.Setenv("DOT_ENABLED", "false")
	t.Setenv("DOH_ENABLED", "false")
	t.Setenv("BLOCKLIST_URLS", "")
	t.Setenv("ALLOWLIST_URLS", "")

	root := t.TempDir()
	cfg := config.LoadConfig()
	cfg.Mode = config.ModeController
	cfg.ControllerURL = ""
	cfg.NodeName = "coverage-node"
	cfg.Port = strconv.Itoa(availableTCPPort(t))
	cfg.WebListenAddr = "127.0.0.1"
	cfg.HistoryDir = filepath.Join(root, "history")
	cfg.ConfigDir = filepath.Join(root, "config")
	cfg.TLSStateDir = filepath.Join(root, "tls")
	cfg.DBPath = "queries.db"
	cfg.IngestSecret = "coverage-test-secret"
	cfg.WebUsername = ""
	cfg.WebPassword = ""
	cfg.WebTLSMode = "off"
	cfg.ControllerTLSTrust = "system"
	cfg.LogLevel = "ERROR"
	cfg.LogFile = ""
	cfg.BaseURL = "/coverage"
	cfg.BlocklistFile = ""
	cfg.AllowlistFile = ""
	cfg.BlocklistURLs = ""
	cfg.AllowlistURLs = ""
	cfg.UpstreamsFile = ""
	cfg.DNSRoutesFile = ""
	cfg.RewritesFile = ""
	cfg.ClientsFile = ""
	cfg.UpstreamDNS = "127.0.0.1:9"
	cfg.BootstrapDNS = ""
	cfg.DNSListenAddr = "127.0.0.1"
	cfg.DNSListenPort = availableDualProtocolPort(t)
	cfg.DoHEnabled = false
	cfg.DoTEnabled = false
	cfg.FilterUpdateInterval = time.Hour
	cfg.CleanupPendingInterval = time.Hour
	cfg.BatchArchiveInterval = time.Hour
	cfg.HTTPShutdownTimeout = 2 * time.Second

	if errs, _ := cfg.VerifyConfig(); len(errs) != 0 {
		t.Fatalf("bootstrap test config is invalid: %v", errs)
	}
	sigChan := make(chan os.Signal, 1)
	sigChan <- syscall.SIGTERM
	started := time.Now()
	runApplication(cfg, sigChan)
	if elapsed := time.Since(started); elapsed > 10*time.Second {
		t.Fatalf("runApplication() took %s", elapsed)
	}
	if _, err := os.Stat(cfg.FullDBPath()); err != nil {
		t.Fatalf("application did not initialize storage: %v", err)
	}
	if _, err := os.Stat(cfg.FullUserRulesPath()); err != nil {
		t.Fatalf("application did not initialize managed user rules: %v", err)
	}
}

func availableTCPPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	return listener.Addr().(*net.TCPAddr).Port
}

func availableDualProtocolPort(t *testing.T) int {
	t.Helper()
	for range 10 {
		tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := tcpListener.Addr().(*net.TCPAddr).Port
		udpConn, udpErr := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port})
		_ = tcpListener.Close()
		if udpErr != nil {
			continue
		}
		_ = udpConn.Close()
		return port
	}
	t.Fatal("find port available for both TCP and UDP")
	return 0
}

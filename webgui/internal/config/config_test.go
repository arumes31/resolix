package config

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestDefaultFilterUpdateIntervalIsDaily(t *testing.T) {
	if DefaultFilterUpdateInterval != 24*time.Hour {
		t.Fatalf("DefaultFilterUpdateInterval = %s, want 24h", DefaultFilterUpdateInterval)
	}
}

func TestResolveModeCanonicalizesLegacyNames(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{name: "default", want: ModeController},
		{name: "controller", value: ModeController, want: ModeController},
		{name: "agent", value: ModeAgent, want: ModeAgent},
		{name: "legacy master", value: "master", want: ModeController},
		{name: "legacy slave", value: "slave", want: ModeAgent},
		{name: "invalid", value: "invalid", want: ModeController},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("MODE", tt.value)
			if got := resolveMode(); got != tt.want {
				t.Fatalf("resolveMode() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestResolveControllerURLPrefersCanonicalEnvironment(t *testing.T) {
	t.Setenv("CONTROLLER_URL", "https://controller.example.test/")
	t.Setenv("MASTER_URL", "https://legacy.example.test")
	if got := resolveControllerURL(); got != "https://controller.example.test" {
		t.Fatalf("resolveControllerURL() = %q", got)
	}

	t.Setenv("CONTROLLER_URL", "")
	if got := resolveControllerURL(); got != "https://legacy.example.test" {
		t.Fatalf("legacy resolveControllerURL() = %q", got)
	}
}

func TestParseDurationEnvRequiresPositiveDuration(t *testing.T) {
	const key = "TEST_DURATION"
	fallback := 5 * time.Second
	for _, value := range []string{"0s", "-1s", "not-a-duration"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv(key, value)
			if got := parseDurationEnv(key, fallback); got != fallback {
				t.Fatalf("parseDurationEnv(%q) = %s; want %s", value, got, fallback)
			}
		})
	}
	t.Setenv(key, "2s")
	if got := parseDurationEnv(key, fallback); got != 2*time.Second {
		t.Fatalf("parseDurationEnv(valid) = %s", got)
	}
}

func TestParseUint32EnvEnforcesBitSize(t *testing.T) {
	const key = "TEST_UINT32"
	for _, value := range []string{"-1", "4294967296", "not-a-number"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv(key, value)
			if got := parseUint32Env(key, 600); got != 600 {
				t.Fatalf("parseUint32Env(%q) = %d, want 600", value, got)
			}
		})
	}
	t.Setenv(key, "4294967295")
	if got := parseUint32Env(key, 600); got != ^uint32(0) {
		t.Fatalf("parseUint32Env(max) = %d, want %d", got, ^uint32(0))
	}
}

func TestLoadConfigOperationalLimits(t *testing.T) {
	t.Setenv("MODE", ModeController)
	t.Setenv("CONTROLLER_URL", "")
	t.Setenv("MASTER_URL", "")
	t.Setenv("RATE_LIMIT_QPS", "")
	t.Setenv("RATE_LIMIT_INTERNAL_QPS", "")
	t.Setenv("RATE_LIMIT_EDE", "")
	t.Setenv("MAX_REQUEST_SIZE", "")
	cfg := LoadConfig()
	if cfg.RateLimitQPS != 80 || cfg.InternalRateLimitQPS != 1000 {
		t.Fatalf("default rate limits = %d/%d, want 80/1000", cfg.RateLimitQPS, cfg.InternalRateLimitQPS)
	}
	if cfg.RateLimitEDE {
		t.Fatal("RATE_LIMIT_EDE enabled by default")
	}
	if cfg.MaxRequestSize != 1<<20 {
		t.Fatalf("default MAX_REQUEST_SIZE = %d, want %d", cfg.MaxRequestSize, 1<<20)
	}

	t.Setenv("RATE_LIMIT_QPS", "250")
	t.Setenv("RATE_LIMIT_INTERNAL_QPS", "500")
	t.Setenv("RATE_LIMIT_EDE", "true")
	cfg = LoadConfig()
	if cfg.RateLimitQPS != 250 || cfg.InternalRateLimitQPS != 500 {
		t.Fatalf("configured rate limits = %d/%d, want 250/500", cfg.RateLimitQPS, cfg.InternalRateLimitQPS)
	}
	if !cfg.RateLimitEDE {
		t.Fatal("RATE_LIMIT_EDE was not loaded")
	}
}

func TestLoadConfigClampsSERVFAILCacheTTL(t *testing.T) {
	t.Setenv("CACHE_SERVFAIL_TTL", "5s")
	if got := LoadConfig().CacheSERVFAILTTL; got != time.Second {
		t.Fatalf("CACHE_SERVFAIL_TTL above bound = %s, want 1s", got)
	}

	t.Setenv("CACHE_SERVFAIL_TTL", "-1s")
	if got := LoadConfig().CacheSERVFAILTTL; got != 0 {
		t.Fatalf("negative CACHE_SERVFAIL_TTL = %s, want disabled", got)
	}
}

func TestLoadConfigDefaultsDNSRoutesToConfigDir(t *testing.T) {
	configDir := t.TempDir()
	t.Setenv("CONFIG_DIR", configDir)
	t.Setenv("DNS_ROUTES_FILE", "")

	cfg := LoadConfig()
	want := filepath.Join(configDir, "dns-routes.json")
	if got := cfg.FullDNSRoutesPath(); got != want {
		t.Fatalf("FullDNSRoutesPath() = %q, want persistent default %q", got, want)
	}
}

func TestClientAliasesAreCopied(t *testing.T) {
	cfg := &Config{}
	aliases := map[string]string{"192.0.2.1": "router"}
	cfg.SetClientAliases(aliases)
	aliases["192.0.2.1"] = "mutated"
	if got := cfg.GetClientAlias("192.0.2.1"); got != "router" {
		t.Fatalf("alias = %q; want router", got)
	}
	snapshot := cfg.GetAllClientAliases()
	snapshot["192.0.2.1"] = "snapshot-mutated"
	if got := cfg.GetClientAlias("192.0.2.1"); got != "router" {
		t.Fatalf("alias after snapshot mutation = %q; want router", got)
	}
}

func TestLoadConfigMagicDNS(t *testing.T) {
	t.Setenv("MODE", ModeController)
	t.Setenv("CONTROLLER_URL", "")
	t.Setenv("MAGICDNS_ENABLED", "true")
	t.Setenv("MAGICDNS_TAILNET", "tailnet-id")
	t.Setenv("MAGICDNS_CLIENT_ID", "client-id")
	t.Setenv("MAGICDNS_CLIENT_SECRET", "client-secret")
	t.Setenv("MAGICDNS_SYNC_INTERVAL", "6h")
	t.Setenv("MAGICDNS_TTL", "120")
	t.Setenv("MAGICDNS_STATE_FILE", "tailscale-records.json")
	t.Setenv("CONFIG_DIR", t.TempDir())

	cfg := LoadConfig()
	if !cfg.MagicDNSEnabled || cfg.MagicDNSTailnet != "tailnet-id" ||
		cfg.MagicDNSClientID != "client-id" || cfg.MagicDNSClientSecret != "client-secret" ||
		cfg.MagicDNSSyncInterval != 6*time.Hour || cfg.MagicDNSTTL != 120 {
		t.Fatalf(
			"MagicDNS config: enabled=%t tailnet=%q client_id=%q client_secret_matches=%t sync_interval=%s ttl=%d",
			cfg.MagicDNSEnabled,
			cfg.MagicDNSTailnet,
			cfg.MagicDNSClientID,
			cfg.MagicDNSClientSecret == "client-secret",
			cfg.MagicDNSSyncInterval,
			cfg.MagicDNSTTL,
		)
	}
	if filepath.Base(cfg.FullMagicDNSStatePath()) != "tailscale-records.json" {
		t.Fatalf("MagicDNS state path = %q", cfg.FullMagicDNSStatePath())
	}
}

func TestClientAliasesProviderLoadsAndOverridesEnvironment(t *testing.T) {
	path := filepath.Join(t.TempDir(), "aliases.txt")
	contents := "# comment\n192.0.2.1 = file-router\ninvalid\n=empty\n192.0.2.2= workstation \n"
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	provider := newClientAliasesProvider(path)
	if got := provider.GetAlias("192.0.2.1"); got != "file-router" {
		t.Fatalf("provider alias = %q", got)
	}
	aliases := provider.GetAllAliases()
	aliases["192.0.2.1"] = "mutated"
	if provider.GetAlias("192.0.2.1") != "file-router" {
		t.Fatal("GetAllAliases returned mutable provider storage")
	}

	cfg := &Config{
		aliasesProvider: provider,
		clientAliases:   map[string]string{"192.0.2.1": "environment", "192.0.2.3": "env-only"},
	}
	if got := cfg.GetClientAlias("192.0.2.1"); got != "file-router" {
		t.Fatalf("file alias did not override environment: %q", got)
	}
	if got := cfg.GetClientAlias("192.0.2.3"); got != "env-only" {
		t.Fatalf("environment fallback = %q", got)
	}
	merged := cfg.GetAllClientAliases()
	if merged["192.0.2.1"] != "file-router" || merged["192.0.2.3"] != "env-only" {
		t.Fatalf("merged aliases = %#v", merged)
	}

	if err := os.WriteFile(path, []byte("192.0.2.4=reloaded\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	provider.load()
	if provider.GetAlias("192.0.2.4") != "reloaded" || provider.GetAlias("192.0.2.1") != "" {
		t.Fatalf("reloaded aliases = %#v", provider.GetAllAliases())
	}

	ctx, cancel := context.WithCancel(t.Context())
	cfg.StartClientAliasesReload(ctx)
	cancel()
}

func TestClientAliasesProviderMissingFileAndNilConfiguration(t *testing.T) {
	provider := newClientAliasesProvider(filepath.Join(t.TempDir(), "missing.txt"))
	if got := provider.GetAllAliases(); len(got) != 0 {
		t.Fatalf("missing file aliases = %#v", got)
	}
	cfg := &Config{}
	cfg.SetClientAliases(nil)
	cfg.StartClientAliasesReload(t.Context())
	if cfg.GetClientAlias("192.0.2.1") != "" || len(cfg.GetAllClientAliases()) != 0 {
		t.Fatal("empty config unexpectedly returned aliases")
	}
}

func TestEnvironmentParsingHelpers(t *testing.T) {
	t.Setenv("CLIENT_ALIASES", "192.0.2.1:router, bad, :empty,192.0.2.2: workstation ")
	aliases := loadEnvAliases()
	if aliases["192.0.2.1"] != "router" || aliases["192.0.2.2"] != "workstation" || len(aliases) != 2 {
		t.Fatalf("loadEnvAliases() = %#v", aliases)
	}
	t.Setenv("TRUSTED_PROXIES", " 192.0.2.1, , 2001:db8::/32 ")
	if got := parseTrustedProxies(); !slices.Equal(got, []string{"192.0.2.1", "2001:db8::/32"}) {
		t.Fatalf("parseTrustedProxies() = %#v", got)
	}

	t.Setenv("TEST_INT64", "")
	if got := parseInt64Env("TEST_INT64", 7); got != 7 {
		t.Fatalf("empty parseInt64Env() = %d", got)
	}
	for _, value := range []string{"-1", "invalid"} {
		t.Setenv("TEST_INT64", value)
		if got := parseInt64Env("TEST_INT64", 7); got != 7 {
			t.Fatalf("parseInt64Env(%q) = %d", value, got)
		}
	}
	t.Setenv("TEST_INT64", "42")
	if got := parseInt64Env("TEST_INT64", 7); got != 42 {
		t.Fatalf("valid parseInt64Env() = %d", got)
	}

	t.Setenv("TEST_INT", "")
	if got := parseIntEnv("TEST_INT", 8); got != 8 {
		t.Fatalf("empty parseIntEnv() = %d", got)
	}
	t.Setenv("TEST_INT", "-1")
	if got := parseIntEnv("TEST_INT", 8); got != 8 {
		t.Fatalf("negative parseIntEnv() = %d", got)
	}

	for _, test := range []struct {
		value string
		want  string
	}{{value: "", want: DefaultPort}, {value: "0", want: DefaultPort}, {value: "65536", want: DefaultPort}, {value: "invalid", want: DefaultPort}, {value: "8080", want: "8080"}} {
		t.Setenv("PORT", test.value)
		if got := resolvePort(); got != test.want {
			t.Fatalf("resolvePort(%q) = %q, want %q", test.value, got, test.want)
		}
	}
	t.Setenv("NODE_NAME", "configured-node")
	if got := resolveNodeName(); got != "configured-node" {
		t.Fatalf("resolveNodeName() = %q", got)
	}
	for _, test := range []struct {
		value string
		want  int
	}{{value: "", want: DefaultUpstreamLatencyThreshold}, {value: "0", want: DefaultUpstreamLatencyThreshold}, {value: "bad", want: DefaultUpstreamLatencyThreshold}, {value: "250", want: 250}} {
		t.Setenv("UPSTREAM_LATENCY_THRESHOLD", test.value)
		if got := resolveLatencyThreshold(); got != test.want {
			t.Fatalf("resolveLatencyThreshold(%q) = %d, want %d", test.value, got, test.want)
		}
	}
}

func TestResolveDoHPath(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{name: "default", want: DefaultDoHPath},
		{name: "leading slash", value: "custom-dns", want: "/custom-dns"},
		{name: "clean", value: "/dns//query/", want: "/dns/query"},
		{name: "reserved API", value: "/api/events", want: DefaultDoHPath},
		{name: "mux wildcard", value: "/{path}", want: DefaultDoHPath},
		{name: "protocol relative", value: "//example.test", want: DefaultDoHPath},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("DOH_PATH", tt.value)
			if got := resolveDoHPath(); got != tt.want {
				t.Fatalf("resolveDoHPath() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNormalizeBaseURL(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{name: "default", want: DefaultBaseURL},
		{name: "leading slash", value: "dns", want: "/dns"},
		{name: "clean path", value: "/dns//admin/", want: "/dns/admin"},
		{name: "protocol relative", value: "//evil.example", want: DefaultBaseURL},
		{name: "absolute URL", value: "https://evil.example", want: DefaultBaseURL},
		{name: "query", value: "/dns?next=//evil.example", want: DefaultBaseURL},
		{name: "fragment", value: "/dns#fragment", want: DefaultBaseURL},
		{name: "backslash", value: `\evil.example`, want: DefaultBaseURL},
		{name: "slash backslash", value: `/\evil.example`, want: DefaultBaseURL},
		{name: "escaped protocol relative", value: "/%2f%2fevil.example", want: DefaultBaseURL},
		{name: "escaped backslash", value: "/%5cevil.example", want: DefaultBaseURL},
		{name: "escaped query", value: "/dns%3Fnext=evil.example", want: DefaultBaseURL},
		{name: "escaped fragment", value: "/dns%23fragment", want: DefaultBaseURL},
		{name: "escaped control", value: "/dns%0A", want: DefaultBaseURL},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("BASE_URL", tt.value)
			if got := normalizeBaseURL(); got != tt.want {
				t.Fatalf("normalizeBaseURL() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestResolveBlockingTrimsAndValidatesAddressFamilies(t *testing.T) {
	t.Setenv("BLOCK_CUSTOM_IP4", " 192.0.2.10 ")
	t.Setenv("BLOCK_CUSTOM_IP6", " 2001:db8::10 ")
	_, ip4, ip6 := resolveBlocking()
	if ip4 != "192.0.2.10" || ip6 != "2001:db8::10" {
		t.Fatalf("trimmed custom IPs = %q/%q", ip4, ip6)
	}

	t.Setenv("BLOCK_CUSTOM_IP4", "2001:db8::1")
	t.Setenv("BLOCK_CUSTOM_IP6", "192.0.2.1")
	_, ip4, ip6 = resolveBlocking()
	if ip4 != DefaultBlockCustomIP4 || ip6 != DefaultBlockCustomIP6 {
		t.Fatalf("wrong-family fallbacks = %q/%q", ip4, ip6)
	}
}

func TestVerifyStep6Config(t *testing.T) {
	base := func() *Config {
		return &Config{Port: DefaultPort, HistoryDir: t.TempDir(), DBPath: DefaultDBPath, IngestSecret: "test-secret"}
	}
	hasErr := func(errs []string, want string) bool {
		for _, err := range errs {
			if strings.Contains(err, want) {
				return true
			}
		}
		return false
	}

	cfg := base()
	cfg.DoTEnabled = true
	cfg.DoTPort = DefaultDoTPort
	errs, _ := cfg.VerifyConfig()
	if !hasErr(errs, "DOT_ENABLED requires TLS_CERT_FILE and TLS_KEY_FILE") {
		t.Fatalf("DoT certificate errors = %v", errs)
	}

	cfg = base()
	cfg.DoTEnabled = true
	cfg.DoTPort = 70000
	cfg.TLSCertFile = "cert.pem"
	cfg.TLSKeyFile = "key.pem"
	errs, _ = cfg.VerifyConfig()
	if !hasErr(errs, "DOT_PORT must be between 1 and 65535") {
		t.Fatalf("DoT port errors = %v", errs)
	}

	cfg = base()
	cfg.DoHEnabled = true
	cfg.DoHPath = "/api/events"
	errs, _ = cfg.VerifyConfig()
	if !hasErr(errs, "DOH_PATH must be a non-conflicting literal HTTP path") {
		t.Fatalf("DoH path errors = %v", errs)
	}
}

func TestVerifyConfigRejectsAuthenticationAndNetworkMisconfiguration(t *testing.T) {
	base := func() *Config {
		return &Config{
			Port: DefaultPort, WebListenAddr: DefaultWebListenAddr,
			HistoryDir: t.TempDir(), DBPath: DefaultDBPath,
			IngestSecret: "test-secret",
		}
	}

	cfg := base()
	cfg.WebUsername = "admin"
	errList, _ := cfg.VerifyConfig()
	if len(errList) == 0 {
		t.Fatal("partial web authentication passed verification")
	}

	cfg = base()
	cfg.Mode = ModeAgent
	cfg.ControllerURL = "https://100.64.0.1:35353"
	cfg.IngestSecret = ""
	cfg.WebUsername = "admin"
	cfg.WebPassword = "web-secret"
	errList, _ = cfg.VerifyConfig()
	if !slices.Contains(errList, "INGEST_SECRET is required in agent mode for authenticated controller communication") {
		t.Fatalf("agent without INGEST_SECRET errors = %v", errList)
	}

	cfg = base()
	cfg.DNSAllowedClients = "not-a-cidr"
	errList, _ = cfg.VerifyConfig()
	if len(errList) == 0 {
		t.Fatal("invalid DNS allow ACL passed verification")
	}

	cfg = base()
	cfg.DNS64 = true
	cfg.DNS64Prefixes = "2001:db8::/64"
	errList, _ = cfg.VerifyConfig()
	if len(errList) == 0 {
		t.Fatal("non-/96 DNS64 prefix passed verification")
	}

	cfg = base()
	cfg.BlocklistURLs = "https://user:password@example.test/list.txt"
	errList, _ = cfg.VerifyConfig()
	if len(errList) == 0 {
		t.Fatal("filter URL with embedded credentials passed verification")
	}
}

func TestLoadConfigControllerTLSModes(t *testing.T) {
	t.Setenv("MODE", ModeController)
	t.Setenv("CONTROLLER_URL", "")
	t.Setenv("WEB_TLS_MODE", "")
	t.Setenv("CONTROLLER_TLS_TRUST", "")
	t.Setenv("CONTROLLER_TLS_PIN_FILE", "")
	t.Setenv("TLS_STATE_DIR", "")
	cfg := LoadConfig()
	if cfg.WebTLSMode != "off" || cfg.ControllerTLSTrust != "system" {
		t.Fatalf("default TLS modes = %q/%q, want off/system", cfg.WebTLSMode, cfg.ControllerTLSTrust)
	}
	if cfg.TLSStateDir != DefaultTLSStateDir {
		t.Fatalf("default TLS state directory = %q", cfg.TLSStateDir)
	}
	if cfg.ControllerTLSPinFile != "controller-ca-pin.json" {
		t.Fatalf("default controller pin file = %q", cfg.ControllerTLSPinFile)
	}

	t.Setenv("MODE", ModeAgent)
	t.Setenv("CONTROLLER_URL", "https://100.64.10.20:35353")
	t.Setenv("CONTROLLER_TLS_TRUST", "tofu-tailnet")
	t.Setenv("CONTROLLER_TLS_PIN_FILE", "custom-pin.json")
	t.Setenv("TLS_STATE_DIR", t.TempDir())
	cfg = LoadConfig()
	if cfg.ControllerTLSTrust != "tofu-tailnet" || cfg.ControllerTLSPinFile != "custom-pin.json" {
		t.Fatalf("configured controller TLS = %q/%q", cfg.ControllerTLSTrust, cfg.ControllerTLSPinFile)
	}

	t.Setenv("CONTROLLER_TLS_PIN_FILE", "tls/controller-ca-pin.json")
	cfg = LoadConfig()
	if cfg.ControllerTLSPinFile != "controller-ca-pin.json" {
		t.Fatalf("legacy controller pin file = %q", cfg.ControllerTLSPinFile)
	}

	t.Setenv("CONTROLLER_TLS_PIN_FILE", "tls/agents/custom-pin.json")
	cfg = LoadConfig()
	if want := filepath.Join("agents", "custom-pin.json"); cfg.ControllerTLSPinFile != want {
		t.Fatalf("custom legacy controller pin file = %q, want %q", cfg.ControllerTLSPinFile, want)
	}
}

func TestControllerTLSPinPathUsesTLSStateDirectory(t *testing.T) {
	tlsStateDir := t.TempDir()
	cfg := &Config{
		HistoryDir:           filepath.Join(t.TempDir(), "history"),
		TLSStateDir:          tlsStateDir,
		ControllerTLSPinFile: "controller-ca-pin.json",
	}
	if got, want := cfg.FullControllerTLSPinPath(), filepath.Join(tlsStateDir, "controller-ca-pin.json"); got != want {
		t.Fatalf("FullControllerTLSPinPath() = %q, want %q", got, want)
	}

	absolute := filepath.Join(t.TempDir(), "absolute-pin.json")
	cfg.ControllerTLSPinFile = absolute
	if got := cfg.FullControllerTLSPinPath(); got != absolute {
		t.Fatalf("absolute FullControllerTLSPinPath() = %q, want %q", got, absolute)
	}

	legacyConfig := &Config{
		HistoryDir:           cfg.HistoryDir,
		ControllerTLSPinFile: "tls/controller-ca-pin.json",
	}
	if got, want := legacyConfig.FullControllerTLSPinPath(), filepath.Join(cfg.HistoryDir, "tls", "controller-ca-pin.json"); got != want {
		t.Fatalf("legacy FullControllerTLSPinPath() = %q, want %q", got, want)
	}
}

func TestManagedPathResolution(t *testing.T) {
	configDir := t.TempDir()
	historyDir := t.TempDir()
	absolute := filepath.Join(t.TempDir(), "absolute.json")
	tests := []struct {
		name string
		set  func(*Config, string)
		get  func(*Config) string
	}{
		{name: "upstreams", set: func(c *Config, value string) { c.UpstreamsFile = value }, get: (*Config).FullUpstreamsPath},
		{name: "dns routes", set: func(c *Config, value string) { c.DNSRoutesFile = value }, get: (*Config).FullDNSRoutesPath},
		{name: "rewrites", set: func(c *Config, value string) { c.RewritesFile = value }, get: (*Config).FullRewritesPath},
		{name: "clients", set: func(c *Config, value string) { c.ClientsFile = value }, get: (*Config).FullClientsPath},
		{name: "blocklist", set: func(c *Config, value string) { c.BlocklistFile = value }, get: (*Config).FullBlocklistPath},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := &Config{ConfigDir: configDir, HistoryDir: historyDir}
			if got := test.get(cfg); got != "" {
				t.Fatalf("empty path = %q", got)
			}
			test.set(cfg, "managed.json")
			if got := test.get(cfg); got != filepath.Join(configDir, "managed.json") {
				t.Fatalf("relative path = %q", got)
			}
			test.set(cfg, absolute)
			if got := test.get(cfg); got != absolute {
				t.Fatalf("absolute path = %q", got)
			}
		})
	}

	cfg := &Config{HistoryDir: historyDir, DBPath: "resolix.db"}
	if cfg.FullConfigDir() != historyDir || cfg.FullDBPath() != filepath.Join(historyDir, "resolix.db") {
		t.Fatalf("legacy path fallbacks: config=%q db=%q", cfg.FullConfigDir(), cfg.FullDBPath())
	}
	cfg.DBPath = absolute
	if cfg.FullDBPath() != absolute {
		t.Fatalf("absolute database path = %q", cfg.FullDBPath())
	}
	if got := cfg.FullTLSStateDir(); got != filepath.Join(historyDir, "tls") {
		t.Fatalf("legacy TLS state directory = %q", got)
	}
}

func TestVerifyConfigReportsMissingOptionalFiles(t *testing.T) {
	t.Setenv("DNSMASQ_PID_FILE", "/deprecated.pid")
	cfg := &Config{
		Mode: ModeController, Port: DefaultPort, WebListenAddr: DefaultWebListenAddr,
		HistoryDir: t.TempDir(), ConfigDir: t.TempDir(), DBPath: DefaultDBPath,
		IngestSecret: "test-secret", ClientAliasesFile: filepath.Join(t.TempDir(), "aliases.txt"),
		BlocklistFile: "blocklist.txt", DNSRoutesFile: "routes.json",
	}
	errs, warnings := cfg.VerifyConfig()
	if len(errs) != 0 {
		t.Fatalf("VerifyConfig errors = %v", errs)
	}
	joined := strings.Join(warnings, "\n")
	for _, want := range []string{"DNSMASQ_PID_FILE is deprecated", "CLIENT_ALIASES_FILE", "BLOCKLIST_FILE", "DNS_ROUTES_FILE"} {
		if !strings.Contains(joined, want) {
			t.Errorf("warning %q missing from %v", want, warnings)
		}
	}
}

func TestVerifyConfigControllerTLSBoundaries(t *testing.T) {
	base := func() *Config {
		return &Config{
			Mode: ModeController, Port: DefaultPort, WebListenAddr: DefaultWebListenAddr,
			HistoryDir: t.TempDir(), DBPath: DefaultDBPath, IngestSecret: "test-secret",
		}
	}
	hasTLSFailure := func(cfg *Config) bool {
		errs, _ := cfg.VerifyConfig()
		return strings.Contains(strings.Join(errs, "\n"), "TLS") ||
			strings.Contains(strings.Join(errs, "\n"), "tofu-tailnet")
	}

	cfg := base()
	cfg.WebTLSMode = "auto"
	cfg.WebTLSIP = "100.64.10.20"
	if hasTLSFailure(cfg) {
		t.Fatal("valid generated controller TLS configuration failed verification")
	}

	cfg = base()
	cfg.WebTLSMode = "auto"
	cfg.WebTLSIP = "192.168.1.10"
	if !hasTLSFailure(cfg) {
		t.Fatal("generated controller TLS accepted a non-Tailscale address")
	}

	cfg = base()
	cfg.Mode = ModeAgent
	cfg.ControllerURL = "https://100.64.10.20:35353"
	cfg.ControllerTLSTrust = "tofu-tailnet"
	cfg.ControllerTLSPinFile = "tls/pin.json"
	if hasTLSFailure(cfg) {
		t.Fatal("valid tailnet TOFU configuration failed verification")
	}

	cfg.ControllerURL = "https://controller.example.test"
	if !hasTLSFailure(cfg) {
		t.Fatal("tailnet TOFU accepted a hostname controller URL")
	}
}

func TestResolveDoHPathRejectsProtocolRelativeForms(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{name: "double slash", value: "//example.test/dns-query"},
		{name: "slash backslash", value: `/\\example.test/dns-query`},
		{name: "backslash slash", value: `\\/example.test/dns-query`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("DOH_PATH", test.value)
			if got := resolveDoHPath(); got != DefaultDoHPath {
				t.Fatalf("resolveDoHPath() = %q, want %q", got, DefaultDoHPath)
			}
		})
	}
}

func TestBatchArchiveIntervalFeedsLegacyAndCurrentFields(t *testing.T) {
	t.Setenv("BATCH_ARCHIVE_INTERVAL", "17s")
	cfg := LoadConfig()
	if cfg.BatchArchiveInterval != 17*time.Second || cfg.ArchiveInterval != 17*time.Second {
		t.Fatalf("archive intervals = %s/%s", cfg.BatchArchiveInterval, cfg.ArchiveInterval)
	}
}

func TestArchiveDurabilityDefaults(t *testing.T) {
	t.Setenv("BATCH_ARCHIVE_INTERVAL", "")
	t.Setenv("ARCHIVE_TRIGGER_SIZE", "")
	cfg := LoadConfig()
	if cfg.BatchArchiveInterval != time.Minute || cfg.ArchiveInterval != time.Minute {
		t.Fatalf("default archive intervals = %s/%s, want 1m/1m", cfg.BatchArchiveInterval, cfg.ArchiveInterval)
	}
	if cfg.ArchiveTriggerSize != 5000 {
		t.Fatalf("default archive trigger = %d, want 5000", cfg.ArchiveTriggerSize)
	}
}

func TestArchiveQueueSettings(t *testing.T) {
	t.Run("explicit values", func(t *testing.T) {
		t.Setenv("ARCHIVE_QUEUE_CAPACITY", "200000")
		t.Setenv("ARCHIVE_TRIGGER_SIZE", "10000")
		t.Setenv("ARCHIVE_WRITE_BATCH_SIZE", "2500")
		cfg := LoadConfig()
		if cfg.ArchiveQueueCapacity != 200000 || cfg.ArchiveTriggerSize != 10000 || cfg.ArchiveWriteBatchSize != 2500 {
			t.Fatalf("archive queue settings = %d/%d/%d", cfg.ArchiveQueueCapacity, cfg.ArchiveTriggerSize, cfg.ArchiveWriteBatchSize)
		}
	})

	t.Run("limits follow capacity", func(t *testing.T) {
		t.Setenv("ARCHIVE_QUEUE_CAPACITY", "100")
		t.Setenv("ARCHIVE_TRIGGER_SIZE", "101")
		t.Setenv("ARCHIVE_WRITE_BATCH_SIZE", "101")
		cfg := LoadConfig()
		if cfg.ArchiveTriggerSize != 50 || cfg.ArchiveWriteBatchSize != 100 {
			t.Fatalf("normalized archive limits = %d/%d, want 50/100", cfg.ArchiveTriggerSize, cfg.ArchiveWriteBatchSize)
		}
	})
}

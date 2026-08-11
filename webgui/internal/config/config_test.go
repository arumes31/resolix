package config

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

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

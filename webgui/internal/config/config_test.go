package config

import (
	"testing"
	"time"
)

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
		return &Config{Port: DefaultPort, HistoryDir: t.TempDir(), DBPath: DefaultDBPath}
	}

	cfg := base()
	cfg.DoTEnabled = true
	cfg.DoTPort = DefaultDoTPort
	errs, _ := cfg.VerifyConfig()
	if len(errs) == 0 {
		t.Fatal("DoT without certificate files passed verification")
	}

	cfg = base()
	cfg.DoTEnabled = true
	cfg.DoTPort = 70000
	cfg.TLSCertFile = "cert.pem"
	cfg.TLSKeyFile = "key.pem"
	errs, _ = cfg.VerifyConfig()
	if len(errs) == 0 {
		t.Fatal("out-of-range DoT port passed verification")
	}

	cfg = base()
	cfg.DoHEnabled = true
	cfg.DoHPath = "/api/events"
	errs, _ = cfg.VerifyConfig()
	if len(errs) == 0 {
		t.Fatal("conflicting DoH path passed verification")
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

func TestBatchArchiveIntervalFeedsLegacyAndCurrentFields(t *testing.T) {
	t.Setenv("BATCH_ARCHIVE_INTERVAL", "17s")
	cfg := LoadConfig()
	if cfg.BatchArchiveInterval != 17*time.Second || cfg.ArchiveInterval != 17*time.Second {
		t.Fatalf("archive intervals = %s/%s", cfg.BatchArchiveInterval, cfg.ArchiveInterval)
	}
}

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

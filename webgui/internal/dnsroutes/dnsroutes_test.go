package dnsroutes

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestRoutePrecedenceAndAtomicSave(t *testing.T) {
	path := filepath.Join(t.TempDir(), "routes.json")
	dr := New(path)
	err := dr.SetRoutes(map[string]string{
		"*.example.com":     "wildcard",
		"example.com":       "exact",
		"*.sub.example.com": "specific-wildcard",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := dr.GetUpstreamForDomain("example.com"); got != "exact" {
		t.Fatalf("apex upstream = %q; want exact", got)
	}
	if got := dr.GetUpstreamForDomain("host.sub.example.com"); got != "specific-wildcard" {
		t.Fatalf("specific wildcard upstream = %q", got)
	}
	if got := New(path).GetUpstreamForDomain("host.sub.example.com"); got != "specific-wildcard" {
		t.Fatalf("reloaded upstream = %q", got)
	}
}

func TestReloadKeepsLastGoodRoutes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "routes.json")
	dr := New(path)
	if err := dr.SetRoutes(map[string]string{"example.test": "192.0.2.53"}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{invalid"), 0o600); err != nil {
		t.Fatal(err)
	}
	dr.load()
	if got := dr.GetUpstreamForDomain("example.test"); got != "192.0.2.53" {
		t.Fatalf("route after corrupt reload = %q", got)
	}
}

func TestOnChangeOnlyFiresForSuccessfulChanges(t *testing.T) {
	path := filepath.Join(t.TempDir(), "routes.json")
	dr := New(path)
	changes := 0
	dr.SetOnChange(func() { changes++ })

	if err := dr.SetRoutes(map[string]string{"example.test": "192.0.2.53"}); err != nil {
		t.Fatal(err)
	}
	if changes != 1 {
		t.Fatalf("changes after SetRoutes = %d, want 1", changes)
	}
	if err := os.WriteFile(path, []byte(`{"changed.test":"198.51.100.53"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	dr.load()
	if changes != 2 {
		t.Fatalf("changes after successful load = %d, want 2", changes)
	}
	if err := os.WriteFile(path, []byte("{invalid"), 0o600); err != nil {
		t.Fatal(err)
	}
	dr.load()
	if changes != 2 {
		t.Fatalf("changes after corrupt load = %d, want 2", changes)
	}
}

func TestUpstreamSettingsRoundTripAndLegacyCompatibility(t *testing.T) {
	t.Run("object settings", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "upstreams.json")
		want := UpstreamSettings{
			Upstreams:           []string{"tls://dns.example:853"},
			BootstrapServers:    []string{"192.0.2.53"},
			BootstrapConfigured: true,
		}
		if err := SaveUpstreamSettings(path, want); err != nil {
			t.Fatal(err)
		}
		got := LoadUpstreamSettings(path)
		if !slices.Equal(got.Upstreams, want.Upstreams) ||
			!slices.Equal(got.BootstrapServers, want.BootstrapServers) || !got.BootstrapConfigured {
			t.Fatalf("settings = %+v, want %+v", got, want)
		}
	})

	t.Run("legacy array inherits bootstrap environment", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "upstreams.json")
		if err := os.WriteFile(path, []byte(`["1.1.1.1"]`), 0o600); err != nil {
			t.Fatal(err)
		}
		got := LoadUpstreamSettings(path)
		if !slices.Equal(got.Upstreams, []string{"1.1.1.1"}) || got.BootstrapConfigured {
			t.Fatalf("legacy settings = %+v", got)
		}
	})
}

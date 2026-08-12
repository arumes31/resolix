package dnsroutes

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestInMemoryRoutesAndLifecycle(t *testing.T) {
	routes := New("")
	if routes.Count() != 0 {
		t.Fatalf("initial Count() = %d", routes.Count())
	}
	if err := routes.SetRoutes(map[string]string{"Example.COM": "192.0.2.53"}); err != nil {
		t.Fatal(err)
	}
	if got := routes.GetUpstreamForDomain("SUB.EXAMPLE.COM."); got != "" {
		t.Fatalf("exact route unexpectedly matched subdomain: %q", got)
	}
	if got := routes.GetUpstreamForDomain("example.com."); got != "192.0.2.53" {
		t.Fatalf("normalized exact route = %q", got)
	}
	if routes.Count() != 1 || routes.GetRoutesMap()["example.com"] != "192.0.2.53" {
		t.Fatalf("route snapshot = %#v", routes.GetRoutes())
	}
	copyOfRoutes := routes.GetRoutes()
	copyOfRoutes[0].Upstream = "changed"
	if routes.GetRoutes()[0].Upstream != "192.0.2.53" {
		t.Fatal("GetRoutes returned mutable internal storage")
	}

	ctx, cancel := context.WithCancel(t.Context())
	routes.StartReload(ctx)
	routes.StartReload(ctx)
	cancel()
	routes.Stop()
}

func TestMatchPattern(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		domain  string
		want    bool
	}{
		{name: "exact", pattern: "example.com", domain: "example.com", want: true},
		{name: "wildcard apex", pattern: "*.example.com", domain: "example.com", want: true},
		{name: "wildcard child", pattern: "*.example.com", domain: "a.example.com", want: true},
		{name: "label boundary", pattern: "*.example.com", domain: "badexample.com"},
		{name: "plain pattern has no suffix match", pattern: "example.com", domain: "a.example.com"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := matchPattern(test.pattern, test.domain); got != test.want {
				t.Fatalf("matchPattern(%q, %q) = %v, want %v", test.pattern, test.domain, got, test.want)
			}
		})
	}
}

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

func TestUpstreamFileCompatibilityAndErrors(t *testing.T) {
	t.Run("legacy list save", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "upstreams.json")
		if err := SaveUpstreams(path, []string{"1.1.1.1", "9.9.9.9"}); err != nil {
			t.Fatal(err)
		}
		if got := LoadUpstreams(path); !slices.Equal(got, []string{"1.1.1.1", "9.9.9.9"}) {
			t.Fatalf("LoadUpstreams() = %#v", got)
		}
	})

	t.Run("object save preserves bootstrap", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "upstreams.json")
		if err := SaveUpstreamSettings(path, UpstreamSettings{
			Upstreams:           []string{"1.1.1.1"},
			BootstrapServers:    []string{"192.0.2.53"},
			BootstrapConfigured: true,
		}); err != nil {
			t.Fatal(err)
		}
		if err := SaveUpstreams(path, []string{"9.9.9.9"}); err != nil {
			t.Fatal(err)
		}
		got := LoadUpstreamSettings(path)
		if !got.BootstrapConfigured || !slices.Equal(got.BootstrapServers, []string{"192.0.2.53"}) ||
			!slices.Equal(got.Upstreams, []string{"9.9.9.9"}) {
			t.Fatalf("settings = %+v", got)
		}
	})

	t.Run("legacy map", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "upstreams.json")
		if err := os.WriteFile(path, []byte(`{"1.1.1.1":"", "9.9.9.9":""}`), 0o600); err != nil {
			t.Fatal(err)
		}
		got := LoadUpstreams(path)
		slices.Sort(got)
		if !slices.Equal(got, []string{"1.1.1.1", "9.9.9.9"}) {
			t.Fatalf("legacy map = %#v", got)
		}
	})

	t.Run("malformed bootstrap", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "upstreams.json")
		if err := os.WriteFile(path, []byte(`{"upstreams":["1.1.1.1"],"bootstrap_servers":"bad"}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := LoadUpstreamSettings(path); len(got.Upstreams) != 0 {
			t.Fatalf("malformed object = %+v", got)
		}
	})

	t.Run("missing parent", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "missing", "upstreams.json")
		if err := SaveUpstreams(path, []string{"1.1.1.1"}); err == nil {
			t.Fatal("SaveUpstreams unexpectedly succeeded")
		}
		if err := SaveUpstreamSettings(path, UpstreamSettings{}); err == nil {
			t.Fatal("SaveUpstreamSettings unexpectedly succeeded")
		}
	})
}

func TestLoadHelpersAndReadLines(t *testing.T) {
	directory := t.TempDir()
	routesPath := filepath.Join(directory, "routes.json")
	if err := os.WriteFile(routesPath, []byte(`{"example.test":"192.0.2.53"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := LoadFromFile(routesPath); got["example.test"] != "192.0.2.53" {
		t.Fatalf("LoadFromFile() = %#v", got)
	}
	if got := LoadFromFile(filepath.Join(directory, "missing.json")); got != nil {
		t.Fatalf("missing LoadFromFile() = %#v", got)
	}
	invalidPath := filepath.Join(directory, "invalid.json")
	if err := os.WriteFile(invalidPath, []byte("invalid"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := LoadFromFile(invalidPath); got != nil {
		t.Fatalf("invalid LoadFromFile() = %#v", got)
	}

	linesPath := filepath.Join(directory, "lines.txt")
	if err := os.WriteFile(linesPath, []byte("# comment\n\n  first  \nsecond\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := ReadLines(linesPath); !slices.Equal(got, []string{"first", "second"}) {
		t.Fatalf("ReadLines() = %#v", got)
	}
	if got := ReadLines(filepath.Join(directory, "missing.txt")); got != nil {
		t.Fatalf("missing ReadLines() = %#v", got)
	}
}

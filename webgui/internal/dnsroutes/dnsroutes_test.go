package dnsroutes

import (
	"os"
	"path/filepath"
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

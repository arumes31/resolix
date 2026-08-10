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

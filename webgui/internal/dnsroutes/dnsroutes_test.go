package dnsroutes

import (
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

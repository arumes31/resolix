package blocklist

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadSupportedFormatsAndStatus(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blocklist.txt")
	contents := `
# comment
0.0.0.0 Example.COM.
127.0.0.1 loopback.test
::1 ipv6-loopback.test
192.0.2.10 allowed-address.test
simple.test
`
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	blocklist := New(path)
	if got := blocklist.Count(); got != 4 {
		t.Fatalf("Count() = %d, want 4", got)
	}
	for _, domain := range []string{"example.com", "loopback.test", "ipv6-loopback.test", "simple.test"} {
		if !blocklist.IsBlocked(domain) {
			t.Errorf("%q was not blocked", domain)
		}
	}
	if blocklist.IsBlocked("allowed-address.test") {
		t.Fatal("non-blocking hosts entry was loaded")
	}
	status := blocklist.Status()
	if status["count"] != 4 || status["file"] != path || status["last_error"] != "" {
		t.Fatalf("Status() = %#v", status)
	}
	if status["last_loaded"] == "" {
		t.Fatalf("Status() has empty load timestamp: %#v", status)
	}
}

func TestEmptyPathAndReloadLifecycle(t *testing.T) {
	blocklist := New("")
	if blocklist.Count() != 0 || blocklist.LastLoaded().IsZero() {
		t.Fatalf("empty-path blocklist state: count=%d loaded=%v", blocklist.Count(), blocklist.LastLoaded())
	}

	ctx, cancel := context.WithCancel(t.Context())
	blocklist.StartReload(ctx)
	blocklist.StartReload(ctx)
	cancel()
	blocklist.Stop()
}

func TestLoadPreservesDataAndReportsError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blocklist.txt")
	if err := os.WriteFile(path, []byte("0.0.0.0 example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bl := New(path)
	loaded := bl.LastLoaded()
	if !bl.IsBlocked("example.com") {
		t.Fatal("initial domain not loaded")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	bl.load()
	status := bl.Status()
	if !bl.IsBlocked("example.com") || !bl.LastLoaded().Equal(loaded) {
		t.Fatal("failed reload replaced the last successful blocklist state")
	}
	if status["last_error"] == "" {
		t.Fatal("failed reload did not expose last_error")
	}
}

func TestIsBlockedParentDomainSuffix(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blocklist.txt")
	if err := os.WriteFile(path, []byte("example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bl := New(path)

	blocked := []string{"example.com", "ads.example.com", "deep.ads.example.com", "EXAMPLE.COM.", "example.com."}
	for _, d := range blocked {
		if !bl.IsBlocked(d) {
			t.Errorf("expected %q to be blocked", d)
		}
	}

	// Suffix checks must respect domain-label boundaries.
	allowed := []string{"badexample.com", "example.com.evil.net", "com", "notexample.com"}
	for _, d := range allowed {
		if bl.IsBlocked(d) {
			t.Errorf("expected %q NOT to be blocked", d)
		}
	}
}

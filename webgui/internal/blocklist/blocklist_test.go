package blocklist

import (
	"os"
	"path/filepath"
	"testing"
)

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

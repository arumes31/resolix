package controllertls

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestMigrateLegacyStateCopiesManagedFilesWithoutOverwriting(t *testing.T) {
	legacyDir := filepath.Join(t.TempDir(), "history", "tls")
	stateDir := filepath.Join(t.TempDir(), "tls-state")
	if err := os.MkdirAll(legacyDir, 0o700); err != nil {
		t.Fatalf("create legacy directory: %v", err)
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatalf("create state directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(legacyDir, caFileName), []byte("legacy-ca"), 0o600); err != nil {
		t.Fatalf("write legacy CA: %v", err)
	}
	if err := os.WriteFile(filepath.Join(legacyDir, DefaultPinFile), []byte("legacy-pin"), 0o600); err != nil {
		t.Fatalf("write legacy pin: %v", err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, DefaultPinFile), []byte("current-pin"), 0o600); err != nil {
		t.Fatalf("write current pin: %v", err)
	}

	migrated, err := MigrateLegacyState(legacyDir, stateDir, DefaultPinFile)
	if err != nil {
		t.Fatalf("MigrateLegacyState() error = %v", err)
	}
	if migrated != 1 {
		t.Fatalf("MigrateLegacyState() count = %d, want 1", migrated)
	}
	assertFileContents(t, filepath.Join(stateDir, caFileName), "legacy-ca")
	assertFileContents(t, filepath.Join(stateDir, DefaultPinFile), "current-pin")
	assertFileContents(t, filepath.Join(legacyDir, caFileName), "legacy-ca")

	info, err := os.Stat(filepath.Join(stateDir, caFileName))
	if err != nil {
		t.Fatalf("stat migrated CA: %v", err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("migrated CA permissions = %o, want 600", info.Mode().Perm())
	}
}

func TestMigrateLegacyStateCopiesConfiguredCustomPin(t *testing.T) {
	legacyDir := filepath.Join(t.TempDir(), "history", "tls")
	stateDir := filepath.Join(t.TempDir(), "tls-state")
	customPin := filepath.Join("agents", "custom-pin.json")
	if err := os.MkdirAll(filepath.Join(legacyDir, filepath.Dir(customPin)), 0o700); err != nil {
		t.Fatalf("create legacy pin directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(legacyDir, customPin), []byte("custom-pin"), 0o600); err != nil {
		t.Fatalf("write legacy custom pin: %v", err)
	}

	migrated, err := MigrateLegacyState(legacyDir, stateDir, customPin)
	if err != nil {
		t.Fatalf("MigrateLegacyState() error = %v", err)
	}
	if migrated != 1 {
		t.Fatalf("MigrateLegacyState() count = %d, want 1", migrated)
	}
	assertFileContents(t, filepath.Join(stateDir, customPin), "custom-pin")
}

func TestMigrateLegacyStateRejectsNonRegularSource(t *testing.T) {
	legacyDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(legacyDir, caFileName), 0o700); err != nil {
		t.Fatalf("create non-regular source: %v", err)
	}
	if _, err := MigrateLegacyState(legacyDir, t.TempDir(), DefaultPinFile); err == nil {
		t.Fatal("MigrateLegacyState() accepted a non-regular source")
	}
}

func TestMigrateLegacyStateSameDirectoryIsNoOp(t *testing.T) {
	dir := t.TempDir()
	migrated, err := MigrateLegacyState(dir, dir, DefaultPinFile)
	if err != nil || migrated != 0 {
		t.Fatalf("MigrateLegacyState() = %d, %v; want 0, nil", migrated, err)
	}
}

func TestMigrateLegacyStateSecuresDestinationDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not expose Unix directory permission bits")
	}
	stateDir := t.TempDir()
	if err := os.Chmod(stateDir, 0o755); err != nil { // #nosec G302 -- the test deliberately creates an over-broad directory to verify hardening.
		t.Fatalf("relax state directory permissions: %v", err)
	}
	if _, err := MigrateLegacyState(t.TempDir(), stateDir, DefaultPinFile); err != nil {
		t.Fatalf("MigrateLegacyState() error = %v", err)
	}
	info, err := os.Stat(stateDir)
	if err != nil {
		t.Fatalf("stat state directory: %v", err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("state directory permissions = %o, want 700", info.Mode().Perm())
	}
}

func assertFileContents(t *testing.T, path, want string) {
	t.Helper()
	data, err := os.ReadFile(path) // #nosec G304 -- test path is created under t.TempDir.
	if err != nil {
		t.Fatalf("read %s: %v", filepath.Base(path), err)
	}
	if string(data) != want {
		t.Fatalf("%s = %q, want %q", filepath.Base(path), data, want)
	}
}

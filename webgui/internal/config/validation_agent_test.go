package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestVerifyConfigAgentIgnoresDatabasePath(t *testing.T) {
	stateDir := t.TempDir()
	blockedParent := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blockedParent, []byte("occupied"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{
		Mode:               ModeAgent,
		Port:               DefaultPort,
		WebListenAddr:      DefaultWebListenAddr,
		HistoryDir:         stateDir,
		DBPath:             filepath.Join(blockedParent, "unused.db"),
		ControllerURL:      "https://100.64.0.1:35353",
		ControllerTLSTrust: "system",
		IngestSecret:       "test-secret",
		WebAuthDisabled:    true,
	}

	errs, _ := cfg.VerifyConfig()
	if len(errs) != 0 {
		t.Fatalf("agent validation errors = %v, want none", errs)
	}
}

package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMigrateLegacyStateCopiesManagedFilesWithoutReplacingDestinations(t *testing.T) {
	root := t.TempDir()
	historyDir := filepath.Join(root, "history")
	configDir := filepath.Join(root, "config")
	if err := os.MkdirAll(filepath.Join(historyDir, "lists"), 0o750); err != nil {
		t.Fatal(err)
	}
	files := []string{
		"filter-subscriptions.json",
		"user_rules.txt",
		"upstreams.json",
		"dns-routes.json",
		"rewrites.json",
		"clients.json",
		filepath.Join("lists", "block.txt"),
	}
	for _, name := range files {
		path := filepath.Join(historyDir, name)
		if err := os.WriteFile(path, []byte("legacy "+name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cfg := &Config{
		HistoryDir:    historyDir,
		ConfigDir:     configDir,
		UpstreamsFile: "upstreams.json",
		DNSRoutesFile: "dns-routes.json",
		RewritesFile:  "rewrites.json",
		ClientsFile:   "clients.json",
		BlocklistFile: filepath.Join("lists", "block.txt"),
	}

	migrated, err := MigrateLegacyState(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if migrated != len(files) {
		t.Fatalf("migrated files = %d, want %d", migrated, len(files))
	}
	for _, name := range files {
		data, readErr := os.ReadFile(filepath.Join(configDir, name)) // #nosec G304 -- test reads a path built from t.TempDir and a fixed table.
		if readErr != nil {
			t.Fatalf("read migrated %s: %v", name, readErr)
		}
		if string(data) != "legacy "+name {
			t.Fatalf("migrated %s = %q", name, data)
		}
		if _, statErr := os.Stat(filepath.Join(historyDir, name)); statErr != nil {
			t.Fatalf("legacy recovery copy %s was removed: %v", name, statErr)
		}
	}

	destination := filepath.Join(configDir, "rewrites.json")
	if err := os.WriteFile(destination, []byte("newer config"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(historyDir, "rewrites.json"), []byte("stale legacy"), 0o600); err != nil {
		t.Fatal(err)
	}
	migrated, err = MigrateLegacyState(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if migrated != 0 {
		t.Fatalf("second migration copied %d files, want 0", migrated)
	}
	data, err := os.ReadFile(destination) // #nosec G304 -- test reads a path below t.TempDir.
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "newer config" {
		t.Fatalf("existing destination was replaced: %q", data)
	}
}

func TestConfigPathsUseDedicatedDirectory(t *testing.T) {
	configDir := t.TempDir()
	cfg := &Config{
		HistoryDir:    filepath.Join(t.TempDir(), "history"),
		ConfigDir:     configDir,
		UpstreamsFile: "upstreams.json",
		DNSRoutesFile: "dns-routes.json",
		RewritesFile:  "rewrites.json",
		ClientsFile:   "clients.json",
	}
	tests := []struct {
		name string
		got  string
		want string
	}{
		{name: "upstreams", got: cfg.FullUpstreamsPath(), want: filepath.Join(configDir, "upstreams.json")},
		{name: "DNS routes", got: cfg.FullDNSRoutesPath(), want: filepath.Join(configDir, "dns-routes.json")},
		{name: "rewrites", got: cfg.FullRewritesPath(), want: filepath.Join(configDir, "rewrites.json")},
		{name: "clients", got: cfg.FullClientsPath(), want: filepath.Join(configDir, "clients.json")},
		{name: "custom rules", got: cfg.FullUserRulesPath(), want: filepath.Join(configDir, "user_rules.txt")},
		{name: "subscriptions", got: cfg.FullFilterSubscriptionsPath(), want: filepath.Join(configDir, "filter-subscriptions.json")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.got != test.want {
				t.Fatalf("path = %q, want %q", test.got, test.want)
			}
		})
	}
}

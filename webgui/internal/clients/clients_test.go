package clients

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestRegistryReplaceIsAtomicAndDefensive(t *testing.T) {
	registry, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	items := []Client{
		{Name: "one", IDs: []string{"192.0.2.1"}, Tags: []string{"original"}},
		{Name: "two", IDs: []string{"198.51.100.0/24"}},
	}
	if err := registry.Replace(items); err != nil {
		t.Fatal(err)
	}
	items[0].Tags[0] = "mutated"
	if got := registry.Find("192.0.2.1"); got == nil || got.Tags[0] != "original" {
		t.Fatalf("Replace retained caller-owned data: %+v", got)
	}
	if err := registry.Replace([]Client{{Name: "duplicate", IDs: []string{"192.0.2.1"}}, {Name: "duplicate", IDs: []string{"198.51.100.1"}}}); err == nil {
		t.Fatal("Replace accepted duplicate names")
	}
	if err := registry.Replace([]Client{{Name: "bad", IDs: []string{"invalid"}}}); err == nil {
		t.Fatal("Replace accepted an invalid client")
	}
	if err := registry.Replace([]Client{{Name: "one", IDs: []string{"192.0.2.0/24"}}, {Name: "two", IDs: []string{"192.0.2.0/24"}}}); err == nil {
		t.Fatal("Replace accepted conflicting client networks")
	}
	if got := registry.Find("192.0.2.1"); got == nil || got.Name != "one" {
		t.Fatalf("failed Replace mutated registry: %+v", got)
	}
}

func TestRegistryStartReloadLifecycle(t *testing.T) {
	inMemory, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	inMemory.StartReload(t.Context())

	path := filepath.Join(t.TempDir(), "clients.json")
	if err := os.WriteFile(path, []byte("[]"), 0o600); err != nil {
		t.Fatal(err)
	}
	registry, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	registry.StartReload(ctx)
}

func TestRegistryCRUDAndPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "clients.json")

	r, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(r.List()) != 0 {
		t.Fatal("new registry must be empty")
	}

	c := Client{Name: "kids-pc", IDs: []string{"192.168.1.50", "fd00::50"}, Tags: []string{"kids"}, UseGlobalSettings: true}
	if err := r.Add(c); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := r.Add(c); err == nil {
		t.Error("duplicate name must be rejected")
	}
	if err := r.Add(Client{Name: "bad", IDs: []string{"999.1.1.1"}}); err == nil {
		t.Error("invalid IP must be rejected")
	}

	// Persistence: reload from disk.
	r2, err := Load(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got := r2.Find("192.168.1.50"); got == nil || got.Name != "kids-pc" {
		t.Fatalf("Find after reload: %+v", got)
	}

	// Update.
	updated := c
	updated.UseGlobalSettings = false
	updated.Upstreams = []string{"9.9.9.9"}
	if err := r2.Update(updated); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if got := r2.Find("192.168.1.50"); got == nil || len(got.Upstreams) != 1 {
		t.Errorf("after update: %+v", got)
	}
	if err := r2.Update(Client{Name: "ghost", IDs: []string{"1.2.3.4"}}); err == nil {
		t.Error("update of missing client must fail")
	}

	// Delete.
	if !r2.Delete("kids-pc") {
		t.Error("Delete returned false for existing client")
	}
	if r2.Find("192.168.1.50") != nil {
		t.Error("deleted client still found")
	}
}

func TestRegistryPersistenceFailureDoesNotMutateMemory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "clients.json")
	registry, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Add(Client{Name: "client", IDs: []string{"192.0.2.1"}}); err == nil {
		t.Fatal("add unexpectedly succeeded with missing persistence directory")
	}
	if clients := registry.List(); len(clients) != 0 {
		t.Fatalf("memory mutated after failed save: %+v", clients)
	}
}

func TestRegistryReturnsDeepCopiesAndRejectsConflicts(t *testing.T) {
	registry, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	original := Client{Name: "one", IDs: []string{"192.0.2.0/24"}, Tags: []string{"original"}}
	if err := registry.Add(original); err != nil {
		t.Fatal(err)
	}
	listed := registry.List()
	listed[0].IDs[0] = "198.51.100.0/24"
	found := registry.Find("192.0.2.1")
	if found == nil || found.IDs[0] != "192.0.2.0/24" {
		t.Fatalf("registry leaked mutable state: %+v", found)
	}
	found.Tags[0] = "mutated"
	if registry.Find("192.0.2.1").Tags[0] != "original" {
		t.Fatal("Find returned internal slice storage")
	}
	if err := registry.Add(Client{Name: "two", IDs: []string{"192.0.2.0/24"}}); err == nil {
		t.Fatal("equal-prefix conflict was accepted")
	}
}

func TestRegistryClonesAddAndUpdateCandidates(t *testing.T) {
	registry, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	candidate := Client{
		Name:      "owned",
		IDs:       []string{"192.0.2.1"},
		Tags:      []string{"original"},
		Upstreams: []string{"9.9.9.9"},
	}
	if err := registry.Add(candidate); err != nil {
		t.Fatal(err)
	}
	candidate.IDs[0] = "198.51.100.1"
	candidate.Tags[0] = "caller-mutated"
	candidate.Upstreams[0] = "1.1.1.1"
	stored := registry.List()[0]
	if stored.IDs[0] != "192.0.2.1" || stored.Tags[0] != "original" || stored.Upstreams[0] != "9.9.9.9" {
		t.Fatalf("Add retained caller-owned state: %+v", stored)
	}

	updated := stored
	updated.Tags = []string{"updated"}
	updated.Upstreams = []string{"8.8.8.8"}
	if err := registry.Update(updated); err != nil {
		t.Fatal(err)
	}
	updated.Tags[0] = "caller-mutated-again"
	updated.Upstreams[0] = "1.0.0.1"
	stored = registry.List()[0]
	if stored.Tags[0] != "updated" || stored.Upstreams[0] != "8.8.8.8" {
		t.Fatalf("Update retained caller-owned state: %+v", stored)
	}
}

func TestLongestPrefixMatch(t *testing.T) {
	r, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	add := func(name string, ids ...string) {
		t.Helper()
		if err := r.Add(Client{Name: name, IDs: ids}); err != nil {
			t.Fatalf("Add %s: %v", name, err)
		}
	}
	add("broad", "10.0.0.0/8")
	add("subnet", "10.1.2.0/24")
	add("host", "10.1.2.3")
	add("v6", "fd00::/64")

	tests := []struct {
		ip, want string
	}{
		{"10.1.2.3", "host"},   // exact /32 wins
		{"10.1.2.9", "subnet"}, // /24 wins over /8
		{"10.9.9.9", "broad"},
		{"fd00::1234", "v6"},
		{"192.168.0.1", ""}, // no match
	}
	for _, tt := range tests {
		got := r.Find(tt.ip)
		gotName := ""
		if got != nil {
			gotName = got.Name
		}
		if gotName != tt.want {
			t.Errorf("Find(%q) = %q, want %q", tt.ip, gotName, tt.want)
		}
	}
	if r.Find("not-an-ip") != nil {
		t.Error("invalid IP must not match")
	}
}

func TestClientJSONDefaultsGlobalSettings(t *testing.T) {
	var client Client
	if err := json.Unmarshal([]byte(`{"name":"legacy","ids":["192.0.2.1"]}`), &client); err != nil {
		t.Fatal(err)
	}
	if !client.UseGlobalSettings {
		t.Fatal("omitted use_global_settings should default true")
	}
}

func TestRegistryHotReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "clients.json")
	r, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Add(Client{Name: "before", IDs: []string{"10.0.0.1"}}); err != nil {
		t.Fatal(err)
	}

	// External edit → reload() picks it up.
	content := `[{"name":"after","ids":["10.0.0.2"],"use_global_settings":true}]`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	r.reload()
	if r.Find("10.0.0.2") == nil || r.Find("10.0.0.1") != nil {
		t.Error("hot-reload did not swap the registry")
	}

	// Corrupt file → keep current.
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	r.reload()
	if r.Find("10.0.0.2") == nil {
		t.Error("corrupt reload must keep last good")
	}
}

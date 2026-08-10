package clients

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

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
	updated.BlockedServices = []string{"tiktok"}
	updated.UseGlobalSettings = false
	if err := r2.Update(updated); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if got := r2.Find("192.168.1.50"); got == nil || len(got.BlockedServices) != 1 {
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

func TestScheduleActive(t *testing.T) {
	// 2024-01-01 was a Monday. Times are local wall-clock (schedule default TZ).
	mon := func(hhmm string) time.Time {
		t.Helper()
		ts, err := time.ParseInLocation("2006-01-02 15:04", "2024-01-01 "+hhmm, time.Local)
		if err != nil {
			t.Fatal(err)
		}
		return ts
	}

	var nilSched *Schedule
	if !nilSched.Active(mon("03:00")) {
		t.Error("nil schedule must always be active")
	}

	s := &Schedule{Days: map[string][]TimeRange{
		"mon": {{Start: "09:00", End: "17:00"}},
	}}
	if !s.Active(mon("10:00")) || !s.Active(mon("09:00")) {
		t.Error("inside window must be active")
	}
	if s.Active(mon("17:00")) || s.Active(mon("08:59")) {
		t.Error("outside window must be inactive")
	}
	// Tuesday: not listed → inactive.
	tue := mon("10:00").AddDate(0, 0, 1)
	if s.Active(tue) {
		t.Error("unlisted day must be inactive")
	}

	// Overnight window.
	on := &Schedule{Days: map[string][]TimeRange{
		"mon": {{Start: "22:00", End: "06:00"}},
	}}
	if !on.Active(mon("23:30")) || !on.Active(mon("05:59")) {
		t.Error("overnight window must cover past-midnight hours")
	}
	if on.Active(mon("12:00")) {
		t.Error("midday must be inactive for overnight window")
	}

	equal := &Schedule{Days: map[string][]TimeRange{
		"mon": {{Start: "09:00", End: "09:00"}},
	}}
	if equal.Active(mon("09:00")) || equal.Active(mon("12:00")) {
		t.Error("equal schedule endpoints must be inactive")
	}
}

func TestSchedulePreviousDayOvernightAndValidation(t *testing.T) {
	location, err := time.LoadLocation("Europe/Vienna")
	if err != nil {
		t.Fatal(err)
	}
	schedule := &Schedule{Timezone: "Europe/Vienna", Days: map[string][]TimeRange{
		"mon": {{Start: "22:00", End: "02:00"}},
	}}
	tuesday := time.Date(2024, time.January, 2, 1, 0, 0, 0, location)
	if !schedule.Active(tuesday) {
		t.Fatal("Monday overnight schedule should remain active early Tuesday")
	}
	bad := Client{Name: "bad", IDs: []string{"192.0.2.1"}, Schedule: &Schedule{Timezone: "Not/AZone"}}
	if err := bad.compile(); err == nil {
		t.Fatal("invalid timezone passed validation")
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

package rewrites

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestStoreCRUDAndPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rewrites.json")

	s, err := Load(path, "")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(s.List()) != 0 {
		t.Fatal("new store must be empty")
	}

	rw, err := s.Add("Example.COM.", "a", "192.0.2.1", "192.0.2.44/24", "192.0.2.0/24")
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if rw.Domain != "example.com" || rw.Type != TypeA || rw.ID == "" {
		t.Errorf("unexpected rewrite normalization: %+v", rw)
	}
	if len(rw.SourceCIDRs) != 1 || rw.SourceCIDRs[0] != "192.0.2.0/24" {
		t.Errorf("source CIDR normalization = %v", rw.SourceCIDRs)
	}
	if _, err := s.Add("bad", "A", "not-an-ip"); err == nil {
		t.Error("expected validation error for bad IPv4")
	}
	if _, err := s.Add("x.com", "BOGUS", "v"); err == nil {
		t.Error("expected validation error for unknown type")
	}

	// Persistence: reload and verify.
	s2, err := Load(path, "")
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	items := s2.List()
	if len(items) != 1 || items[0].Domain != "example.com" || len(items[0].SourceCIDRs) != 1 {
		t.Fatalf("reloaded items: %+v", items)
	}

	// Delete.
	if found, err := s2.Delete(items[0].ID); err != nil || !found {
		t.Error("Delete returned false for existing ID")
	}
	if found, err := s2.Delete(items[0].ID); err != nil || found {
		t.Error("Delete returned true for missing ID")
	}
	s3, err := Load(path, "")
	if err != nil {
		t.Fatalf("reload after delete: %v", err)
	}
	if len(s3.List()) != 0 {
		t.Error("delete was not persisted")
	}
}

func TestStoreUpdateAndPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rewrites.json")
	store, err := Load(path, "example.com:192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	originalID := store.List()[0].ID
	updated, found, err := store.Update(originalID, "Updated.Example.", "AAAA", "2001:db8::10", "100.100.1.1/10")
	if err != nil || !found {
		t.Fatalf("Update() = %+v, found %v, err %v", updated, found, err)
	}
	if updated.ID != originalID || updated.Domain != "updated.example" || updated.Type != TypeAAAA ||
		updated.Value != "2001:db8::10" || len(updated.SourceCIDRs) != 1 || updated.SourceCIDRs[0] != "100.64.0.0/10" {
		t.Fatalf("updated rewrite = %+v", updated)
	}

	store, err = Load(path, "")
	if err != nil {
		t.Fatalf("reload after update: %v", err)
	}
	items := store.List()
	if len(items) != 1 || items[0].ID != originalID || items[0].Domain != "updated.example" {
		t.Fatalf("update was not persisted: %+v", items)
	}
	if _, found, err := store.Update("missing", "missing.example", "A", "192.0.2.2"); err != nil || found {
		t.Fatalf("Update() missing ID = found %v, err %v; want false, nil", found, err)
	}
}

func TestDeleteReturnsPersistenceErrorAndRollsBack(t *testing.T) {
	store, err := Load("", "")
	if err != nil {
		t.Fatal(err)
	}
	rewrite, err := store.Add("example.test", "A", "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	store.path = filepath.Join(t.TempDir(), "missing", "rewrites.json")
	found, err := store.Delete(rewrite.ID)
	if !found || err == nil {
		t.Fatalf("Delete() = found %v, err %v; want true and persistence error", found, err)
	}
	if len(store.List()) != 1 {
		t.Fatal("failed delete was not rolled back")
	}
}

func TestReplaceDoesNotPublishBeforePersistence(t *testing.T) {
	store, err := Load("", "example.test:192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	store.path = filepath.Join(t.TempDir(), "missing", "rewrites.json")
	if err := store.Replace([]Rewrite{{Domain: "new.example", Type: TypeA, Value: "192.0.2.2"}}); err == nil {
		t.Fatal("Replace() succeeded with an unwritable persistence path")
	}
	items := store.List()
	if len(items) != 1 || items[0].Domain != "example.test" {
		t.Fatalf("failed replacement was published: %+v", items)
	}
}

func TestUpdateDoesNotPublishBeforePersistence(t *testing.T) {
	store, err := Load("", "example.test:192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	original := store.List()[0]
	store.path = filepath.Join(t.TempDir(), "missing", "rewrites.json")
	_, found, err := store.Update(original.ID, "updated.example", TypeA, "192.0.2.2")
	if !found || err == nil {
		t.Fatalf("Update() = found %v, err %v; want true and persistence error", found, err)
	}
	items := store.List()
	if len(items) != 1 || items[0].ID != original.ID || items[0].Domain != original.Domain || items[0].Value != original.Value {
		t.Fatalf("failed update was published: %+v", items)
	}
}

func TestLoadSeedsFromDomainsOnce(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rewrites.json")

	// First boot: file does not exist → seed from DOMAINS env.
	s, err := Load(path, "internal.net:100.1.2.3,.app.example.com:100.4.5.6,bogus")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	items := s.List()
	if len(items) != 2 {
		t.Fatalf("seeded items = %+v, want 2", items)
	}
	// List() sorts by domain: app.example.com before internal.net.
	if items[0].Type != TypeA || items[0].Domain != "app.example.com" || items[1].Domain != "internal.net" {
		t.Errorf("unexpected seeds: %+v", items)
	}
	if _, err := os.Stat(path); err != nil {
		t.Error("seeds were not persisted")
	}

	// Second boot: file exists → env is ignored entirely.
	s2, err := Load(path, "different.example:1.1.1.1")
	if err != nil {
		t.Fatalf("second Load: %v", err)
	}
	if len(s2.List()) != 2 {
		t.Errorf("second boot re-seeded: %+v", s2.List())
	}
	for _, rw := range s2.List() {
		if rw.Domain == "different.example" {
			t.Error("DOMAINS env overwrote existing rewrites file")
		}
	}
}

func TestLookupMatching(t *testing.T) {
	s, err := Load("", "example.com:192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Add("example.com", "TXT", "v=spf1 -all"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Add("other.org", "A", "192.0.2.2"); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		domain string
		want   int
	}{
		{"example.com", 2},          // A + TXT
		{"sub.example.com", 2},      // subdomain inherits both
		{"deep.sub.example.com", 2}, // any depth
		{"notexample.com", 0},       // label boundary
		{"example.com.evil.net", 0},
		{"other.org", 1},
		{"unrelated.net", 0},
	}
	for _, tt := range tests {
		if got := len(s.Lookup(tt.domain)); got != tt.want {
			t.Errorf("Lookup(%q) = %d rewrites, want %d", tt.domain, got, tt.want)
		}
	}
}

func TestLookupWildcardAndDomainSpecificity(t *testing.T) {
	s, err := Load("", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range []Rewrite{
		{Domain: "*.example.com", Type: TypeA, Value: "192.0.2.1"},
		{Domain: "home.example.com", Type: TypeA, Value: "192.0.2.2"},
		{Domain: "home.example.com", Type: TypeA, Value: "192.0.2.3"},
		{Domain: "*.lab.example.com", Type: TypeA, Value: "192.0.2.4"},
	} {
		if _, err := s.Add(item.Domain, item.Type, item.Value); err != nil {
			t.Fatalf("Add(%q): %v", item.Domain, err)
		}
	}

	tests := []struct {
		name   string
		domain string
		want   []string
	}{
		{name: "wildcard excludes apex", domain: "example.com"},
		{name: "wildcard matches one label", domain: "printer.example.com", want: []string{"192.0.2.1"}},
		{name: "wildcard matches multiple labels", domain: "deep.printer.example.com", want: []string{"192.0.2.1"}},
		{name: "exact domain takes priority", domain: "home.example.com", want: []string{"192.0.2.2", "192.0.2.3"}},
		{name: "more specific wildcard takes priority", domain: "printer.lab.example.com", want: []string{"192.0.2.4"}},
		{name: "specific wildcard excludes its apex", domain: "lab.example.com", want: []string{"192.0.2.1"}},
		{name: "label boundary", domain: "notexample.com"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := s.Lookup(test.domain)
			if len(got) != len(test.want) {
				t.Fatalf("Lookup(%q) = %+v, want values %v", test.domain, got, test.want)
			}
			for i, item := range got {
				if item.Value != test.want[i] {
					t.Errorf("Lookup(%q)[%d].Value = %q, want %q", test.domain, i, item.Value, test.want[i])
				}
			}
		})
	}
}

func TestLookupForClientPrefersNarrowestSource(t *testing.T) {
	s, err := Load("", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range []Rewrite{
		{Domain: "service.example", Type: TypeA, Value: "192.0.2.1"},
		{Domain: "service.example", Type: TypeA, Value: "192.0.2.2", SourceCIDRs: []string{"100.64.0.0/10"}},
		{Domain: "service.example", Type: TypeA, Value: "192.0.2.3", SourceCIDRs: []string{"100.100.0.0/16"}},
		{Domain: "service.example", Type: TypeA, Value: "192.0.2.4", SourceCIDRs: []string{"100.100.0.0/16"}},
	} {
		if _, err := s.Add(item.Domain, item.Type, item.Value, item.SourceCIDRs...); err != nil {
			t.Fatalf("Add(%q, %q): %v", item.Domain, item.Value, err)
		}
	}

	tests := []struct {
		name     string
		clientIP string
		want     []string
	}{
		{name: "outside uses all clients", clientIP: "192.168.1.20", want: []string{"192.0.2.1"}},
		{name: "tailnet scope overrides all clients", clientIP: "100.101.1.20", want: []string{"192.0.2.2"}},
		{name: "narrow subnet overrides tailnet", clientIP: "100.100.1.20", want: []string{"192.0.2.3", "192.0.2.4"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := s.LookupForClient("service.example", test.clientIP)
			if len(got) != len(test.want) {
				t.Fatalf("LookupForClient(%q) = %+v, want values %v", test.clientIP, got, test.want)
			}
			for i, item := range got {
				if item.Value != test.want[i] {
					t.Errorf("LookupForClient(%q)[%d].Value = %q, want %q", test.clientIP, i, item.Value, test.want[i])
				}
			}
		})
	}
}

func TestLookupForClientFallsBackWhenSpecificScopeDoesNotMatch(t *testing.T) {
	s, err := Load("", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Add("*.example.com", TypeA, "192.0.2.1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Add("home.example.com", TypeA, "192.0.2.2", "100.64.0.0/10"); err != nil {
		t.Fatal(err)
	}

	outside := s.LookupForClient("home.example.com", "192.168.1.20")
	if len(outside) != 1 || outside[0].Value != "192.0.2.1" {
		t.Fatalf("outside client lookup = %+v, want wildcard fallback", outside)
	}
	tailnet := s.LookupForClient("home.example.com", "100.100.1.20")
	if len(tailnet) != 1 || tailnet[0].Value != "192.0.2.2" {
		t.Fatalf("tailnet client lookup = %+v, want exact scoped rewrite", tailnet)
	}
}

func TestLookupFiltersBySourceCIDR(t *testing.T) {
	s, err := Load("", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Add(
		"tailnet.example",
		TypeA,
		"192.0.2.10",
		"100.64.0.0/10",
		"fd7a:115c:a1e0::/48",
	); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Add("all.example", TypeA, "192.0.2.11"); err != nil {
		t.Fatal(err)
	}
	if got := len(s.Lookup("tailnet.example")); got != 1 {
		t.Fatalf("unfiltered Lookup returned %d rewrites, want 1", got)
	}

	tests := []struct {
		name     string
		domain   string
		clientIP string
		want     int
	}{
		{name: "tailscale IPv4", domain: "tailnet.example", clientIP: "100.100.10.20", want: 1},
		{name: "mapped tailscale IPv4", domain: "tailnet.example", clientIP: "::ffff:100.100.10.20", want: 1},
		{name: "tailscale IPv6", domain: "tailnet.example", clientIP: "fd7a:115c:a1e0::1234", want: 1},
		{name: "outside subnet", domain: "tailnet.example", clientIP: "192.168.1.20", want: 0},
		{name: "invalid client", domain: "tailnet.example", clientIP: "not-an-ip", want: 0},
		{name: "unrestricted", domain: "all.example", clientIP: "192.168.1.20", want: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := len(s.LookupForClient(test.domain, test.clientIP)); got != test.want {
				t.Fatalf("LookupForClient(%q, %q) = %d, want %d", test.domain, test.clientIP, got, test.want)
			}
		})
	}

	items := s.List()
	items[1].SourceCIDRs[0] = "0.0.0.0/0"
	if got := len(s.LookupForClient("tailnet.example", "192.168.1.20")); got != 0 {
		t.Fatal("List returned mutable source CIDR state")
	}
	if _, err := s.Add("invalid.example", TypeA, "192.0.2.12", "not-a-cidr"); err == nil {
		t.Fatal("Add accepted an invalid source CIDR")
	}
}

func TestBuildRRPerType(t *testing.T) {
	const name = "example.com."
	tests := []struct {
		typ, value string
		qtype      uint16
		wantNil    bool
	}{
		{TypeA, "192.0.2.1", dns.TypeA, false},
		{TypeA, "192.0.2.1", dns.TypeAAAA, true}, // type mismatch
		{TypeA, "::1", dns.TypeA, true},          // wrong family
		{TypeAAAA, "2001:db8::1", dns.TypeAAAA, false},
		{TypeAAAA, "192.0.2.1", dns.TypeAAAA, true},
		{TypeCNAME, "target.example.net", dns.TypeA, false},
		{TypePTR, "host.example.net", dns.TypePTR, false},
		{TypeMX, "10 mail.example.net", dns.TypeMX, false},
		{TypeMX, "notanumber mail.example.net", dns.TypeMX, true},
		{TypeTXT, "hello world", dns.TypeTXT, false},
		{TypeSRV, "0 5 5060 sip.example.net", dns.TypeSRV, false},
		{TypeSRV, "0 5 bad sip.example.net", dns.TypeSRV, true},
	}
	for _, tt := range tests {
		rw := Rewrite{Domain: "example.com", Type: tt.typ, Value: tt.value}
		rr := rw.BuildRR(name, tt.qtype)
		if (rr == nil) != tt.wantNil {
			t.Errorf("BuildRR(%s %s, qtype %d) nil = %v, want %v", tt.typ, tt.value, tt.qtype, rr == nil, tt.wantNil)
			continue
		}
		if rr != nil {
			if rr.Header().Ttl != AnswerTTL {
				t.Errorf("%s: TTL = %d, want %d", tt.typ, rr.Header().Ttl, AnswerTTL)
			}
			if rr.Header().Name != name {
				t.Errorf("%s: name = %q, want %q", tt.typ, rr.Header().Name, name)
			}
		}
	}
}

func TestValidate(t *testing.T) {
	valid := []struct{ domain, typ, value string }{
		{"example.com", TypeA, "192.0.2.1"},
		{"*.example.com", TypeA, "192.0.2.1"},
		{"example.com", TypeAAAA, "2001:db8::1"},
		{"example.com", TypeCNAME, "target.example.net"},
		{"example.com", TypePTR, "host.example.net"},
		{"example.com", TypeMX, "10 mail.example.net"},
		{"example.com", TypeTXT, "text"},
		{"_sip._tcp.example.com", TypeSRV, "0 5 5060 sip.example.net"},
		{"example.com", TypeNXDOMAIN, ""},
		{"example.com", TypeREFUSED, ""},
		{"example.com", TypeNOERROR, ""},
	}
	for _, v := range valid {
		if err := Validate(v.domain, v.typ, v.value); err != nil {
			t.Errorf("Validate(%+v) unexpected error: %v", v, err)
		}
	}

	invalid := []struct{ domain, typ, value string }{
		{"", TypeA, "192.0.2.1"},
		{".example.com", TypeA, "192.0.2.1"},
		{".*.example.com", TypeA, "192.0.2.1"},
		{"*example.com", TypeA, "192.0.2.1"},
		{"*..example.com", TypeA, "192.0.2.1"},
		{"foo.*.example.com", TypeA, "192.0.2.1"},
		{"example.com", TypeA, "999.1.1.1"},
		{"example.com", TypeAAAA, "192.0.2.1"},
		{"example.com", TypeCNAME, ""},
		{"example.com", TypeMX, "garbage"},
		{"example.com", TypeTXT, ""},
		{"example.com", TypeTXT, strings.Repeat("é", 128)},
		{"example.com", TypeSRV, "1 2 3"},
		{"example.com", "WKS", "x"},
	}
	for _, v := range invalid {
		if err := Validate(v.domain, v.typ, v.value); err == nil {
			t.Errorf("Validate(%+v) expected error", v)
		}
	}
}

func TestAddRejectsLeadingDotDomains(t *testing.T) {
	s, err := Load("", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, domain := range []string{".example.com", ".*.example.com"} {
		if _, err := s.Add(domain, TypeA, "192.0.2.1"); err == nil {
			t.Errorf("Add(%q) expected error", domain)
		}
	}
}

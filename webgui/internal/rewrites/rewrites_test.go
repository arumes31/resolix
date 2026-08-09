package rewrites

import (
	"os"
	"path/filepath"
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

	rw, err := s.Add("Example.COM.", "a", "192.0.2.1")
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if rw.Domain != "example.com" || rw.Type != TypeA || rw.ID == "" {
		t.Errorf("unexpected rewrite normalization: %+v", rw)
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
	if len(items) != 1 || items[0].Domain != "example.com" {
		t.Fatalf("reloaded items: %+v", items)
	}

	// Delete.
	if !s2.Delete(items[0].ID) {
		t.Error("Delete returned false for existing ID")
	}
	if s2.Delete(items[0].ID) {
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
		{"example.com", TypeA, "999.1.1.1"},
		{"example.com", TypeAAAA, "192.0.2.1"},
		{"example.com", TypeCNAME, ""},
		{"example.com", TypeMX, "garbage"},
		{"example.com", TypeTXT, ""},
		{"example.com", TypeSRV, "1 2 3"},
		{"example.com", "WKS", "x"},
	}
	for _, v := range invalid {
		if err := Validate(v.domain, v.typ, v.value); err == nil {
			t.Errorf("Validate(%+v) expected error", v)
		}
	}
}

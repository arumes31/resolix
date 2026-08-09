package policy

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

func TestSafeSearchTargets(t *testing.T) {
	p := New(Config{SafeSearch: []string{"google", "bing", "ddg", "youtube"}})

	tests := []struct {
		domain string
		want   string
	}{
		// google: apex + www.google.<TLD> + google.<TLD> variants
		{"google.com", googleTarget},
		{"www.google.com", googleTarget},
		{"www.google.de", googleTarget},
		{"www.google.co.uk", googleTarget},
		{"google.fr", googleTarget},
		{"google.evil.example", ""},
		{"google.com.attacker.example", ""},
		{"mail.google.com", ""}, // not a search frontend
		// bing
		{"www.bing.com", bingTarget},
		{"bing.com", bingTarget},
		{"cn.bing.com", ""},
		// duckduckgo
		{"duckduckgo.com", ddgTarget},
		{"www.duckduckgo.com", ddgTarget},
		{"api.duckduckgo.com", ""},
		// youtube
		{"www.youtube.com", youtubeTarget},
		{"m.youtube.com", youtubeTarget},
		{"youtube.com", youtubeTarget},
		{"youtubei.googleapis.com", youtubeTarget},
		{"youtube.googleapis.com", youtubeTarget},
		{"www.youtube-nocookie.com", youtubeTarget},
		{"music.youtube.com", ""},
		{"googleapis.com", ""},
		// unrelated
		{"example.com", ""},
	}
	for _, tt := range tests {
		if got := p.SafeSearchTarget(tt.domain); got != tt.want {
			t.Errorf("SafeSearchTarget(%q) = %q, want %q", tt.domain, got, tt.want)
		}
	}
}

func TestSafeSearchEngineSubset(t *testing.T) {
	p := New(Config{SafeSearch: []string{"google"}})
	if got := p.SafeSearchTarget("www.google.com"); got != googleTarget {
		t.Errorf("google engine off: got %q", got)
	}
	if got := p.SafeSearchTarget("www.bing.com"); got != "" {
		t.Errorf("bing must be disabled, got %q", got)
	}
	if got := p.SafeSearchTarget("www.youtube.com"); got != "" {
		t.Errorf("youtube must be disabled, got %q", got)
	}

	none := New(Config{})
	if got := none.SafeSearchTarget("www.google.com"); got != "" {
		t.Errorf("no engines: got %q", got)
	}
}

func TestIsBogusAnswer(t *testing.T) {
	a := func(ip string) *dns.A {
		return &dns.A{Hdr: dns.RR_Header{Name: "x.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP(ip).To4()}
	}
	p := New(Config{BogusNets: []string{"10.0.0.0/8", "192.0.2.33"}})

	tests := []struct {
		name    string
		answers []dns.RR
		want    bool
	}{
		{"all in range", []dns.RR{a("10.1.2.3"), a("10.9.9.9")}, true},
		{"single host entry", []dns.RR{a("192.0.2.33")}, true},
		{"mixed in/out", []dns.RR{a("10.1.2.3"), a("93.184.216.34")}, false},
		{"all out of range", []dns.RR{a("93.184.216.34")}, false},
		{"empty answers", nil, false},
	}
	for _, tt := range tests {
		if got := p.IsBogusAnswer(tt.answers); got != tt.want {
			t.Errorf("%s: IsBogusAnswer = %v, want %v", tt.name, got, tt.want)
		}
	}

	// No bogus nets configured → never bogus.
	empty := New(Config{})
	if empty.IsBogusAnswer([]dns.RR{a("10.1.2.3")}) {
		t.Error("no bogus nets: expected false")
	}
}

func TestPolicyFlags(t *testing.T) {
	p := New(Config{AAAADisabled: true, RefuseANY: true})
	if !p.AAAADisabledEnabled() || !p.RefuseANYEnabled() {
		t.Error("flags should be enabled")
	}
	off := New(Config{})
	if off.AAAADisabledEnabled() || off.RefuseANYEnabled() {
		t.Error("flags should be disabled")
	}
	var nilPolicy *Policy
	if nilPolicy.Enabled() || nilPolicy.AAAADisabledEnabled() || nilPolicy.RefuseANYEnabled() || nilPolicy.IsBogusAnswer(nil) {
		t.Error("nil policy must be inert")
	}
}

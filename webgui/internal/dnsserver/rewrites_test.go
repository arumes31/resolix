package dnsserver

import (
	"testing"
)

func TestParseStaticHosts(t *testing.T) {
	tests := []struct {
		name    string
		env     string
		want    map[string]string // domain → expected IP string (empty map value = key absent)
		wantLen int
	}{
		{
			name:    "empty",
			env:     "",
			wantLen: 0,
		},
		{
			name:    "single",
			env:     "internal.net:100.1.2.3",
			want:    map[string]string{"internal.net": "100.1.2.3"},
			wantLen: 1,
		},
		{
			name:    "leading dot stripped",
			env:     ".internal.net:100.1.2.3",
			want:    map[string]string{"internal.net": "100.1.2.3"},
			wantLen: 1,
		},
		{
			name:    "multiple with spaces",
			env:     "a.com:1.2.3.4, b.com:5.6.7.8",
			want:    map[string]string{"a.com": "1.2.3.4", "b.com": "5.6.7.8"},
			wantLen: 2,
		},
		{
			name:    "invalid entries skipped",
			env:     "no-ip-part,badip:999.1.1.1,ipv6:::1,ok.com:9.9.9.9",
			want:    map[string]string{"ok.com": "9.9.9.9"},
			wantLen: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hosts := ParseStaticHosts(tt.env)
			if len(hosts) != tt.wantLen {
				t.Fatalf("ParseStaticHosts(%q) len = %d, want %d (%v)", tt.env, len(hosts), tt.wantLen, hosts)
			}
			for domain, wantIP := range tt.want {
				ip, ok := hosts[domain]
				if !ok {
					t.Errorf("missing domain %q", domain)
					continue
				}
				if ip.String() != wantIP {
					t.Errorf("hosts[%q] = %s, want %s", domain, ip, wantIP)
				}
			}
		})
	}
}

func TestMatchStatic(t *testing.T) {
	hosts := ParseStaticHosts("internal.net:100.1.2.3,app.example.com:100.4.5.6")

	tests := []struct {
		name    string
		query   string
		wantHit bool
		wantIP  string
	}{
		{"apex match", "internal.net", true, "100.1.2.3"},
		{"subdomain match", "foo.internal.net", true, "100.1.2.3"},
		{"deep subdomain match", "a.b.c.internal.net", true, "100.1.2.3"},
		{"second entry apex", "app.example.com", true, "100.4.5.6"},
		{"second entry subdomain", "www.app.example.com", true, "100.4.5.6"},
		{"label-boundary no match", "notinternal.net", false, ""},
		{"suffix of name no match", "internal.net.evil.com", false, ""},
		{"unrelated no match", "example.org", false, ""},
		{"empty name", "", false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := matchStatic(hosts, tt.query)
			if tt.wantHit {
				if ip == nil || ip.String() != tt.wantIP {
					t.Errorf("matchStatic(%q) = %v, want %s", tt.query, ip, tt.wantIP)
				}
			} else if ip != nil {
				t.Errorf("matchStatic(%q) = %v, want nil", tt.query, ip)
			}
		})
	}

	if ip := matchStatic(nil, "internal.net"); ip != nil {
		t.Error("nil map must not match")
	}
}

func TestNormalizeUpstream(t *testing.T) {
	tests := []struct {
		in     string
		want   string
		wantOK bool
	}{
		{"8.8.8.8", "8.8.8.8:53", true},
		{"8.8.8.8#5353", "8.8.8.8:5353", true},
		{"8.8.8.8:5353", "8.8.8.8:5353", true},
		{" 1.1.1.1 ", "1.1.1.1:53", true},
		{"::1", "[::1]:53", true},
		{"", "", false},
		{"not-an-ip", "", false},
		{"8.8.8.8:", "", false},
	}
	for _, tt := range tests {
		got, ok := normalizeUpstream(tt.in)
		if ok != tt.wantOK || got != tt.want {
			t.Errorf("normalizeUpstream(%q) = (%q, %v), want (%q, %v)", tt.in, got, ok, tt.want, tt.wantOK)
		}
	}
}

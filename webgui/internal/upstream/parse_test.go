package upstream

import (
	"testing"
)

func TestParse(t *testing.T) {
	tests := []struct {
		in      string
		scheme  string
		host    string
		port    string
		path    string
		wantErr bool
	}{
		{"8.8.8.8", "udp", "8.8.8.8", "53", "", false},
		{"8.8.8.8:5353", "udp", "8.8.8.8", "5353", "", false},
		{"8.8.8.8#5353", "udp", "8.8.8.8", "5353", "", false},
		{"::1", "udp", "::1", "53", "", false},
		{"udp://1.1.1.1", "udp", "1.1.1.1", "53", "", false},
		{"tcp://1.1.1.1:5353", "tcp", "1.1.1.1", "5353", "", false},
		{"tls://dns.google", "tls", "dns.google", "853", "", false},
		{"tls://1.1.1.1:8853", "tls", "1.1.1.1", "8853", "", false},
		{"https://dns.google/dns-query", "https", "dns.google", "443", "/dns-query", false},
		{"https://1.1.1.1", "https", "1.1.1.1", "443", "/dns-query", false},
		{"https://1.1.1.1:4443/custom", "https", "1.1.1.1", "4443", "/custom", false},
		{"dns.google", "", "", "", "", true},        // hostname without scheme
		{"quic://dns.google", "", "", "", "", true}, // unsupported scheme
		{"https://", "", "", "", "", true},
		{"", "", "", "", "", true},
	}
	for _, tt := range tests {
		spec, err := Parse(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Errorf("Parse(%q) expected error, got %+v", tt.in, spec)
			}
			continue
		}
		if err != nil {
			t.Errorf("Parse(%q) unexpected error: %v", tt.in, err)
			continue
		}
		if spec.Scheme != tt.scheme || spec.Host != tt.host || spec.Port != tt.port || spec.Path != tt.path {
			t.Errorf("Parse(%q) = %+v, want scheme=%s host=%s port=%s path=%s",
				tt.in, spec, tt.scheme, tt.host, tt.port, tt.path)
		}
		if spec.String() != tt.in {
			t.Errorf("Parse(%q).String() = %q", tt.in, spec.String())
		}
	}
}

func TestSpecHostname(t *testing.T) {
	ipSpec, _ := Parse("8.8.8.8")
	if ipSpec.Hostname() {
		t.Error("IP literal must not need bootstrap")
	}
	nameSpec, _ := Parse("tls://dns.google")
	if !nameSpec.Hostname() {
		t.Error("dns.google must need bootstrap")
	}
}

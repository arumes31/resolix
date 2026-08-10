// Package upstream implements upstream DNS resolvers (plain UDP/TCP, DoT,
// DoH) with bootstrap DNS, pooling (strict/parallel/load-balance modes),
// fallback upstreams, per-upstream latency stats, ECS, and DNS64 synthesis.
package upstream

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Scheme identifiers for upstream specs.
const (
	SchemeUDP   = "udp"
	SchemeTCP   = "tcp"
	SchemeTLS   = "tls"
	SchemeHTTPS = "https"
)

// Spec is a parsed upstream address.
type Spec struct {
	Scheme string // udp | tcp | tls | https
	Host   string // IP or hostname
	Port   string // always populated (53/853/443 defaults)
	Path   string // DoH path (default /dns-query)
	Raw    string // original spec string
}

// Hostname reports whether the spec's host is a DNS name (not an IP literal)
// and therefore needs bootstrap resolution.
func (s Spec) Hostname() bool {
	return net.ParseIP(s.Host) == nil
}

// String returns the original spec string when available, or a canonical
// representation for programmatically constructed specs.
func (s Spec) String() string {
	if s.Raw != "" {
		return s.Raw
	}
	result := s.Scheme + "://" + net.JoinHostPort(s.Host, s.Port)
	if s.Scheme == SchemeHTTPS {
		result += s.Path
	}
	return result
}

// Parse parses an upstream spec:
//
//	plain:   8.8.8.8, 8.8.8.8:5353, 8.8.8.8#5353 (UDP with TCP truncation fallback)
//	udp://8.8.8.8[:53]
//	tcp://8.8.8.8[:53]
//	tls://dns.google[:853]     (DoT; ServerName from host)
//	https://dns.google[:443][/dns-query]  (DoH, RFC 8484)
//
// Plain (schemeless) specs require an IP literal; hostname upstreams must use
// an explicit scheme so bootstrap handling is unambiguous.
func Parse(raw string) (Spec, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return Spec{}, fmt.Errorf("empty upstream spec")
	}

	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil {
			return Spec{}, fmt.Errorf("invalid upstream %q: %w", raw, err)
		}
		spec := Spec{Scheme: strings.ToLower(u.Scheme), Host: u.Hostname(), Port: u.Port(), Raw: raw}
		switch spec.Scheme {
		case SchemeUDP, SchemeTCP:
			if spec.Port == "" {
				spec.Port = "53"
			}
		case SchemeTLS:
			if spec.Port == "" {
				spec.Port = "853"
			}
		case SchemeHTTPS:
			if spec.Port == "" {
				spec.Port = "443"
			}
			spec.Path = u.Path
			if spec.Path == "" {
				spec.Path = "/dns-query"
			}
		default:
			return Spec{}, fmt.Errorf("unsupported upstream scheme %q in %q", u.Scheme, raw)
		}
		if spec.Host == "" {
			return Spec{}, fmt.Errorf("missing host in upstream %q", raw)
		}
		return spec, nil
	}

	// Plain formats: ip, ip:port, ip#port (dnsmasq style).
	normalized := raw
	if host, port, ok := strings.Cut(raw, "#"); ok {
		normalized = net.JoinHostPort(host, port)
	}
	host, port, err := net.SplitHostPort(normalized)
	if err != nil {
		if net.ParseIP(normalized) == nil {
			return Spec{}, fmt.Errorf("plain upstream %q must be an IP literal (use a scheme for hostnames)", raw)
		}
		return Spec{Scheme: SchemeUDP, Host: normalized, Port: "53", Raw: raw}, nil
	}
	if net.ParseIP(host) == nil {
		return Spec{}, fmt.Errorf("plain upstream %q must be an IP literal", raw)
	}
	if port == "" {
		port = "53"
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return Spec{}, fmt.Errorf("plain upstream %q has an invalid port", raw)
	}
	return Spec{Scheme: SchemeUDP, Host: host, Port: port, Raw: raw}, nil
}

// ValidateBootstrapServers requires plain UDP IP-literal resolvers. Allowing a
// hostname here would fall back to the operating-system resolver and defeat
// the bootstrap boundary for hostname-based DoT and DoH upstreams.
func ValidateBootstrapServers(servers []string) error {
	for index, raw := range servers {
		spec, err := Parse(raw)
		if err != nil {
			return fmt.Errorf("bootstrap resolver %d: %w", index+1, err)
		}
		if spec.Scheme != SchemeUDP {
			return fmt.Errorf("bootstrap resolver %d must use plain UDP", index+1)
		}
		if spec.Hostname() {
			return fmt.Errorf("bootstrap resolver %d must use an IP literal", index+1)
		}
	}
	return nil
}

// dialAddrs returns the host:port addresses to dial. For IP literals it is a
// single static address; for hostnames the bootstrapper supplies pinned IPs.
func (s Spec) dialAddrs(boot *bootstrapper) ([]string, error) {
	if !s.Hostname() {
		return []string{net.JoinHostPort(s.Host, s.Port)}, nil
	}
	if boot == nil {
		return nil, fmt.Errorf("upstream %q needs bootstrap DNS (BOOTSTRAP_DNS)", s.Raw)
	}
	ips, err := boot.Lookup(s.Host)
	if err != nil {
		return nil, err
	}
	addrs := make([]string, 0, len(ips))
	for _, ip := range ips {
		addrs = append(addrs, net.JoinHostPort(ip, s.Port))
	}
	return addrs, nil
}

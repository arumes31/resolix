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
	"time"
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
	Scheme  string        // udp | tcp | tls | https
	Host    string        // IP or hostname
	Port    string        // always populated (53/853/443 defaults)
	Path    string        // DoH path (default /dns-query)
	Query   string        // DoH endpoint query, excluding resolver options
	Timeout time.Duration // zero means the protocol default
	Weight  int           // zero means 1
	Raw     string        // original spec string
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
		if s.Query != "" {
			result += "?" + s.Query
		}
	}
	options := url.Values{}
	if s.Timeout > 0 {
		options.Set("timeout", s.Timeout.String())
	}
	if s.Weight > 1 {
		options.Set("weight", strconv.Itoa(s.Weight))
	}
	if encoded := options.Encode(); encoded != "" {
		separator := "?"
		if strings.Contains(result, "?") {
			separator = "&"
		}
		result += separator + encoded
	}
	return result
}

// TimeoutDuration returns the configured timeout or the protocol default.
func (s Spec) TimeoutDuration() time.Duration {
	if s.Timeout > 0 {
		return s.Timeout
	}
	if s.Scheme == SchemeHTTPS {
		return 20 * time.Second
	}
	return 5 * time.Second
}

// SelectionWeight returns the configured load-balancing weight.
func (s Spec) SelectionWeight() int {
	if s.Weight <= 0 {
		return 1
	}
	return s.Weight
}

// NormalizedKey identifies an endpoint independently of spelling and
// selection options. It is used to reject duplicate resolver entries.
func (s Spec) NormalizedKey() string {
	key := s.Scheme + "://" + net.JoinHostPort(strings.ToLower(strings.TrimSuffix(s.Host, ".")), s.Port)
	if s.Scheme == SchemeHTTPS {
		key += s.Path
		if s.Query != "" {
			key += "?" + s.Query
		}
	}
	return key
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
		return parseExplicitSpec(raw)
	}
	return parsePlainSpec(raw)
}

func parseExplicitSpec(raw string) (Spec, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return Spec{}, fmt.Errorf("invalid upstream %q: %w", raw, err)
	}
	spec := Spec{Scheme: strings.ToLower(u.Scheme), Host: strings.ToLower(strings.TrimSuffix(u.Hostname(), ".")), Port: u.Port(), Raw: raw}
	options := u.Query()
	if err := applyResolverOptions(raw, options, &spec); err != nil {
		return Spec{}, err
	}
	if err := applyResolverTransport(raw, u, options, &spec); err != nil {
		return Spec{}, err
	}
	if spec.Host == "" {
		return Spec{}, fmt.Errorf("missing host in upstream %q", raw)
	}
	portNumber, err := strconv.Atoi(spec.Port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return Spec{}, fmt.Errorf("upstream %q has an invalid port", raw)
	}
	return spec, nil
}

func applyResolverOptions(raw string, options url.Values, spec *Spec) error {
	if timeoutValue := options.Get("timeout"); timeoutValue != "" {
		timeout, err := time.ParseDuration(timeoutValue)
		if err != nil || timeout < 250*time.Millisecond || timeout > 60*time.Second {
			return fmt.Errorf("upstream %q timeout must be between 250ms and 60s", raw)
		}
		spec.Timeout = timeout
		options.Del("timeout")
	}
	if weightValue := options.Get("weight"); weightValue != "" {
		weight, err := strconv.Atoi(weightValue)
		if err != nil || weight < 1 || weight > 100 {
			return fmt.Errorf("upstream %q weight must be between 1 and 100", raw)
		}
		spec.Weight = weight
		options.Del("weight")
	}
	return nil
}

func applyResolverTransport(raw string, parsed *url.URL, options url.Values, spec *Spec) error {
	switch spec.Scheme {
	case SchemeUDP, SchemeTCP:
		if len(options) > 0 {
			return fmt.Errorf("upstream %q has unsupported query options", raw)
		}
		if spec.Port == "" {
			spec.Port = "53"
		}
	case SchemeTLS:
		if len(options) > 0 {
			return fmt.Errorf("upstream %q has unsupported query options", raw)
		}
		if spec.Port == "" {
			spec.Port = "853"
		}
	case SchemeHTTPS:
		if spec.Port == "" {
			spec.Port = "443"
		}
		spec.Path = parsed.Path
		if spec.Path == "" {
			spec.Path = "/dns-query"
		}
		spec.Query = options.Encode()
	default:
		return fmt.Errorf("unsupported upstream scheme %q in %q", parsed.Scheme, raw)
	}
	return nil
}

func parsePlainSpec(raw string) (Spec, error) {
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

// Normalize returns the canonical endpoint key for a resolver specification.
func Normalize(raw string) (string, error) {
	spec, err := Parse(raw)
	if err != nil {
		return "", err
	}
	return spec.NormalizedKey(), nil
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

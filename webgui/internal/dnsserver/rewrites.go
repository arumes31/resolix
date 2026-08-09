package dnsserver

import (
	"log"
	"net"
	"strings"
)

// ParseStaticHosts parses the DOMAINS env format (comma-separated
// domain:ip pairs) into a static-rewrite map. A leading dot on the domain is
// ignored, matching dnsmasq address=/ semantics. Only IPv4 addresses are
// accepted; invalid entries are skipped with a warning.
func ParseStaticHosts(domainsEnv string) map[string]net.IP {
	hosts := make(map[string]net.IP)
	for _, pair := range strings.Split(domainsEnv, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		domain, ipStr, ok := strings.Cut(pair, ":")
		if !ok {
			log.Printf("[WARN] Invalid DOMAINS entry (want domain:ip): %q", pair)
			continue
		}
		domain = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(domain), "."))
		ip := net.ParseIP(strings.TrimSpace(ipStr))
		if domain == "" || ip == nil || ip.To4() == nil {
			log.Printf("[WARN] Invalid DOMAINS entry (IPv4 only): %q", pair)
			continue
		}
		hosts[domain] = ip.To4()
	}
	return hosts
}

// matchStatic returns the rewrite IP when name equals the domain or any of
// its subdomains (apex + all-subdomains match, like dnsmasq address=/).
func matchStatic(hosts map[string]net.IP, name string) net.IP {
	if len(hosts) == 0 || name == "" {
		return nil
	}
	if ip, ok := hosts[name]; ok {
		return ip
	}
	for d := name; ; {
		dot := strings.IndexByte(d, '.')
		if dot < 0 {
			return nil
		}
		d = d[dot+1:]
		if ip, ok := hosts[d]; ok {
			return ip
		}
	}
}

// normalizeUpstream converts a raw UPSTREAM_DNS entry (plain ip, ip#port, or
// ip:port) into host:port form. The second return value is false for empty
// or invalid entries.
func normalizeUpstream(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false
	}
	// dnsmasq-style ip#port
	if host, port, ok := strings.Cut(raw, "#"); ok {
		raw = host + ":" + port
	}
	host, port, err := net.SplitHostPort(raw)
	if err != nil {
		// No port present — default to 53.
		if net.ParseIP(raw) == nil {
			return "", false
		}
		return net.JoinHostPort(raw, "53"), true
	}
	if net.ParseIP(host) == nil || port == "" {
		return "", false
	}
	return net.JoinHostPort(host, port), true
}

// normalizeName lowercases a DNS name and strips the trailing dot.
func normalizeName(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, "."))
}

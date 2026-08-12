package dnsserver

import (
	"net"
	"strings"

	"github.com/miekg/dns"
)

// privatePTRSuffix is appended to known client names in PTR answers.
const privatePTRSuffix = "lan"

// privateNets covers RFC1918, Tailscale CGNAT, and IPv6 ULA ranges.
var privateNets = mustCIDRs([]string{
	"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
	"100.64.0.0/10", "fc00::/7",
})

func mustCIDRs(raws []string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(raws))
	for _, raw := range raws {
		_, n, err := net.ParseCIDR(raw)
		if err != nil {
			panic(err)
		}
		out = append(out, n)
	}
	return out
}

// isPrivateIP reports whether ip is in a private/CGNAT/ULA range.
func isPrivateIP(ip net.IP) bool {
	for _, n := range privateNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// arpaToIP converts a PTR query name (in-addr.arpa / ip6.arpa) back to an IP.
func arpaToIP(name string) net.IP {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if suffix := ".in-addr.arpa"; strings.HasSuffix(name, suffix) {
		labels := strings.Split(strings.TrimSuffix(name, suffix), ".")
		if len(labels) != 4 {
			return nil
		}
		ip := make(net.IP, 4)
		for i, l := range labels {
			if len(l) == 0 || len(l) > 3 {
				return nil
			}
			var v int
			for _, c := range l {
				if c < '0' || c > '9' {
					return nil
				}
				v = v*10 + int(c-'0')
			}
			if v > 255 {
				return nil
			}
			ip[3-i] = byte(v)
		}
		return ip
	}
	if suffix := ".ip6.arpa"; strings.HasSuffix(name, suffix) {
		labels := strings.Split(strings.TrimSuffix(name, suffix), ".")
		if len(labels) != 32 {
			return nil
		}
		ip := make(net.IP, 16)
		for i, l := range labels {
			if len(l) != 1 {
				return nil
			}
			c := l[0]
			var v byte
			switch {
			case c >= '0' && c <= '9':
				v = c - '0'
			case c >= 'a' && c <= 'f':
				v = c - 'a' + 10
			default:
				return nil
			}
			nib := 31 - i
			if nib%2 == 0 {
				ip[nib/2] |= v << 4
			} else {
				ip[nib/2] |= v
			}
		}
		return ip
	}
	return nil
}

// ptrName resolves an IP to a known client name: clients registry first,
// then CLIENT_ALIASES, then the resolver rDNS cache.
func (s *Server) ptrName(ip string) string {
	if s.cfg.Clients != nil {
		if cl := s.cfg.Clients.Find(ip); cl != nil && cl.Name != "" {
			return cl.Name
		}
	}
	if s.cfg.AliasFunc != nil {
		if alias := s.cfg.AliasFunc(ip); alias != "" {
			return alias
		}
	}
	if s.cfg.ResolveClientHostnames && s.cfg.Resolver != nil {
		if host := s.cfg.Resolver.GetHostname(ip); host != "" {
			return host
		}
	}
	return ""
}

// sanitizePTRName makes a client name safe for use as a DNS label.
func sanitizePTRName(name string) string {
	var b strings.Builder
	for _, c := range strings.ToLower(name) {
		if b.Len() >= 63 {
			break
		}
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-':
			b.WriteRune(c)
		case c == ' ' || c == '_' || c == '.':
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

// stagePrivatePTR answers PTR queries for private-range addresses with a
// known client name, authoritatively ("<name>.lan."). Unknown names and
// public ranges fall through to normal forwarding.
func (s *Server) stagePrivatePTR(q dns.Question, resp *dns.Msg) (resolution, bool) {
	if !s.cfg.PrivatePTR || q.Qtype != dns.TypePTR {
		return resolution{}, false
	}
	ip := arpaToIP(q.Name)
	if ip == nil || !isPrivateIP(ip) {
		return resolution{}, false
	}
	name := sanitizePTRName(s.ptrName(ip.String()))
	if name == "" {
		// Unknown private client: forward normally.
		return resolution{}, false
	}
	resp.Answer = []dns.RR{&dns.PTR{
		Hdr: dns.RR_Header{
			Name:   q.Name,
			Rrtype: dns.TypePTR,
			Class:  dns.ClassINET,
			Ttl:    staticTTL,
		},
		Ptr: dns.Fqdn(name + "." + privatePTRSuffix),
	}}
	resp.Authoritative = true
	return resolution{
		upstream:    "Private PTR",
		matchedRule: name,
		blockReason: "PrivatePTR",
	}, true
}

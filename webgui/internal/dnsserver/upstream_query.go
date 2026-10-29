package dnsserver

import (
	"log"
	"strings"

	"github.com/miekg/dns"
)

func (s *Server) forward(r *dns.Msg, specs []string) (string, *dns.Msg) {
	// DNSSEC passthrough: set or clear the DO bit on a copy so the configured
	// toggle applies even when the client supplied its own OPT record.
	clientID := r.Id
	r = r.Copy()
	// Never reuse the client-chosen transaction ID upstream: a client that
	// knows the ID could race a forged answer into the shared cache.
	r.Id = dns.Id()
	if opt := r.IsEdns0(); opt != nil {
		opt.SetUDPSize(defaultEDNSUDPSize)
		opt.SetDo(s.cfg.DNSSEC)
	} else {
		r.SetEdns0(defaultEDNSUDPSize, s.cfg.DNSSEC)
	}
	if s.cfg.Pool != nil {
		if len(specs) > 0 {
			if m, used, err := s.cfg.Pool.ExchangeSpecs(specs, r); err == nil && acceptUpstreamReply(r, m, clientID) {
				return used, m
			}
			// Client upstreams failed: fall through to routes/global pool.
		}
		if s.cfg.Routes != nil && len(r.Question) > 0 {
			domain := normalizeName(r.Question[0].Name)
			if spec := s.cfg.Routes.GetUpstreamForDomain(domain); spec != "" {
				if m, used, err := s.cfg.Pool.ExchangeRoute(spec, r); err == nil && acceptUpstreamReply(r, m, clientID) {
					return used, m
				}
				// Route upstream failed: fall through to the general pool.
			}
		}
		m, used, err := s.cfg.Pool.Exchange(r)
		if err != nil || !acceptUpstreamReply(r, m, clientID) {
			return "", nil
		}
		return used, m
	}

	for _, up := range s.upstreams {
		m, _, err := s.client.Exchange(r, up)
		if err != nil || m == nil {
			log.Printf("[DEBUG] Upstream %s exchange failed: %v", up, err)
			continue
		}
		if m.Truncated {
			// Retry over TCP per DNS convention.
			tcpClient := &dns.Client{Net: "tcp", Timeout: upstreamTimeout}
			if tm, _, terr := tcpClient.Exchange(r, up); terr == nil && tm != nil {
				m = tm
			}
		}
		if !acceptUpstreamReply(r, m, clientID) {
			log.Printf("[DEBUG] Upstream %s returned a mismatched response", up)
			continue
		}
		return up, m
	}
	return "", nil
}

// acceptUpstreamReply reports whether m answers the exact query sent upstream
// (same transaction ID and question section). On success it restores the
// client's original transaction ID on m.
func acceptUpstreamReply(query, m *dns.Msg, clientID uint16) bool {
	if m == nil || m.Id != query.Id || len(m.Question) != len(query.Question) {
		return false
	}
	for i, q := range query.Question {
		a := m.Question[i]
		if a.Qtype != q.Qtype || a.Qclass != q.Qclass || !strings.EqualFold(a.Name, q.Name) {
			return false
		}
	}
	m.Id = clientID
	return true
}

// storeInCache caches a forwarded response with clamped TTLs, including
// negative answers (NXDOMAIN/NODATA) keyed off the SOA TTL (max 600s).

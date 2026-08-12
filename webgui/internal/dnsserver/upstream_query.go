package dnsserver

import (
	"log"

	"github.com/miekg/dns"
)

func (s *Server) forward(r *dns.Msg, specs []string) (string, *dns.Msg) {
	// DNSSEC passthrough: set or clear the DO bit on a copy so the configured
	// toggle applies even when the client supplied its own OPT record.
	r = r.Copy()
	if opt := r.IsEdns0(); opt != nil {
		opt.SetUDPSize(defaultEDNSUDPSize)
		opt.SetDo(s.cfg.DNSSEC)
	} else {
		r.SetEdns0(defaultEDNSUDPSize, s.cfg.DNSSEC)
	}
	if s.cfg.Pool != nil {
		if len(specs) > 0 {
			if m, used, err := s.cfg.Pool.ExchangeSpecs(specs, r); err == nil && m != nil {
				m.Id = r.Id
				return used, m
			}
			// Client upstreams failed: fall through to routes/global pool.
		}
		if s.cfg.Routes != nil && len(r.Question) > 0 {
			domain := normalizeName(r.Question[0].Name)
			if spec := s.cfg.Routes.GetUpstreamForDomain(domain); spec != "" {
				if m, used, err := s.cfg.Pool.ExchangeRoute(spec, r); err == nil && m != nil {
					m.Id = r.Id
					return used, m
				}
				// Route upstream failed: fall through to the general pool.
			}
		}
		m, used, err := s.cfg.Pool.Exchange(r)
		if err != nil || m == nil {
			return "", nil
		}
		m.Id = r.Id
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
		m.Id = r.Id
		return up, m
	}
	return "", nil
}

// storeInCache caches a forwarded response with clamped TTLs, including
// negative answers (NXDOMAIN/NODATA) keyed off the SOA TTL (max 600s).

package upstream

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// bootEntry pins bootstrap-resolved IPs with the TTL from the answer.
type bootEntry struct {
	ips       []string
	expiresAt time.Time
}

// bootstrapper resolves hostname-based upstreams via plain UDP bootstrap
// servers (BOOTSTRAP_DNS). Resolved IPs are cached with their TTL; on
// resolution failure the last known IPs are kept.
type bootstrapper struct {
	servers []string
	client  *dns.Client

	mu    sync.Mutex
	cache map[string]*bootEntry
}

func newBootstrapper(servers []string) *bootstrapper {
	var normalized []string
	for _, raw := range servers {
		spec, err := Parse(raw)
		if err != nil {
			log.Printf("[WARN] Ignoring invalid BOOTSTRAP_DNS entry %q: %v", raw, err)
			continue
		}
		if spec.Scheme != SchemeUDP {
			log.Printf("[WARN] BOOTSTRAP_DNS entries must be plain UDP resolvers, skipping %q", raw)
			continue
		}
		normalized = append(normalized, net.JoinHostPort(spec.Host, spec.Port))
	}
	return &bootstrapper{
		servers: normalized,
		client:  &dns.Client{Timeout: exchangeTimeout},
		cache:   make(map[string]*bootEntry),
	}
}

// Enabled reports whether any usable bootstrap servers are configured.
func (b *bootstrapper) Enabled() bool {
	return b != nil && len(b.servers) > 0
}

// Lookup resolves host to IP addresses via the bootstrap servers, using the
// TTL-pinned cache when fresh and keeping last-known IPs on failure.
func (b *bootstrapper) Lookup(host string) ([]string, error) {
	b.mu.Lock()
	ent, ok := b.cache[host]
	fresh := ok && time.Now().Before(ent.expiresAt)
	cached := ent
	b.mu.Unlock()

	if fresh {
		return cached.ips, nil
	}

	ips, ttl, err := b.resolve(host)
	if err != nil || len(ips) == 0 {
		if ok {
			log.Printf("[WARN] Bootstrap refresh for %s failed (%v); keeping last known IPs", host, err)
			return cached.ips, nil
		}
		if err == nil {
			err = fmt.Errorf("no A/AAAA records")
		}
		return nil, fmt.Errorf("bootstrap resolve %s: %w", host, err)
	}

	b.mu.Lock()
	b.cache[host] = &bootEntry{ips: ips, expiresAt: time.Now().Add(time.Duration(ttl) * time.Second)}
	b.mu.Unlock()
	return ips, nil
}

// resolve queries A and AAAA records for host through the bootstrap servers.
func (b *bootstrapper) resolve(host string) (ips []string, ttl uint32, err error) {
	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(host), qtype)
		for _, server := range b.servers {
			resp, _, xerr := b.client.Exchange(m, server)
			if xerr != nil || resp == nil {
				err = xerr
				continue
			}
			for _, rr := range resp.Answer {
				switch v := rr.(type) {
				case *dns.A:
					ips = append(ips, v.A.String())
					ttl = minTTL(ttl, rr.Header().Ttl)
				case *dns.AAAA:
					ips = append(ips, v.AAAA.String())
					ttl = minTTL(ttl, rr.Header().Ttl)
				}
			}
			if len(ips) > 0 {
				return ips, ttl, nil
			}
		}
	}
	return nil, 0, err
}

// minTTL returns the smaller non-zero TTL.
func minTTL(cur, next uint32) uint32 {
	if cur == 0 || (next > 0 && next < cur) {
		return next
	}
	return cur
}

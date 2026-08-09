// Package dnsserver implements the in-process DNS server that replaces
// dnsmasq. It serves UDP and TCP listeners and answers queries through an
// ordered pipeline: static rewrites → cache lookup → strict-order upstream
// forwarding → cache store → respond. Every answered query is emitted as a
// models.QueryEvent into the existing Store/SSE pipeline.
package dnsserver

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/miekg/dns"

	"tailscale-dnsrewrite/webgui/internal/models"
)

const (
	// defaultCacheSize mirrors the dnsmasq cache-size=25000 setting.
	defaultCacheSize = 25000
	// minCacheTTL mirrors the dnsmasq local-ttl=60 setting.
	minCacheTTL = 60
	// maxCacheTTL mirrors the dnsmasq max-ttl=600 setting.
	maxCacheTTL = 600
	// upstreamTimeout bounds a single upstream exchange before the next
	// upstream is tried (dnsmasq default is ~20s total; we keep it snappy).
	upstreamTimeout = 5 * time.Second
	// staticTTL is the TTL for static rewrite answers (dnsmasq local-ttl).
	staticTTL = 60
)

// Config holds the DNS server configuration.
type Config struct {
	// Addr is the listen address (DNS_LISTEN_ADDR, TAILSCALE_IP, or 0.0.0.0).
	Addr string
	// Port is the listen port (DNS_LISTEN_PORT, default 53).
	Port int
	// Upstreams are raw UPSTREAM_DNS entries (ip, ip#port, ip:port),
	// queried in strict order.
	Upstreams []string
	// StaticHosts holds DOMAINS static rewrites (domain → IPv4).
	StaticHosts map[string]net.IP
	// NodeName identifies this node on emitted events.
	NodeName string
	// CacheSize overrides the cache capacity (0 = defaultCacheSize).
	CacheSize int
}

// Server is the embedded DNS server.
type Server struct {
	cfg       Config
	upstreams []string
	cache     *cache
	emit      func(models.QueryEvent)
	udp       *dns.Server
	tcp       *dns.Server
	client    *dns.Client
}

// New creates a DNS server. emit is invoked synchronously for every answered
// query (typically Store.AddEvent + Server.BroadcastEvent wiring from main).
func New(cfg Config, emit func(models.QueryEvent)) *Server {
	s := &Server{
		cfg:   cfg,
		cache: newCache(cfg.CacheSize),
		emit:  emit,
		client: &dns.Client{
			Timeout: upstreamTimeout,
		},
	}
	for _, raw := range cfg.Upstreams {
		if addr, ok := normalizeUpstream(raw); ok {
			s.upstreams = append(s.upstreams, addr)
		} else if raw != "" {
			log.Printf("[WARN] Ignoring invalid UPSTREAM_DNS entry: %q", raw)
		}
	}
	if len(s.upstreams) == 0 {
		log.Printf("[WARN] No valid upstream DNS servers configured; all non-static queries will fail")
	}
	addr := s.ListenAddr()
	s.udp = &dns.Server{Addr: addr, Net: "udp", Handler: dns.HandlerFunc(s.ServeDNS)}
	s.tcp = &dns.Server{Addr: addr, Net: "tcp", Handler: dns.HandlerFunc(s.ServeDNS)}
	return s
}

// ListenAddr returns the host:port the server binds to.
func (s *Server) ListenAddr() string {
	return net.JoinHostPort(s.cfg.Addr, fmt.Sprintf("%d", s.cfg.Port))
}

// Start runs the UDP and TCP listeners until ctx is canceled or a listener
// fails, then shuts both down gracefully.
func (s *Server) Start(ctx context.Context) error {
	errCh := make(chan error, 2)
	go func() { errCh <- s.udp.ListenAndServe() }()
	go func() { errCh <- s.tcp.ListenAndServe() }()

	select {
	case <-ctx.Done():
		_ = s.udp.Shutdown()
		_ = s.tcp.Shutdown()
		return nil
	case err := <-errCh:
		_ = s.udp.Shutdown()
		_ = s.tcp.Shutdown()
		return fmt.Errorf("DNS listener on %s: %w", s.ListenAddr(), err)
	}
}

// ServeDNS handles a single DNS request through the ordered pipeline.
func (s *Server) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	start := time.Now()

	resp := new(dns.Msg)
	resp.SetReply(r)
	resp.RecursionAvailable = true

	var (
		upstream string
		cacheHit bool
	)

	if len(r.Question) == 0 {
		resp.Rcode = dns.RcodeFormatError
	} else {
		question := r.Question[0]
		domain := normalizeName(question.Name)
		key := cacheKey{name: domain, qtype: question.Qtype}

		switch {
		case question.Qtype == dns.TypeA && s.staticHosts() != nil:
			if ip := matchStatic(s.staticHosts(), domain); ip != nil {
				resp.Answer = []dns.RR{&dns.A{
					Hdr: dns.RR_Header{
						Name:   question.Name,
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    staticTTL,
					},
					A: ip,
				}}
				upstream = "Local Override"
				break
			}
			fallthrough
		default:
			upstream, cacheHit = s.resolveViaCacheOrUpstream(r, resp, key)
		}
	}

	_ = w.WriteMsg(resp)
	if s.emit != nil {
		s.emit(s.buildEvent(r, resp, w, upstream, cacheHit, start))
	}
}

// staticHosts returns the configured static rewrite map (never nil).
func (s *Server) staticHosts() map[string]net.IP {
	return s.cfg.StaticHosts
}

// resolveViaCacheOrUpstream runs the cache → forward → cache-store stages.
// It fills resp on success and returns the upstream label for the event.
func (s *Server) resolveViaCacheOrUpstream(r *dns.Msg, resp *dns.Msg, key cacheKey) (string, bool) {
	// Stage: cache lookup.
	if ent, remaining, ok := s.cache.get(key); ok {
		resp.Rcode = ent.rcode
		resp.Answer = withTTL(ent.answers, remaining)
		resp.Ns = withTTL(ent.authority, remaining)
		return "System Cache", true
	}

	// Stage: forward to upstreams in strict order (first success wins).
	upstream, m := s.forward(r)
	if m == nil {
		resp.Rcode = dns.RcodeServerFailure
		return upstream, false
	}
	resp.Rcode = m.Rcode
	resp.Answer = m.Answer
	resp.Ns = m.Ns
	resp.Extra = m.Extra

	// Stage: cache store.
	s.storeInCache(key, m)
	return upstream, false
}

// forward tries each upstream in strict order and returns the first
// successful response (any rcode counts as success; transport errors and
// timeouts move to the next upstream).
func (s *Server) forward(r *dns.Msg) (string, *dns.Msg) {
	for _, upstream := range s.upstreams {
		m, _, err := s.client.Exchange(r, upstream)
		if err != nil || m == nil {
			log.Printf("[DEBUG] Upstream %s exchange failed: %v", upstream, err)
			continue
		}
		if m.Truncated {
			// Retry over TCP per DNS convention.
			tcpClient := &dns.Client{Net: "tcp", Timeout: upstreamTimeout}
			if tm, _, terr := tcpClient.Exchange(r, upstream); terr == nil && tm != nil {
				m = tm
			}
		}
		m.Id = r.Id
		return upstream, m
	}
	return "", nil
}

// storeInCache caches a forwarded response with clamped TTLs, including
// negative answers (NXDOMAIN/NODATA) keyed off the SOA TTL (max 600s).
func (s *Server) storeInCache(key cacheKey, m *dns.Msg) {
	ent := &cacheEntry{
		answers:   copyRRs(m.Answer),
		authority: copyRRs(m.Ns),
		rcode:     m.Rcode,
		storedAt:  time.Now(),
	}

	switch {
	case m.Rcode == dns.RcodeSuccess && len(m.Answer) > 0:
		// Positive answer: min answer TTL clamped to [60, 600].
		ent.ttl = clampTTL(minAnswerTTL(m.Answer))
	case m.Rcode == dns.RcodeNameError || (m.Rcode == dns.RcodeSuccess && len(m.Answer) == 0):
		// Negative answer (NXDOMAIN/NODATA): SOA TTL clamped to max 600.
		ttl, ok := soaTTL(m.Ns)
		if !ok {
			return
		}
		if ttl > maxCacheTTL {
			ttl = maxCacheTTL
		}
		if ttl == 0 {
			return
		}
		ent.ttl = ttl
	default:
		// SERVFAIL and other rcodes are not cached.
		return
	}
	s.cache.set(key, ent)
}

// withTTL returns copies of rrs with the given TTL applied (TTL decrement on
// cache hits).
func withTTL(rrs []dns.RR, ttl uint32) []dns.RR {
	if len(rrs) == 0 {
		return nil
	}
	out := make([]dns.RR, len(rrs))
	for i, rr := range rrs {
		c := dns.Copy(rr)
		c.Header().Ttl = ttl
		out[i] = c
	}
	return out
}

// buildEvent assembles the QueryEvent for an answered query.
func (s *Server) buildEvent(r, resp *dns.Msg, w dns.ResponseWriter, upstream string, cacheHit bool, start time.Time) models.QueryEvent {
	ev := models.QueryEvent{
		UnixTime: time.Now().Unix(),
		Node:     s.cfg.NodeName,
		Upstream: upstream,
	}
	if len(r.Question) > 0 {
		ev.Type = dns.TypeToString[r.Question[0].Qtype]
		ev.Domain = normalizeName(r.Question[0].Name)
	}
	ev.ClientIP = clientIPFromRemote(w.RemoteAddr())
	ev.ResponseCode = dns.RcodeToString[resp.Rcode]

	latencyMs := float64(time.Since(start).Microseconds()) / 1000.0
	if cacheHit {
		latencyMs = 0
	}
	ev.Latency = sql.NullFloat64{Float64: latencyMs, Valid: true}
	return ev
}

// clientIPFromRemote extracts the IP part of a DNS client address.
func clientIPFromRemote(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}

// Package dnsserver implements the in-process DNS server that replaces
// dnsmasq. It serves UDP and TCP listeners and answers queries through an
// ordered pipeline: policy short-circuits (refuse-ANY, AAAA-disable) →
// typed rewrites → safe-search → filter → cache lookup → strict-order
// upstream forwarding → bogus-NXDOMAIN conversion → cache store → respond.
// Every answered query is emitted as a models.QueryEvent into the existing
// Store/SSE pipeline.
package dnsserver

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"tailscale-dnsrewrite/webgui/internal/filter"
	"tailscale-dnsrewrite/webgui/internal/models"
	"tailscale-dnsrewrite/webgui/internal/policy"
	"tailscale-dnsrewrite/webgui/internal/rewrites"
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
	// maxChainDepth caps CNAME/safe-search chase chains to avoid loops.
	maxChainDepth = 8
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
	// Filter is the filter engine (nil = filtering disabled).
	Filter *filter.Engine
	// BlockingMode selects the blocked-response mode:
	// nxdomain (default) | null_ip | refused | custom_ip.
	BlockingMode string
	// BlockCustomIP4/IP6 are the answer addresses in custom_ip mode.
	BlockCustomIP4 string
	BlockCustomIP6 string
	// Rewrites is the typed-rewrite store (nil = fall back to StaticHosts).
	Rewrites *rewrites.Store
	// Policy holds safe-search / bogus-NXDOMAIN / AAAA / ANY policy (nil = off).
	Policy *policy.Policy
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

	rewriteHits    atomic.Int64
	safeSearchHits atomic.Int64
	bogusNXHits    atomic.Int64
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
	handler := dns.HandlerFunc(s.ServeDNS)
	s.udp = &dns.Server{Net: "udp", Handler: handler}
	s.tcp = &dns.Server{Net: "tcp", Handler: handler}
	return s
}

// ListenAddr returns the host:port the server binds to.
func (s *Server) ListenAddr() string {
	return net.JoinHostPort(s.cfg.Addr, fmt.Sprintf("%d", s.cfg.Port))
}

// resetTolerantConn wraps a UDP socket to ignore spurious
// "connection reset" read errors. On Windows, an ICMP port-unreachable
// (e.g. from a client that already closed its socket) surfaces as
// WSAECONNRESET on the next ReadFrom and would otherwise kill the listener.
type resetTolerantConn struct {
	net.PacketConn
}

func (c resetTolerantConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		n, addr, err := c.PacketConn.ReadFrom(p)
		if err != nil && strings.Contains(err.Error(), "connection reset") {
			continue
		}
		return n, addr, err
	}
}

// Start binds the configured address and runs the UDP and TCP listeners
// until ctx is canceled or a listener fails, then shuts both down gracefully.
func (s *Server) Start(ctx context.Context) error {
	udpConn, err := net.ListenPacket("udp", s.ListenAddr())
	if err != nil {
		return fmt.Errorf("DNS UDP listener on %s: %w", s.ListenAddr(), err)
	}
	tcpLn, err := net.Listen("tcp", s.ListenAddr())
	if err != nil {
		_ = udpConn.Close()
		return fmt.Errorf("DNS TCP listener on %s: %w", s.ListenAddr(), err)
	}
	return s.StartOn(ctx, udpConn, tcpLn)
}

// StartOn runs the UDP and TCP listeners on pre-bound sockets until ctx is
// canceled or a listener fails. Tests use it with :0 sockets to avoid
// port-reservation races.
func (s *Server) StartOn(ctx context.Context, udpConn net.PacketConn, tcpLn net.Listener) error {
	s.udp.PacketConn = resetTolerantConn{udpConn}
	s.tcp.Listener = tcpLn

	errCh := make(chan error, 2)
	go func() { errCh <- s.udp.ActivateAndServe() }()
	go func() { errCh <- s.tcp.ActivateAndServe() }()

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

// resolution describes how a query was answered, for event emission.
type resolution struct {
	upstream    string
	cacheHit    bool
	blocked     bool
	matchedRule string
	blockReason string
}

// ServeDNS handles a single DNS request through the ordered pipeline.
func (s *Server) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	start := time.Now()

	resp := new(dns.Msg)
	resp.SetReply(r)
	resp.RecursionAvailable = true

	res := s.resolve(r, resp, 0)
	_ = w.WriteMsg(resp)
	if s.emit != nil {
		s.emit(s.buildEvent(r, resp, w, res, start))
	}
}

// resolve runs the request pipeline and fills resp.
//
// Order: refuse-ANY / AAAA-disable short-circuits → typed rewrites →
// safe-search → filter → cache → strict-order forward → bogus-NXDOMAIN
// conversion → cache store. depth bounds CNAME/safe-search chase chains.
func (s *Server) resolve(r *dns.Msg, resp *dns.Msg, depth int) resolution {
	if len(r.Question) == 0 {
		resp.Rcode = dns.RcodeFormatError
		return resolution{}
	}
	q := r.Question[0]
	domain := normalizeName(q.Name)

	// Early policy short-circuits (before rewrites).
	if s.cfg.Policy != nil {
		if s.cfg.Policy.RefuseANY && q.Qtype == dns.TypeANY {
			resp.Rcode = dns.RcodeRefused
			return resolution{upstream: "Policy", matchedRule: "REFUSE_ANY", blockReason: policy.ReasonRefusedANY}
		}
		if s.cfg.Policy.AAAADisabled && q.Qtype == dns.TypeAAAA {
			// NODATA: NOERROR with an empty answer section.
			return resolution{upstream: "Policy", matchedRule: "AAAA_DISABLED", blockReason: policy.ReasonAAAADisabled}
		}
	}

	// Stage 1: typed rewrites (short-circuit, pre-cache).
	if res, handled := s.stageRewrites(r, q, resp, depth); handled {
		return res
	}

	// Stage 2: safe search (CNAME to the restricted variant, chased below).
	if res, handled := s.stageSafeSearch(r, q, resp, depth); handled {
		return res
	}

	// Stage 3: filter. Blocked responses are NOT cached (cheap to
	// regenerate; must not poison the forwarded-answer cache).
	if s.cfg.Filter != nil && !s.cfg.Filter.Paused() {
		if f := s.cfg.Filter.Match(domain); f.Blocked && !f.Allowed {
			blockedResp := s.blockedResponse(r, q)
			resp.Rcode = blockedResp.Rcode
			resp.Answer = blockedResp.Answer
			return resolution{upstream: "Filtered", blocked: true, matchedRule: f.Rule, blockReason: f.Reason}
		}
	}

	// Stage 4: cache → forward → bogus-NXDOMAIN → cache store.
	key := cacheKey{name: domain, qtype: q.Qtype}
	return s.resolveViaCacheOrUpstream(r, resp, key)
}

// stageRewrites applies typed rewrites from the store (or the legacy
// StaticHosts fallback). handled is true when a rewrite answered the query.
func (s *Server) stageRewrites(_ *dns.Msg, q dns.Question, resp *dns.Msg, depth int) (resolution, bool) {
	domain := normalizeName(q.Name)

	if s.cfg.Rewrites == nil {
		// Legacy fallback: StaticHosts map (used when no store is wired).
		if q.Qtype == dns.TypeA {
			if ip := matchStatic(s.staticHosts(), domain); ip != nil {
				resp.Answer = []dns.RR{&dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: staticTTL},
					A:   ip,
				}}
				return resolution{upstream: "Local Override"}, true
			}
		}
		return resolution{}, false
	}

	entries := s.cfg.Rewrites.Lookup(domain)
	if len(entries) == 0 {
		return resolution{}, false
	}
	s.rewriteHits.Add(1)

	// RCODE rewrites take precedence over record rewrites.
	for _, e := range entries {
		switch e.Type {
		case rewrites.TypeNXDOMAIN:
			resp.Rcode = dns.RcodeNameError
			return resolution{upstream: "Rewrite", matchedRule: e.String(), blockReason: "Rewrite"}, true
		case rewrites.TypeREFUSED:
			resp.Rcode = dns.RcodeRefused
			return resolution{upstream: "Rewrite", matchedRule: e.String(), blockReason: "Rewrite"}, true
		case rewrites.TypeNOERROR:
			return resolution{upstream: "Rewrite", matchedRule: e.String(), blockReason: "Rewrite"}, true
		}
	}

	// Records matching the question type. CNAME entries are handled by the
	// chase below (except for explicit CNAME questions).
	var answers []dns.RR
	matched := ""
	for _, e := range entries {
		if e.Type == rewrites.TypeCNAME && q.Qtype != dns.TypeCNAME {
			continue
		}
		if rr := e.BuildRR(q.Name, q.Qtype); rr != nil {
			answers = append(answers, rr)
			matched = e.String()
		}
	}
	if len(answers) > 0 {
		resp.Answer = answers
		return resolution{upstream: "Rewrite", matchedRule: matched, blockReason: "Rewrite"}, true
	}

	// CNAME rewrites chase the target through the rest of the pipeline.
	if q.Qtype == dns.TypeA || q.Qtype == dns.TypeAAAA || q.Qtype == dns.TypeCNAME {
		for _, e := range entries {
			if e.Type != rewrites.TypeCNAME {
				continue
			}
			return s.chaseCNAME(q, resp, e.Value, e.String(), "Rewrite", "Rewrite", depth), true
		}
	}

	// The rewrite set covers this domain but not the qtype → NODATA.
	return resolution{upstream: "Rewrite", matchedRule: entries[0].String(), blockReason: "Rewrite"}, true
}

// stageSafeSearch rewrites configured safe-search domains to their
// restricted variants (pre-cache, like rewrites).
func (s *Server) stageSafeSearch(_ *dns.Msg, q dns.Question, resp *dns.Msg, depth int) (resolution, bool) {
	if s.cfg.Policy == nil {
		return resolution{}, false
	}
	target := s.cfg.Policy.SafeSearchTarget(normalizeName(q.Name))
	if target == "" {
		return resolution{}, false
	}
	s.safeSearchHits.Add(1)

	// Address-type queries chase the restricted target through the rest of
	// the pipeline and return both the CNAME and the target's records.
	if q.Qtype == dns.TypeA || q.Qtype == dns.TypeAAAA || q.Qtype == dns.TypeCNAME {
		return s.chaseCNAME(q, resp, target, "SafeSearch", "SafeSearch", policy.ReasonSafeSearch, depth), true
	}
	// Other types get just the CNAME record.
	resp.Answer = []dns.RR{&dns.CNAME{
		Hdr:    dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: staticTTL},
		Target: dns.Fqdn(target),
	}}
	return resolution{upstream: "SafeSearch", matchedRule: "SafeSearch", blockReason: policy.ReasonSafeSearch}, true
}

// chaseCNAME appends the CNAME record and resolves the target through the
// rest of the pipeline (filter/cache/forward), merging the answers.
func (s *Server) chaseCNAME(q dns.Question, resp *dns.Msg, target, rule, label, reason string, depth int) resolution {
	if depth >= maxChainDepth {
		resp.Rcode = dns.RcodeServerFailure
		return resolution{upstream: label, matchedRule: rule + " (chain depth exceeded)", blockReason: reason}
	}
	fqdn := dns.Fqdn(target)
	cname := &dns.CNAME{
		Hdr:    dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: staticTTL},
		Target: fqdn,
	}
	sub := new(dns.Msg)
	sub.SetQuestion(fqdn, q.Qtype)
	subResp := new(dns.Msg)
	subResp.SetReply(sub)
	subResp.RecursionAvailable = true
	s.resolve(sub, subResp, depth+1)

	resp.Rcode = subResp.Rcode
	resp.Answer = append([]dns.RR{cname}, subResp.Answer...)
	resp.Ns = subResp.Ns
	return resolution{upstream: label, matchedRule: rule, blockReason: reason}
}

// blockedResponse builds the response for a filtered query according to the
// configured blocking mode, with TTL 60 per existing conventions.
func (s *Server) blockedResponse(r *dns.Msg, question dns.Question) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetReply(r)
	resp.RecursionAvailable = true

	hdr := dns.RR_Header{
		Name:   question.Name,
		Class:  dns.ClassINET,
		Ttl:    staticTTL,
		Rrtype: question.Qtype,
	}
	switch s.cfg.BlockingMode {
	case "refused":
		resp.Rcode = dns.RcodeRefused
	case "null_ip", "custom_ip":
		v4, v6 := s.blockIPs()
		switch question.Qtype {
		case dns.TypeA:
			if ip := net.ParseIP(v4); ip != nil {
				resp.Answer = []dns.RR{&dns.A{Hdr: hdr, A: ip.To4()}}
			}
		case dns.TypeAAAA:
			if ip := net.ParseIP(v6); ip != nil {
				resp.Answer = []dns.RR{&dns.AAAA{Hdr: hdr, AAAA: ip}}
			}
		default:
			// Other types get a NODATA (NOERROR, empty) answer.
		}
	default: // "nxdomain"
		resp.Rcode = dns.RcodeNameError
	}
	return resp
}

// blockIPs returns the IPv4/IPv6 answers for null_ip and custom_ip modes.
func (s *Server) blockIPs() (v4, v6 string) {
	v4, v6 = "0.0.0.0", "::"
	if s.cfg.BlockingMode == "custom_ip" {
		if s.cfg.BlockCustomIP4 != "" {
			v4 = s.cfg.BlockCustomIP4
		}
		if s.cfg.BlockCustomIP6 != "" {
			v6 = s.cfg.BlockCustomIP6
		}
	}
	return v4, v6
}

// staticHosts returns the configured static rewrite map (never nil).
func (s *Server) staticHosts() map[string]net.IP {
	return s.cfg.StaticHosts
}

// resolveViaCacheOrUpstream runs the cache → forward → bogus-NXDOMAIN →
// cache-store stages. It fills resp on success.
func (s *Server) resolveViaCacheOrUpstream(r *dns.Msg, resp *dns.Msg, key cacheKey) resolution {
	// Stage: cache lookup.
	if ent, remaining, ok := s.cache.get(key); ok {
		resp.Rcode = ent.rcode
		resp.Answer = withTTL(ent.answers, remaining)
		resp.Ns = withTTL(ent.authority, remaining)
		return resolution{upstream: "System Cache", cacheHit: true}
	}

	// Stage: forward to upstreams in strict order (first success wins).
	upstream, m := s.forward(r)
	if m == nil {
		resp.Rcode = dns.RcodeServerFailure
		return resolution{upstream: upstream}
	}

	// Stage: bogus-NXDOMAIN conversion (anti-poisoning) — runs before the
	// cache store so converted answers never poison the cache.
	if s.cfg.Policy != nil && s.cfg.Policy.IsBogusAnswer(m.Answer) {
		s.bogusNXHits.Add(1)
		resp.Rcode = dns.RcodeNameError
		return resolution{upstream: upstream, matchedRule: "BOGUS_NXDOMAIN", blockReason: policy.ReasonBogusNX}
	}

	resp.Rcode = m.Rcode
	resp.Answer = m.Answer
	resp.Ns = m.Ns
	resp.Extra = m.Extra

	// Stage: cache store.
	s.storeInCache(key, m)
	return resolution{upstream: upstream}
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
func (s *Server) buildEvent(r, resp *dns.Msg, w dns.ResponseWriter, res resolution, start time.Time) models.QueryEvent {
	ev := models.QueryEvent{
		UnixTime:    time.Now().Unix(),
		Node:        s.cfg.NodeName,
		Upstream:    res.upstream,
		Blocked:     res.blocked,
		MatchedRule: res.matchedRule,
		BlockReason: res.blockReason,
	}
	if len(r.Question) > 0 {
		ev.Type = dns.TypeToString[r.Question[0].Qtype]
		ev.Domain = normalizeName(r.Question[0].Name)
	}
	ev.ClientIP = clientIPFromRemote(w.RemoteAddr())
	ev.ResponseCode = dns.RcodeToString[resp.Rcode]

	latencyMs := float64(time.Since(start).Microseconds()) / 1000.0
	if res.cacheHit {
		latencyMs = 0
	}
	ev.Latency = sql.NullFloat64{Float64: latencyMs, Valid: true}
	return ev
}

// Stats returns the pipeline hit counters for metrics:
// rewrites, safe-search, and bogus-NXDOMAIN conversions.
func (s *Server) Stats() (rewriteHits, safeSearchHits, bogusNXHits int64) {
	return s.rewriteHits.Load(), s.safeSearchHits.Load(), s.bogusNXHits.Load()
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

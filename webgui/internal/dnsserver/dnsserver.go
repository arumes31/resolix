// Package dnsserver implements the in-process DNS server that replaces
// dnsmasq. It serves UDP and TCP listeners and answers queries through an
// ordered pipeline: refuse-ANY/AAAA-disable → typed rewrites → private PTR →
// safe-search → filter → cache → client upstreams →
// domain route → global pool → bogus-NXDOMAIN → cache store → respond.
// Every answered query is emitted as a models.QueryEvent into the existing
// Store/SSE pipeline.
package dnsserver

import (
	"context"
	"crypto/tls"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/miekg/dns"

	"github.com/arumes31/resolix/webgui/internal/clients"
	"github.com/arumes31/resolix/webgui/internal/dnsroutes"
	"github.com/arumes31/resolix/webgui/internal/dnssettings"
	"github.com/arumes31/resolix/webgui/internal/filter"
	"github.com/arumes31/resolix/webgui/internal/models"
	"github.com/arumes31/resolix/webgui/internal/policy"
	"github.com/arumes31/resolix/webgui/internal/resolver"
	"github.com/arumes31/resolix/webgui/internal/rewrites"
	"github.com/arumes31/resolix/webgui/internal/upstream"
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
	// defaultEDNSUDPSize is the fragmentation-safe DNS payload size recommended
	// by DNS Flag Day 2020. Larger client advertisements are clamped to it.
	defaultEDNSUDPSize = 1232
	// maxMissFlights bounds distinct concurrent cache-miss work so random-name
	// floods cannot grow the coalescing map without limit.
	maxMissFlights           = 1024
	maxBackgroundRefreshes   = 64
	defaultTCPIdleTimeout    = 8 * time.Second
	defaultTCPMaxQueries     = 128
	defaultTCPMaxConnections = 256
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
	// BlockedResponseTTL is used for synthetic blocked A/AAAA answers.
	BlockedResponseTTL uint32
	// Rewrites is the typed-rewrite store (nil = fall back to StaticHosts).
	Rewrites *rewrites.Store
	// Policy holds safe-search / bogus-NXDOMAIN / AAAA / ANY policy (nil = off).
	Policy *policy.Policy
	// Pool is the upstream pool (nil = legacy strict-order Upstreams path).
	Pool *upstream.Pool
	// Routes provides per-domain upstream routing (nil = no routes).
	Routes *dnsroutes.DNSRoutes
	// Clients is the per-client policy registry (nil = all clients global).
	Clients *clients.Registry
	// AliasFunc resolves a client IP to its display alias (CLIENT_ALIASES);
	// a matching registry client's name takes precedence.
	AliasFunc func(ip string) string
	// CacheMinTTL/CacheMaxTTL override cache TTL bounds (0 = 60/600).
	CacheMinTTL     uint32
	CacheMaxTTL     uint32
	CacheOptimistic bool
	// CachePrefetch refreshes frequently used entries shortly before expiry.
	CachePrefetch       bool
	CachePrefetchWindow time.Duration
	CachePrefetchHits   uint32
	// CacheSERVFAILTTL enables a bounded SERVFAIL micro-cache. Values above one
	// second are clamped to one second; zero disables it.
	CacheSERVFAILTTL time.Duration

	// AllowedClients restricts service to these IPs/CIDRs when non-empty.
	AllowedClients string
	// DisallowedClients drops queries from these IPs/CIDRs silently.
	DisallowedClients string
	// RateLimitQPS limits public clients per IP (0 = disabled).
	RateLimitQPS int
	// InternalRateLimitQPS limits LAN and Tailscale clients per IP (0 = disabled).
	InternalRateLimitQPS int
	// RateLimitEDE opts EDNS-capable clients into a small REFUSED response with
	// EDE Prohibited. The default remains a silent drop to resist amplification.
	RateLimitEDE bool
	// RateLimitIPv4Prefix/IPv6Prefix aggregate clients into subnet buckets.
	RateLimitIPv4Prefix int
	RateLimitIPv6Prefix int
	// RateLimitAllowlist bypasses query rate limiting for trusted IPs/CIDRs.
	RateLimitAllowlist string
	// PrivatePTR answers PTR for known private clients locally.
	PrivatePTR bool
	// PrivatePTRUpstreams route unknown private PTR queries to dedicated resolvers.
	PrivatePTRUpstreams []string
	// ResolveClientHostnames enriches events and local PTR answers from reverse DNS.
	ResolveClientHostnames bool
	// DNSSEC enables DO-bit passthrough to upstreams (no local validation).
	DNSSEC bool
	// Resolver is the reverse-DNS resolver used for private PTR fallback.
	Resolver *resolver.Resolver

	// DoTEnabled serves DNS-over-TLS on DoTPort (requires TLS cert/key).
	DoTEnabled  bool
	DoTPort     int
	TLSCertFile string
	TLSKeyFile  string
	// TCPIdleTimeout and TCPMaxQueries tune persistent DNS TCP/DoT sessions.
	// TCPMaxConnections bounds active TCP and DoT connections across listeners.
	TCPIdleTimeout    time.Duration
	TCPMaxQueries     int
	TCPMaxConnections int
}

// Server is the embedded DNS server.
type Server struct {
	cfg       Config
	upstreams []string
	cache     *cache
	emit      func(models.QueryEvent, bool) // (event, excludeFromStats)
	udp       *dns.Server
	tcp       *dns.Server
	dot       *dns.Server
	client    *dns.Client

	// ACL and rate limiting (Step 6)
	allowed             []*net.IPNet
	allowedConfigured   bool
	disallowed          []*net.IPNet
	rateLimitAllowlist  []*net.IPNet
	rateLimiter         *rateLimiter
	rateLimitDropped    atomic.Int64
	aclDropped          atomic.Int64
	aclAllowlistDropped atomic.Int64
	ready               atomic.Bool

	rewriteHits    atomic.Int64
	safeSearchHits atomic.Int64
	bogusNXHits    atomic.Int64

	// refreshInFlight tracks optimistic-cache background refreshes (single-flight).
	refreshMu       sync.Mutex
	refreshInFlight map[cacheKey]bool
	refreshSlots    chan struct{}

	missMu          sync.Mutex
	missInFlight    map[cacheKey]*missFlight
	cacheMutationMu sync.Mutex
	cacheGeneration atomic.Uint64
	tcpSlots        chan struct{}
	// runtimeMu prevents live policy replacement from racing active queries.
	// Listener and dependency fields in cfg remain immutable after startup.
	runtimeMu sync.RWMutex
}

type missFlight struct {
	done    chan struct{}
	result  upstreamResult
	waiters int
}

type upstreamResult struct {
	upstream    string
	msg         *dns.Msg
	matchedRule string
	blockReason string
}

// New creates a DNS server. emit is invoked synchronously for every answered
// query with the event and whether the client is stats-excluded (typically
// Store.AddEvent + Server.BroadcastEvent wiring from main).
func New(cfg Config, emit func(models.QueryEvent, bool)) *Server {
	if cfg.TCPIdleTimeout <= 0 {
		cfg.TCPIdleTimeout = defaultTCPIdleTimeout
	}
	if cfg.TCPMaxQueries <= 0 {
		cfg.TCPMaxQueries = defaultTCPMaxQueries
	}
	if cfg.TCPMaxConnections <= 0 {
		cfg.TCPMaxConnections = defaultTCPMaxConnections
	}
	if cfg.RateLimitIPv4Prefix <= 0 {
		cfg.RateLimitIPv4Prefix = 32
	}
	if cfg.RateLimitIPv6Prefix <= 0 {
		cfg.RateLimitIPv6Prefix = 128
	}
	s := &Server{
		cfg:             cfg,
		cache:           newCache(cfg.CacheSize, cfg.CacheMinTTL, cfg.CacheMaxTTL),
		emit:            emit,
		refreshInFlight: make(map[cacheKey]bool),
		refreshSlots:    make(chan struct{}, maxBackgroundRefreshes),
		missInFlight:    make(map[cacheKey]*missFlight),
		client: &dns.Client{
			Timeout: upstreamTimeout,
			UDPSize: defaultEDNSUDPSize,
		},
	}
	if s.cfg.CachePrefetchWindow <= 0 {
		s.cfg.CachePrefetchWindow = 30 * time.Second
	}
	if s.cfg.CachePrefetchHits == 0 {
		s.cfg.CachePrefetchHits = 3
	}
	if s.cfg.CacheSERVFAILTTL > time.Second {
		s.cfg.CacheSERVFAILTTL = time.Second
	}
	if s.cfg.CacheSERVFAILTTL < 0 {
		s.cfg.CacheSERVFAILTTL = 0
	}
	if cfg.TCPMaxConnections > 0 {
		s.tcpSlots = make(chan struct{}, cfg.TCPMaxConnections)
	}
	s.cache.optimistic = cfg.CacheOptimistic
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
	s.allowed = parseCIDRList(cfg.AllowedClients)
	s.allowedConfigured = strings.TrimSpace(cfg.AllowedClients) != ""
	s.disallowed = parseCIDRList(cfg.DisallowedClients)
	s.rateLimitAllowlist = parseCIDRList(cfg.RateLimitAllowlist)
	s.rateLimiter = newRateLimiter(cfg.RateLimitQPS)
	handler := dns.HandlerFunc(s.ServeDNS)
	s.udp = &dns.Server{Net: "udp", Handler: handler, UDPSize: defaultEDNSUDPSize}
	s.tcp = newTCPServer("tcp", handler, cfg)
	return s
}

func newTCPServer(network string, handler dns.Handler, cfg Config) *dns.Server {
	server := &dns.Server{Net: network, Handler: handler, MaxTCPQueries: cfg.TCPMaxQueries}
	if cfg.TCPIdleTimeout > 0 {
		idleTimeout := cfg.TCPIdleTimeout
		server.IdleTimeout = func() time.Duration { return idleTimeout }
	}
	return server
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
	const maxConsecutiveResets = 8
	for resets := 0; ; resets++ {
		n, addr, err := c.PacketConn.ReadFrom(p)
		reset := errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.Errno(10054))
		if reset && resets < maxConsecutiveResets {
			continue
		}
		return n, addr, err
	}
}

// connectionLimitListener rejects connections above a shared fixed limit.
// The slot is released exactly once when the accepted connection closes.
type connectionLimitListener struct {
	net.Listener
	slots chan struct{}
}

func (l connectionLimitListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		select {
		case l.slots <- struct{}{}:
			return &slotConn{Conn: conn, release: func() { <-l.slots }}, nil
		default:
			_ = conn.Close()
		}
	}
}

type slotConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *slotConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

func (s *Server) limitTCPListener(listener net.Listener) net.Listener {
	if listener == nil || s.tcpSlots == nil {
		return listener
	}
	return connectionLimitListener{Listener: listener, slots: s.tcpSlots}
}

// Start binds the configured address and runs the listeners until ctx is
// canceled or a listener fails, then shuts everything down gracefully. When
// DoT is enabled, certificates are validated before anything is bound.
func (s *Server) Start(ctx context.Context) error {
	// DoT requires certificates — fail fast before binding anything.
	var tlsConfig *tls.Config
	if s.cfg.DoTEnabled {
		if s.cfg.TLSCertFile == "" || s.cfg.TLSKeyFile == "" {
			return fmt.Errorf("DOT_ENABLED requires TLS_CERT_FILE and TLS_KEY_FILE")
		}
		cert, err := tls.LoadX509KeyPair(s.cfg.TLSCertFile, s.cfg.TLSKeyFile)
		if err != nil {
			return fmt.Errorf("DoT TLS keypair: %w", err)
		}
		tlsConfig = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	}

	udpConn, err := net.ListenPacket("udp", s.ListenAddr())
	if err != nil {
		return fmt.Errorf("DNS UDP listener on %s: %w", s.ListenAddr(), err)
	}
	tcpLn, err := net.Listen("tcp", s.ListenAddr())
	if err != nil {
		_ = udpConn.Close()
		return fmt.Errorf("DNS TCP listener on %s: %w", s.ListenAddr(), err)
	}

	var dotLn net.Listener
	if tlsConfig != nil {
		port := s.cfg.DoTPort
		if port == 0 {
			port = 853
		}
		dotAddr := net.JoinHostPort(s.cfg.Addr, fmt.Sprintf("%d", port))
		raw, err := net.Listen("tcp", dotAddr)
		if err != nil {
			_ = udpConn.Close()
			_ = tcpLn.Close()
			return fmt.Errorf("DNS DoT listener on %s: %w", dotAddr, err)
		}
		dotLn = tls.NewListener(raw, tlsConfig)
	}
	return s.startOn(ctx, udpConn, tcpLn, dotLn)
}

// StartOn runs the UDP and TCP listeners on pre-bound sockets until ctx is
// canceled or a listener fails. Tests use it with :0 sockets to avoid
// port-reservation races.
func (s *Server) StartOn(ctx context.Context, udpConn net.PacketConn, tcpLn net.Listener) error {
	return s.startOn(ctx, udpConn, tcpLn, nil)
}

// startOn serves all bound listeners until ctx is canceled or one fails.
func (s *Server) startOn(ctx context.Context, udpConn net.PacketConn, tcpLn, dotLn net.Listener) error {
	serveCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	s.udp.PacketConn = resetTolerantConn{udpConn}
	s.tcp.Listener = s.limitTCPListener(tcpLn)
	servers := []*dns.Server{s.udp, s.tcp}
	if dotLn != nil {
		s.dot = newTCPServer("tcp-tls", dns.HandlerFunc(s.ServeDNS), s.cfg)
		s.dot.Listener = s.limitTCPListener(dotLn)
		servers = append(servers, s.dot)
	}

	if s.rateLimiter != nil {
		go s.rateLimiter.rateLimitCleanupLoop(serveCtx.Done())
	}

	errCh := make(chan error, len(servers))
	for _, srv := range servers {
		go func(srv *dns.Server) { errCh <- srv.ActivateAndServe() }(srv)
	}
	s.ready.Store(true)
	defer s.ready.Store(false)

	shutdown := func() {
		for _, srv := range servers {
			_ = srv.Shutdown()
		}
	}
	select {
	case <-ctx.Done():
		shutdown()
		return nil
	case err := <-errCh:
		shutdown()
		return fmt.Errorf("DNS listener on %s: %w", s.ListenAddr(), err)
	}
}

// resolution describes how a query was answered, for event emission.
type resolution struct {
	upstream    string
	cacheHit    bool
	cacheState  string
	blocked     bool
	matchedRule string
	blockReason string
	cacheTTL    uint32
	negativeSOA string
	ede         *dns.EDNS0_EDE
}

const (
	cacheStateFresh      = "fresh"
	cacheStateStale      = "stale"
	cacheStatePrefetched = "prefetched"
	cacheStateNegative   = "negative"
	cacheStateCoalesced  = "coalesced"
	cacheStateSERVFAIL   = "servfail"
)

// Resolve answers a query message through the full pipeline and emits the
// query event. It returns drop=true for deny-list matches, allow-list misses,
// and rate-limit excess so DNS listeners emit no response. Shared by the
// UDP/TCP/DoT listeners and the DoH endpoint.
func (s *Server) Resolve(r *dns.Msg, clientIP string) (resp *dns.Msg, drop bool) {
	s.runtimeMu.RLock()
	defer s.runtimeMu.RUnlock()
	start := time.Now()

	resp = new(dns.Msg)
	resp.SetReply(r)
	resp.RecursionAvailable = true

	// Stage 0a: ACL — disallowed clients are dropped silently.
	if s.aclDrop(clientIP) {
		s.aclDropped.Add(1)
		return nil, true
	}
	// Stage 0b: ACL — outside a non-empty allowed list → silent drop.
	if s.aclAllowlistDrop(clientIP) {
		s.aclAllowlistDropped.Add(1)
		return nil, true
	}
	// Stage 0c: per-IP rate limit → silent drop. LAN and Tailscale clients use
	// the higher internal rate without relaxing the public-client limit.
	rateLimitQPS := s.cfg.RateLimitQPS
	if isInternalClientIP(clientIP) {
		rateLimitQPS = s.cfg.InternalRateLimitQPS
	}
	if s.rateLimiter != nil && !cidrListContains(s.rateLimitAllowlist, clientIP) &&
		!s.rateLimiter.allowAtRate(
			clientIP,
			rateLimitQPS,
			s.cfg.RateLimitIPv4Prefix,
			s.cfg.RateLimitIPv6Prefix,
		) {
		s.rateLimitDropped.Add(1)
		if s.cfg.RateLimitEDE && r.IsEdns0() != nil {
			resp.Rcode = dns.RcodeRefused
			resp.Extra = responseExtra(r, nil)
			addExtendedError(resp, r, dns.ExtendedErrorCodeProhibited, "rate limit exceeded")
			return resp, false
		}
		return nil, true
	}

	// Per-client resolution happens once at query start.
	var cl *clients.Client
	if s.cfg.Clients != nil {
		cl = s.cfg.Clients.Find(clientIP)
	}

	res := s.resolve(r, resp, 0, cl, clientIP, make(map[string]struct{}))
	if res.ede != nil {
		addExtendedError(resp, r, res.ede.InfoCode, res.ede.ExtraText)
	}
	if s.cfg.Policy != nil && s.cfg.Policy.AAAADisabled && len(r.Question) > 0 &&
		(r.Question[0].Qtype == dns.TypeHTTPS || r.Question[0].Qtype == dns.TypeSVCB) {
		stripIPv6Hints(resp.Answer)
	}

	if s.emit == nil {
		return resp, false
	}
	if cl != nil && cl.ExcludeFromLog {
		return resp, false // exclude_from_log: skip event emission entirely
	}
	excludeFromStats := cl != nil && cl.ExcludeFromStats
	s.emit(s.buildEvent(r, resp, clientIP, cl, res, start), excludeFromStats)
	return resp, false
}

func stripIPv6Hints(records []dns.RR) {
	for _, record := range records {
		var values *[]dns.SVCBKeyValue
		switch typed := record.(type) {
		case *dns.SVCB:
			values = &typed.Value
		case *dns.HTTPS:
			values = &typed.Value
		}
		if values == nil {
			continue
		}
		filtered := (*values)[:0]
		for _, value := range *values {
			if _, ipv6Hint := value.(*dns.SVCBIPv6Hint); !ipv6Hint {
				filtered = append(filtered, value)
			}
		}
		*values = filtered
	}
}

// ServeDNS implements the dns.Handler interface (UDP/TCP/DoT listeners).
func (s *Server) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	resp, drop := s.Resolve(r, clientIPFromRemote(w.RemoteAddr()))
	if drop || resp == nil {
		return
	}
	if isUDPNetwork(w.LocalAddr()) {
		resp = resp.Copy()
		resp.Truncate(int(clientUDPSize(r)))
	}
	_ = w.WriteMsg(resp)
}

func isUDPNetwork(addr net.Addr) bool {
	return addr != nil && strings.HasPrefix(strings.ToLower(addr.Network()), "udp")
}

// resolve runs the request pipeline and fills resp.
//
// Order: refuse-ANY / AAAA-disable short-circuits → typed rewrites → private
// PTR → safe-search (per-client aware) → filter (unless the client disabled
// filtering) → cache →
// forward (client upstreams → per-domain route → global pool) →
// bogus-NXDOMAIN conversion → cache store. depth bounds chase chains.
func (s *Server) resolve(
	r *dns.Msg,
	resp *dns.Msg,
	depth int,
	cl *clients.Client,
	clientIP string,
	cnamePath map[string]struct{},
) resolution {
	if r.Response || r.Opcode != dns.OpcodeQuery || len(r.Question) != 1 {
		resp.Rcode = dns.RcodeFormatError
		resp.Extra = responseExtra(r, nil)
		addExtendedError(resp, r, dns.ExtendedErrorCodeInvalidData, "expected one standard DNS query question")
		return resolution{}
	}
	q := r.Question[0]
	if _, valid := dns.IsDomainName(q.Name); !valid {
		resp.Rcode = dns.RcodeFormatError
		resp.Extra = responseExtra(r, nil)
		addExtendedError(resp, r, dns.ExtendedErrorCodeInvalidData, "invalid question name")
		return resolution{}
	}
	domain := normalizeName(q.Name)

	// Early policy short-circuits (before rewrites).
	if s.cfg.Policy != nil {
		if s.cfg.Policy.RefuseANY && q.Qtype == dns.TypeANY {
			resp.Rcode = dns.RcodeRefused
			resp.Extra = responseExtra(r, nil)
			addExtendedError(resp, r, dns.ExtendedErrorCodeProhibited, "ANY queries are disabled")
			return resolution{upstream: "Policy", matchedRule: "REFUSE_ANY", blockReason: policy.ReasonRefusedANY}
		}
		if s.cfg.Policy.AAAADisabled && q.Qtype == dns.TypeAAAA {
			// NODATA: NOERROR with an empty answer section.
			return resolution{upstream: "Policy", matchedRule: "AAAA_DISABLED", blockReason: policy.ReasonAAAADisabled}
		}
	}

	// Stage 1: typed rewrites (short-circuit, pre-cache).
	if res, handled := s.stageRewrites(r, q, resp, depth, cl, clientIP, cnamePath); handled {
		return res
	}

	// Stage 1b: automatic private PTR, below explicit user rewrites.
	if res, handled := s.stagePrivatePTR(q, resp); handled {
		return res
	}

	// Stage 2: safe search (global engines or per-client override).
	if res, handled := s.stageSafeSearch(r, q, resp, depth, cl, clientIP, cnamePath); handled {
		return res
	}

	// Stage 3: filter (skipped for clients with filtering disabled).
	// Blocked responses are NOT cached (cheap to regenerate; must not poison
	// the forwarded-answer cache).
	if s.filteringEnabledFor(cl) && s.cfg.Filter != nil && !s.cfg.Filter.Paused() {
		if f := s.cfg.Filter.Match(domain); f.Blocked && !f.Allowed {
			blockedResp := s.blockedResponse(r, q)
			resp.Rcode = blockedResp.Rcode
			resp.Answer = blockedResp.Answer
			resp.Extra = responseExtra(r, nil)
			addExtendedError(resp, r, dns.ExtendedErrorCodeFiltered, "blocked by filtering policy")
			return resolution{upstream: "Filtered", blocked: true, matchedRule: f.Rule, blockReason: f.Reason}
		}
	}

	// Stage 4: cache → forward → bogus-NXDOMAIN → cache store. Clients with
	// custom upstreams get a distinct cache group so their answers never
	// pollute the shared global cache.
	group, specs := clientUpstreamGroup(cl)
	if q.Qtype == dns.TypePTR {
		if ip := arpaToIP(q.Name); ip != nil && isPrivateIP(ip) && len(s.cfg.PrivatePTRUpstreams) > 0 {
			specs = s.cfg.PrivatePTRUpstreams
			group = "private-ptr:" + strings.Join(specs, ",")
		}
	}
	key := s.makeCacheKey(r, q, domain, group, cl)
	return s.resolveViaCacheOrUpstream(r, resp, key, specs)
}

// filteringEnabledFor reports whether the filter engine applies to a client.
func (s *Server) filteringEnabledFor(cl *clients.Client) bool {
	return cl == nil || cl.UseGlobalSettings || cl.FilteringEnabled
}

// clientUpstreamGroup returns the cache discriminator and custom upstream
// specs for a client (empty when the client uses the global pool).
func clientUpstreamGroup(cl *clients.Client) (group string, specs []string) {
	if cl == nil || cl.UseGlobalSettings || len(cl.Upstreams) == 0 {
		return "", nil
	}
	return "up:" + strings.Join(cl.Upstreams, ","), cl.Upstreams
}

// makeCacheKey includes every request dimension that can change an upstream
// response. Configuration swaps should additionally call the targeted
// invalidation methods so unreachable generations do not consume capacity.
func (s *Server) makeCacheKey(r *dns.Msg, q dns.Question, domain, group string, cl *clients.Client) cacheKey {
	key := cacheKey{
		name: domain, qtype: q.Qtype, qclass: q.Qclass, group: group,
		cd: r.CheckingDisabled, policy: clientPolicyScope(cl),
	}
	if opt := r.IsEdns0(); opt != nil {
		key.do = opt.Do()
		key.ecs = ecsScope(opt)
	}
	if group == "" && s.cfg.Routes != nil {
		key.route = s.cfg.Routes.GetUpstreamForDomain(domain)
	}
	return key
}

func clientPolicyScope(cl *clients.Client) string {
	if cl == nil || cl.UseGlobalSettings {
		return "global"
	}
	return strings.Join([]string{
		"custom",
		strconv.FormatBool(cl.FilteringEnabled),
		strconv.FormatBool(cl.SafeSearchEnabled),
		strings.Join(cl.SafeSearchEngines, ","),
		strings.Join(cl.Upstreams, ","),
	}, "|")
}

func ecsScope(opt *dns.OPT) string {
	var scopes []string
	for _, option := range opt.Option {
		subnet, ok := option.(*dns.EDNS0_SUBNET)
		if !ok {
			continue
		}
		address := subnet.Address
		bits := 128
		if subnet.Family == 1 {
			address = address.To4()
			bits = 32
		}
		if address == nil || int(subnet.SourceNetmask) > bits {
			scopes = append(scopes, fmt.Sprintf("%d/%d/%d/invalid", subnet.Family, subnet.SourceNetmask, subnet.SourceScope))
			continue
		}
		masked := address.Mask(net.CIDRMask(int(subnet.SourceNetmask), bits))
		scopes = append(scopes, fmt.Sprintf("%d/%d/%d/%s", subnet.Family, subnet.SourceNetmask, subnet.SourceScope, masked))
	}
	return strings.Join(scopes, ";")
}

// stageRewrites applies typed rewrites from the store (or the legacy
// StaticHosts fallback). handled is true when a rewrite answered the query.
func (s *Server) stageRewrites(
	request *dns.Msg,
	q dns.Question,
	resp *dns.Msg,
	depth int,
	cl *clients.Client,
	clientIP string,
	cnamePath map[string]struct{},
) (resolution, bool) {
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

	entries := s.cfg.Rewrites.LookupForClient(domain, clientIP)
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
			return s.chaseCNAME(request, q, resp, e.Value, e.String(), "Rewrite", "Rewrite", depth, cl, clientIP, cnamePath), true
		}
	}

	// The rewrite set covers this domain but not the qtype → NODATA.
	return resolution{upstream: "Rewrite", matchedRule: entries[0].String(), blockReason: "Rewrite"}, true
}

// stageSafeSearch rewrites configured safe-search domains to their
// restricted variants (pre-cache, like rewrites). Clients with global
// settings disabled use their own engine list (or inherit the global set).
func (s *Server) stageSafeSearch(
	request *dns.Msg,
	q dns.Question,
	resp *dns.Msg,
	depth int,
	cl *clients.Client,
	clientIP string,
	cnamePath map[string]struct{},
) (resolution, bool) {
	target := ""
	switch {
	case cl != nil && !cl.UseGlobalSettings:
		if cl.SafeSearchEnabled {
			engines := policy.ParseEngines(cl.SafeSearchEngines)
			if len(engines) == 0 && s.cfg.Policy != nil {
				engines = s.cfg.Policy.Engines()
			}
			target = policy.SafeSearchTargetFor(engines, normalizeName(q.Name))
		}
	case s.cfg.Policy != nil:
		target = s.cfg.Policy.SafeSearchTarget(normalizeName(q.Name))
	}
	if target == "" {
		return resolution{}, false
	}
	s.safeSearchHits.Add(1)

	// Address-type queries chase the restricted target through the rest of
	// the pipeline and return both the CNAME and the target's records.
	if q.Qtype == dns.TypeA || q.Qtype == dns.TypeAAAA || q.Qtype == dns.TypeCNAME {
		return s.chaseCNAME(
			request,
			q,
			resp,
			target,
			"SafeSearch",
			"SafeSearch",
			policy.ReasonSafeSearch,
			depth,
			cl,
			clientIP,
			cnamePath,
		), true
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
func (s *Server) chaseCNAME(
	request *dns.Msg,
	q dns.Question,
	resp *dns.Msg,
	target string,
	rule string,
	label string,
	reason string,
	depth int,
	cl *clients.Client,
	clientIP string,
	cnamePath map[string]struct{},
) resolution {
	source := normalizeName(q.Name)
	normalizedTarget := normalizeName(target)
	if _, seen := cnamePath[normalizedTarget]; seen || normalizedTarget == source || depth >= maxChainDepth {
		resp.Rcode = dns.RcodeServerFailure
		return resolution{
			upstream:    label,
			matchedRule: fmt.Sprintf("%s (CNAME loop at %s -> %s)", rule, source, normalizedTarget),
			blockReason: "CNAME_LOOP",
			ede: &dns.EDNS0_EDE{
				InfoCode:  dns.ExtendedErrorCodeOther,
				ExtraText: "CNAME loop detected",
			},
		}
	}
	cnamePath[source] = struct{}{}
	fqdn := dns.Fqdn(target)
	cname := &dns.CNAME{
		Hdr:    dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: staticTTL},
		Target: fqdn,
	}
	sub := request.Copy()
	sub.Response = false
	sub.Question = []dns.Question{{Name: fqdn, Qtype: q.Qtype, Qclass: q.Qclass}}
	sub.Answer = nil
	sub.Ns = nil
	subResp := new(dns.Msg)
	subResp.SetReply(sub)
	subResp.RecursionAvailable = true
	subResolution := s.resolve(sub, subResp, depth+1, cl, clientIP, cnamePath)

	resp.Rcode = subResp.Rcode
	resp.Answer = append([]dns.RR{cname}, subResp.Answer...)
	resp.Ns = subResp.Ns
	if subResolution.blockReason == "CNAME_LOOP" {
		return subResolution
	}
	return resolution{upstream: label, blocked: subResolution.blocked, matchedRule: rule, blockReason: reason}
}

// blockedResponse builds the response for a filtered query according to the
// configured blocking mode and response TTL.
func (s *Server) blockedResponse(r *dns.Msg, question dns.Question) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetReply(r)
	resp.RecursionAvailable = true

	ttl := s.cfg.BlockedResponseTTL
	if ttl == 0 {
		ttl = staticTTL
	}
	hdr := dns.RR_Header{
		Name:   question.Name,
		Class:  dns.ClassINET,
		Ttl:    ttl,
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
// cache-store stages. It fills resp on success. specs, when non-empty, are
// per-client custom upstreams used instead of routes/global pool.
func (s *Server) resolveViaCacheOrUpstream(r *dns.Msg, resp *dns.Msg, key cacheKey, specs []string) resolution {
	// Stage: cache lookup.
	if ent, remaining, ok := s.cache.get(key); ok {
		applyCacheEntry(resp, r, ent, remaining)
		state, label := cacheEntryState(ent)
		if s.shouldPrefetch(ent, remaining) {
			s.refreshAsync(key, r.Copy(), specs, true)
		}
		return resolution{
			upstream: label, cacheHit: true, cacheState: state,
			cacheTTL: remaining, negativeSOA: ent.negativeSOA,
		}
	}

	// Optimistic caching: serve the stale entry with TTL 1 and refresh in
	// the background (single-flight per key).
	if s.cfg.CacheOptimistic {
		if ent, ok := s.cache.getStale(key); ok {
			applyCacheEntry(resp, r, ent, 1)
			code := dns.ExtendedErrorCodeStaleAnswer
			label := "System Cache (stale)"
			if ent.negative {
				code = dns.ExtendedErrorCodeStaleNXDOMAINAnswer
				label = "System Cache (stale negative)"
			}
			addExtendedError(resp, r, code, "stale answer served while refreshing")
			s.refreshAsync(key, r.Copy(), specs, false)
			return resolution{
				upstream: label, cacheHit: true, cacheState: cacheStateStale,
				cacheTTL: 1, negativeSOA: ent.negativeSOA,
			}
		}
	}

	// Coalesce concurrent misses for the same complete cache key. If the
	// bounded flight table is full, the caller proceeds independently.
	generation := s.cacheGeneration.Load()
	flight, leader := s.beginMissFlight(key)
	if flight == nil {
		resp.Rcode = dns.RcodeServerFailure
		resp.Extra = responseExtra(r, nil)
		addExtendedError(resp, r, dns.ExtendedErrorCodeNetworkError, "upstream concurrency limit reached")
		return resolution{upstream: "Overloaded", blockReason: "UPSTREAM_CAPACITY"}
	}
	if !leader {
		<-flight.done
		s.cache.coalesced.Add(1)
		result := cloneUpstreamResult(flight.result)
		s.applyUpstreamResult(resp, r, result)
		return resolution{
			upstream: result.upstream, cacheState: cacheStateCoalesced,
			matchedRule: result.matchedRule, blockReason: result.blockReason,
		}
	}

	result := s.fetchUpstreamResult(r, specs)
	if result.msg != nil {
		s.storeInCacheIfGeneration(key, result.msg, false, generation)
	}
	s.completeMissFlight(key, flight, result)
	s.applyUpstreamResult(resp, r, result)
	return resolution{
		upstream:    result.upstream,
		matchedRule: result.matchedRule,
		blockReason: result.blockReason,
	}
}

func applyCacheEntry(resp, request *dns.Msg, ent *cacheEntry, ttl uint32) {
	resp.Rcode = ent.rcode
	resp.AuthenticatedData = ent.authenticatedData
	resp.Answer = withTTL(ent.answers, ttl)
	resp.Ns = withTTL(ent.authority, ttl)
	resp.Extra = responseExtra(request, nil)
	if ent.servfail {
		addExtendedError(resp, request, dns.ExtendedErrorCodeCachedError, "cached upstream failure")
	}
}

func cacheEntryState(ent *cacheEntry) (state, label string) {
	switch {
	case ent.prefetched && ent.negative:
		return cacheStatePrefetched, "System Cache (prefetched negative)"
	case ent.prefetched:
		return cacheStatePrefetched, "System Cache (prefetched)"
	case ent.negative:
		return cacheStateNegative, "System Cache (negative)"
	case ent.servfail:
		return cacheStateSERVFAIL, "System Cache (servfail)"
	default:
		return cacheStateFresh, "System Cache"
	}
}

func (s *Server) shouldPrefetch(ent *cacheEntry, remaining uint32) bool {
	return s.cfg.CachePrefetch && ent.hits >= s.cfg.CachePrefetchHits &&
		time.Duration(remaining)*time.Second <= s.cfg.CachePrefetchWindow
}

func (s *Server) fetchUpstreamResult(r *dns.Msg, specs []string) upstreamResult {
	usedUpstream, message := s.forward(r, specs)
	if message == nil {
		message = new(dns.Msg)
		message.SetReply(r)
		message.Rcode = dns.RcodeServerFailure
		return upstreamResult{upstream: usedUpstream, msg: message}
	}

	// Bogus-NXDOMAIN conversion runs before cache storage. The converted
	// response is intentionally not cacheable because it has no authority SOA.
	if s.cfg.Policy != nil && s.cfg.Policy.IsBogusAnswer(message.Answer) {
		s.bogusNXHits.Add(1)
		converted := new(dns.Msg)
		converted.SetReply(r)
		converted.Rcode = dns.RcodeNameError
		return upstreamResult{
			upstream: usedUpstream, msg: converted,
			matchedRule: "BOGUS_NXDOMAIN", blockReason: policy.ReasonBogusNX,
		}
	}
	return upstreamResult{upstream: usedUpstream, msg: message}
}

func (s *Server) applyUpstreamResult(resp, request *dns.Msg, result upstreamResult) {
	if result.msg == nil {
		resp.Rcode = dns.RcodeServerFailure
		resp.Extra = responseExtra(request, nil)
		addExtendedError(resp, request, dns.ExtendedErrorCodeNetworkError, "no reachable upstream")
		return
	}
	resp.Rcode = result.msg.Rcode
	resp.AuthenticatedData = result.msg.AuthenticatedData
	resp.Answer = copyRRs(result.msg.Answer)
	resp.Ns = copyRRs(result.msg.Ns)
	resp.Extra = responseExtra(request, result.msg.Extra)
	if result.msg.Rcode == dns.RcodeServerFailure {
		addExtendedError(resp, request, dns.ExtendedErrorCodeNetworkError, "no reachable upstream")
	}
}

func cloneUpstreamResult(result upstreamResult) upstreamResult {
	if result.msg != nil {
		result.msg = result.msg.Copy()
	}
	return result
}

func (s *Server) beginMissFlight(key cacheKey) (*missFlight, bool) {
	s.missMu.Lock()
	defer s.missMu.Unlock()
	if flight, ok := s.missInFlight[key]; ok {
		flight.waiters++
		return flight, false
	}
	if len(s.missInFlight) >= maxMissFlights {
		return nil, false
	}
	flight := &missFlight{done: make(chan struct{})}
	s.missInFlight[key] = flight
	return flight, true
}

func (s *Server) completeMissFlight(key cacheKey, flight *missFlight, result upstreamResult) {
	if flight == nil {
		return
	}
	s.missMu.Lock()
	flight.result = cloneUpstreamResult(result)
	delete(s.missInFlight, key)
	close(flight.done)
	s.missMu.Unlock()
}

// responseExtra preserves non-OPT additional records from upstream and
// creates an OPT record from the current client's EDNS request. Upstream OPT
// records are hop-by-hop and must not be relayed or cached for another client.
func responseExtra(request *dns.Msg, upstreamExtra []dns.RR) []dns.RR {
	extra := make([]dns.RR, 0, len(upstreamExtra)+1)
	for _, rr := range upstreamExtra {
		if _, ok := rr.(*dns.OPT); !ok {
			extra = append(extra, dns.Copy(rr))
		}
	}
	requestOPT := request.IsEdns0()
	if requestOPT == nil {
		return extra
	}
	opt := new(dns.OPT)
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = dns.TypeOPT
	opt.SetUDPSize(clientUDPSize(request))
	opt.SetVersion(requestOPT.Version())
	opt.SetDo(requestOPT.Do())
	return append(extra, opt)
}

func clientUDPSize(request *dns.Msg) uint16 {
	if request == nil {
		return dns.MinMsgSize
	}
	requestOPT := request.IsEdns0()
	if requestOPT == nil {
		return dns.MinMsgSize
	}
	size := requestOPT.UDPSize()
	if size < dns.MinMsgSize {
		return dns.MinMsgSize
	}
	if size > defaultEDNSUDPSize {
		return defaultEDNSUDPSize
	}
	return size
}

func addExtendedError(resp, request *dns.Msg, code uint16, text string) {
	if request == nil || request.IsEdns0() == nil {
		return
	}
	opt := resp.IsEdns0()
	if opt == nil {
		resp.Extra = responseExtra(request, resp.Extra)
		opt = resp.IsEdns0()
	}
	if opt == nil {
		return
	}
	opt.Option = append(opt.Option, &dns.EDNS0_EDE{InfoCode: code, ExtraText: text})
}

// refreshAsync repopulates a stale cache entry in the background,
// single-flight per key. No event is emitted (not a client query).
func (s *Server) refreshAsync(key cacheKey, r *dns.Msg, specs []string, prefetch bool) {
	generation := s.cacheGeneration.Load()
	select {
	case s.refreshSlots <- struct{}{}:
	default:
		return
	}
	s.refreshMu.Lock()
	if s.refreshInFlight[key] {
		s.refreshMu.Unlock()
		<-s.refreshSlots
		return
	}
	s.refreshInFlight[key] = true
	s.refreshMu.Unlock()

	go func() {
		s.runtimeMu.RLock()
		defer s.runtimeMu.RUnlock()
		defer func() {
			<-s.refreshSlots
			s.refreshMu.Lock()
			delete(s.refreshInFlight, key)
			s.refreshMu.Unlock()
		}()
		result := s.fetchUpstreamResult(r, specs)
		if result.msg != nil && result.msg.Rcode != dns.RcodeServerFailure &&
			s.storeInCacheIfGeneration(key, result.msg, prefetch, generation) {
			s.cache.refreshes.Add(1)
			if prefetch {
				s.cache.prefetches.Add(1)
			}
		}
	}()
}

// ApplySettings replaces live-safe DNS behavior. Active requests finish with
// one coherent policy while new requests observe the replacement.
func (s *Server) ApplySettings(settings dnssettings.Settings) {
	settings = settings.Normalize()
	s.runtimeMu.Lock()
	defer s.runtimeMu.Unlock()
	s.cfg.BlockingMode = settings.BlockingMode
	s.cfg.BlockCustomIP4 = settings.BlockCustomIPv4
	s.cfg.BlockCustomIP6 = settings.BlockCustomIPv6
	s.cfg.BlockedResponseTTL = settings.BlockedResponseTTL
	s.cfg.Policy = policy.New(policy.Config{
		SafeSearch:   settings.SafeSearch,
		BogusNets:    settings.BogusNXDOMAIN,
		AAAADisabled: settings.AAAADisabled,
		RefuseANY:    settings.RefuseANY,
	})
	s.cfg.AllowedClients = strings.Join(settings.AllowedClients, " ")
	s.cfg.DisallowedClients = strings.Join(settings.DisallowedClients, " ")
	s.allowed = parseCIDRList(s.cfg.AllowedClients)
	s.allowedConfigured = len(settings.AllowedClients) > 0
	s.disallowed = parseCIDRList(s.cfg.DisallowedClients)
	s.cfg.RateLimitQPS = settings.RateLimitQPS
	s.cfg.InternalRateLimitQPS = settings.InternalRateLimitQPS
	s.cfg.RateLimitEDE = settings.RateLimitEDE
	s.cfg.RateLimitIPv4Prefix = settings.RateLimitIPv4Prefix
	s.cfg.RateLimitIPv6Prefix = settings.RateLimitIPv6Prefix
	s.cfg.RateLimitAllowlist = strings.Join(settings.RateLimitAllowlist, " ")
	s.rateLimitAllowlist = parseCIDRList(s.cfg.RateLimitAllowlist)
	s.cfg.PrivatePTR = settings.PrivatePTR
	s.cfg.PrivatePTRUpstreams = append([]string(nil), settings.PrivatePTRUpstreams...)
	s.cfg.ResolveClientHostnames = settings.ResolveClientHostnames
	s.cfg.DNSSEC = settings.DNSSEC
	s.cfg.CacheOptimistic = settings.CacheOptimistic
	s.cfg.CachePrefetch = settings.CachePrefetch
	s.cfg.CachePrefetchWindow = time.Duration(settings.CachePrefetchWindowMS) * time.Millisecond
	s.cfg.CachePrefetchHits = settings.CachePrefetchHits
	s.cfg.CacheSERVFAILTTL = time.Duration(settings.CacheSERVFAILTTLMS) * time.Millisecond
	s.cache.reconfigure(
		settings.CacheSize,
		settings.CacheMinTTL,
		settings.CacheMaxTTL,
		settings.CacheOptimistic,
	)
}

// forward resolves r through the upstream pool. Per-client custom upstreams
// (specs) override per-domain routes and the global pool; per-domain DNS
// routes take precedence over the global pool (route failure falls back).
// When no pool is configured (legacy/tests), the plain strict-order path is
// used.
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
func (s *Server) storeInCache(key cacheKey, m *dns.Msg) {
	s.cacheMutationMu.Lock()
	defer s.cacheMutationMu.Unlock()
	s.storeInCacheWithSource(key, m, false)
}

// storeInCacheIfGeneration publishes a fetched response only when no cache
// invalidation has completed since the fetch started. The generation check and
// cache mutation share the same lock as invalidation, making the operation
// linearizable: either the store precedes an invalidation and is removed by it,
// or it follows the invalidation and is rejected as stale.
func (s *Server) storeInCacheIfGeneration(
	key cacheKey,
	m *dns.Msg,
	prefetched bool,
	generation uint64,
) bool {
	s.cacheMutationMu.Lock()
	defer s.cacheMutationMu.Unlock()
	if generation != s.cacheGeneration.Load() {
		return false
	}
	s.storeInCacheWithSource(key, m, prefetched)
	return true
}

func (s *Server) storeInCacheWithSource(key cacheKey, m *dns.Msg, prefetched bool) {
	if m == nil || m.Truncated {
		return
	}
	ent := &cacheEntry{
		answers:           copyRRs(m.Answer),
		authority:         copyRRs(m.Ns),
		rcode:             m.Rcode,
		authenticatedData: m.AuthenticatedData,
		storedAt:          time.Now(),
		prefetched:        prefetched,
	}

	switch {
	case m.Rcode == dns.RcodeSuccess && len(m.Answer) > 0:
		// Positive answer: min answer TTL clamped to the configured bounds.
		ent.ttl = s.cache.clamp(minAnswerTTL(m.Answer))
	case m.Rcode == dns.RcodeNameError || (m.Rcode == dns.RcodeSuccess && len(m.Answer) == 0):
		// Negative answer (NXDOMAIN/NODATA): SOA TTL clamped to the max.
		ttl, origin, ok := soaMetadata(m.Ns)
		if !ok {
			return
		}
		if ttl > s.cache.maxTTL {
			ttl = s.cache.maxTTL
		}
		if ttl == 0 {
			return
		}
		ent.ttl = ttl
		ent.negative = true
		ent.negativeSOA = origin
	case m.Rcode == dns.RcodeServerFailure && s.cfg.CacheSERVFAILTTL > 0:
		ent.ttl = 1
		ent.servfail = true
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

// buildEvent assembles the QueryEvent for an answered query. A matching
// registry client's name wins over CLIENT_ALIASES for the Alias field.
func (s *Server) buildEvent(r, resp *dns.Msg, clientIP string, cl *clients.Client, res resolution, start time.Time) models.QueryEvent {
	ev := models.QueryEvent{
		UnixTime:    time.Now().Unix(),
		Node:        s.cfg.NodeName,
		Upstream:    res.upstream,
		Blocked:     res.blocked,
		MatchedRule: res.matchedRule,
		BlockReason: res.blockReason,
		CacheStatus: res.cacheState,
		CacheTTL:    res.cacheTTL,
		NegativeSOA: res.negativeSOA,
	}
	if len(r.Question) > 0 {
		ev.Type = dns.TypeToString[r.Question[0].Qtype]
		ev.Domain = normalizeName(r.Question[0].Name)
	}
	ev.ClientIP = clientIP
	ev.ResponseCode = dns.RcodeToString[resp.Rcode]
	if s.cfg.ResolveClientHostnames && s.cfg.Resolver != nil {
		ev.ClientHostname = s.cfg.Resolver.GetHostname(clientIP)
	}

	// DNSSEC passthrough status (no local validation): only an upstream AD bit
	// proves a secure response; all other responses remain indeterminate.
	if s.cfg.DNSSEC {
		if resp.AuthenticatedData {
			ev.DNSSEC = "secure"
		} else {
			ev.DNSSEC = "indeterminate"
		}
	}

	// Alias: registry client name wins; otherwise fall back to CLIENT_ALIASES.
	switch {
	case cl != nil:
		ev.Alias = cl.Name
	case s.cfg.AliasFunc != nil:
		ev.Alias = s.cfg.AliasFunc(clientIP)
	}

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

// RateLimitDropped returns the number of queries silently dropped by the rate limiter.
func (s *Server) RateLimitDropped() int64 {
	return s.rateLimitDropped.Load()
}

// Ready reports whether all configured DNS listeners have been started.
func (s *Server) Ready() bool {
	return s.ready.Load()
}

// ACLStats reports ACL drops and active rate-limit buckets.
func (s *Server) ACLStats() (deniedDropped, allowlistDropped int64, buckets int) {
	if s.rateLimiter != nil {
		buckets = s.rateLimiter.bucketCount()
	}
	return s.aclDropped.Load(), s.aclAllowlistDropped.Load(), buckets
}

// CacheStats returns a snapshot of the in-process response cache.
func (s *Server) CacheStats() CacheStats {
	stats := s.cache.stats()
	s.missMu.Lock()
	stats.InFlight = len(s.missInFlight)
	s.missMu.Unlock()
	return stats
}

// CacheEntries returns a stable diagnostic snapshot. Negative entries include
// their remaining TTL and SOA; answer data is not exposed.
func (s *Server) CacheEntries() []CacheEntryStatus {
	return s.cache.entryStatuses()
}

// ClearCache removes all in-process DNS response cache entries and returns
// the number removed.
func (s *Server) ClearCache() int {
	s.cacheMutationMu.Lock()
	defer s.cacheMutationMu.Unlock()
	s.cacheGeneration.Add(1)
	return s.cache.clear()
}

// InvalidateCacheDomains removes cache entries at or below the supplied
// domain suffixes. It is intended for rewrite, filter, and DNS-route updates.
func (s *Server) InvalidateCacheDomains(domains ...string) int {
	normalized := make([]string, 0, len(domains))
	for _, domain := range domains {
		domain = normalizeName(strings.TrimPrefix(strings.TrimSpace(domain), "*."))
		if domain != "" {
			normalized = append(normalized, domain)
		}
	}
	if len(normalized) == 0 {
		return 0
	}
	s.cacheMutationMu.Lock()
	defer s.cacheMutationMu.Unlock()
	s.cacheGeneration.Add(1)
	return s.cache.invalidate(func(key cacheKey) bool {
		for _, domain := range normalized {
			if key.name == domain || strings.HasSuffix(key.name, "."+domain) {
				return true
			}
		}
		return false
	})
}

// InvalidateCacheRoutes removes entries resolved through any supplied route
// upstream spec. Callers should pass both old and new specs when a route is
// changed.
func (s *Server) InvalidateCacheRoutes(routeSpecs ...string) int {
	routes := make(map[string]struct{}, len(routeSpecs))
	for _, spec := range routeSpecs {
		if spec = strings.TrimSpace(spec); spec != "" {
			routes[spec] = struct{}{}
		}
	}
	if len(routes) == 0 {
		return 0
	}
	s.cacheMutationMu.Lock()
	defer s.cacheMutationMu.Unlock()
	s.cacheGeneration.Add(1)
	return s.cache.invalidate(func(key cacheKey) bool {
		_, match := routes[key.route]
		return match
	})
}

// InvalidateCacheGroups removes entries for exact per-client upstream group
// discriminators. An empty group represents the global upstream pool.
func (s *Server) InvalidateCacheGroups(groups ...string) int {
	selected := make(map[string]struct{}, len(groups))
	for _, group := range groups {
		selected[group] = struct{}{}
	}
	if len(selected) == 0 {
		return 0
	}
	s.cacheMutationMu.Lock()
	defer s.cacheMutationMu.Unlock()
	s.cacheGeneration.Add(1)
	return s.cache.invalidate(func(key cacheKey) bool {
		_, match := selected[key.group]
		return match
	})
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

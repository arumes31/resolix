// Package dnsserver implements the in-process DNS server that replaces
// dnsmasq. It serves UDP and TCP listeners and answers queries through an
// ordered pipeline: refuse-ANY/AAAA-disable → typed rewrites → MagicDNS →
// private PTR → safe-search → filter → cache → client upstreams →
// domain route → global pool → bogus-NXDOMAIN → cache store → respond.
// Every answered query is emitted as a models.QueryEvent into the existing
// Store/SSE pipeline.
package dnsserver

import (
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"github.com/arumes31/resolix/webgui/internal/clients"
	"github.com/arumes31/resolix/webgui/internal/dnsroutes"
	"github.com/arumes31/resolix/webgui/internal/filter"
	"github.com/arumes31/resolix/webgui/internal/magicdns"
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
	// MagicDNS is the read-only, controller-synchronized Tailscale record store.
	MagicDNS *magicdns.Store
	// MagicDNSTTL is applied to generated MagicDNS A and AAAA answers.
	MagicDNSTTL uint32
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

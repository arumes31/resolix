package dnsserver

import (
	"database/sql"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/arumes31/resolix/webgui/internal/clients"
	"github.com/arumes31/resolix/webgui/internal/dnssettings"
	"github.com/arumes31/resolix/webgui/internal/models"
	"github.com/arumes31/resolix/webgui/internal/policy"
)

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
	s.cacheMutationMu.Lock()
	s.cacheGeneration.Add(1)
	s.cache.reconfigure(
		settings.CacheSize,
		settings.CacheMinTTL,
		settings.CacheMaxTTL,
		settings.CacheOptimistic,
	)
	s.cacheMutationMu.Unlock()
}

// forward resolves r through the upstream pool. Per-client custom upstreams
// (specs) override per-domain routes and the global pool; per-domain DNS
// routes take precedence over the global pool (route failure falls back).
// When no pool is configured (legacy/tests), the plain strict-order path is
// used.

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

package dnsserver

import (
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/arumes31/resolix/webgui/internal/policy"
)

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
		// DNS TTLs are whole seconds. Backdate the one-second entry so its
		// effective lifetime follows the configured subsecond SERVFAIL bound.
		ent.storedAt = ent.storedAt.Add(s.cfg.CacheSERVFAILTTL - time.Second)
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

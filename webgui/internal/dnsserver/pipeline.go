package dnsserver

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/arumes31/resolix/webgui/internal/clients"
	"github.com/arumes31/resolix/webgui/internal/policy"
	"github.com/arumes31/resolix/webgui/internal/rewrites"
)

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

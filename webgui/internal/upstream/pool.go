package upstream

import (
	"context"
	"fmt"
	"log"
	"math/rand/v2"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// Pool modes (UPSTREAM_MODE).
const (
	ModeLoadBalance   = "load_balance"
	ModeParallel      = "parallel"
	ModeStrict        = "strict"
	maxResolverGroups = 256
)

// PoolConfig configures the upstream pool.
type PoolConfig struct {
	// Mode: load_balance (default) | parallel | strict.
	Mode string
	// PrimarySpecs / FallbackSpecs are upstream specs (see Parse).
	PrimarySpecs  []string
	FallbackSpecs []string
	// BootstrapServers are plain UDP resolvers for hostname upstreams.
	BootstrapServers []string
	// ECSClientSubnet, when set, is attached as EDNS0 client subnet.
	ECSClientSubnet string
	// DNS64 enables AAAA synthesis from A records on empty AAAA answers.
	DNS64 bool
	// DNS64Prefixes are the synthesis prefixes (default 64:ff9b::/96).
	DNS64Prefixes []string
	// CacheMinTTL/CacheMaxTTL also bound bootstrap address caching.
	CacheMinTTL uint32
	CacheMaxTTL uint32
}

// stat tracks per-upstream performance.
type stat struct {
	ewmaMS         float64 // exponentially weighted moving average latency
	failures       atomic.Int64
	failurePenalty atomic.Int64
	successes      atomic.Int64
}

// StatSnapshot reports per-upstream stats for metrics.
type StatSnapshot struct {
	Spec      string  `json:"spec"`
	EWMAms    float64 `json:"ewma_ms"`
	Failures  int64   `json:"failures"`
	Successes int64   `json:"successes"`
	Healthy   bool    `json:"healthy"`
}

// Pool resolves queries against a set of upstreams with a configurable
// selection mode, fallback list, health awareness, ECS, and DNS64.
type Pool struct {
	cfg PoolConfig

	mu       sync.RWMutex
	primary  []Resolver
	fallback []Resolver
	routes   map[string]Resolver   // route-spec resolver cache
	groups   map[string][]Resolver // per-client spec-set resolver cache

	boot *bootstrapper

	statsMu sync.Mutex
	stats   map[string]*stat

	healthFn atomic.Value // func() map[string]float64 (latency ms; <0 = unhealthy)

	ecsIP     net.IP
	ecsBits   int
	ecsFamily uint16

	dns64Prefixes []*net.IPNet
}

// NewPool builds the pool from the configuration. Invalid specs are skipped
// with warnings; the pool never fails hard so DNS keeps working with
// whatever valid upstreams remain.
func NewPool(cfg PoolConfig) *Pool {
	p := &Pool{
		cfg:    cfg,
		routes: make(map[string]Resolver),
		groups: make(map[string][]Resolver),
		stats:  make(map[string]*stat),
		boot:   newBootstrapper(cfg.BootstrapServers),
	}
	p.boot.setTTLLimits(cfg.CacheMinTTL, cfg.CacheMaxTTL)
	if cfg.Mode == "" {
		p.cfg.Mode = ModeLoadBalance
	}

	if cfg.ECSClientSubnet != "" {
		if err := p.parseECS(cfg.ECSClientSubnet); err != nil {
			log.Printf("[WARN] Invalid ECS_CLIENT_SUBNET %q: %v (ignoring)", cfg.ECSClientSubnet, err)
		}
	}

	if cfg.DNS64 {
		prefixes := cfg.DNS64Prefixes
		if len(prefixes) == 0 {
			prefixes = []string{"64:ff9b::/96"}
		}
		for _, raw := range prefixes {
			ip, n, err := net.ParseCIDR(strings.TrimSpace(raw))
			ones, bits := 0, 0
			if err == nil {
				ones, bits = n.Mask.Size()
			}
			if err != nil || ip.To4() != nil || ones != 96 || bits != 128 {
				log.Printf("[WARN] Invalid DNS64 prefix %q (ignoring)", raw)
				continue
			}
			p.dns64Prefixes = append(p.dns64Prefixes, n)
		}
	}

	p.primary = p.buildResolvers(cfg.PrimarySpecs)
	p.fallback = p.buildResolvers(cfg.FallbackSpecs)
	p.warnHostnameUpstreams()
	return p
}

// warnHostnameUpstreams logs a warning when hostname upstreams exist but no
// bootstrap DNS is configured.
func (p *Pool) warnHostnameUpstreams() {
	if p.boot.Enabled() {
		return
	}
	for _, r := range p.allResolvers() {
		if dr, ok := r.(*dnsResolver); ok && dr.spec.Hostname() {
			log.Printf("[WARN] Upstream %q uses a hostname but BOOTSTRAP_DNS is not set", dr.spec.Raw)
		}
		if hr, ok := r.(*dohResolver); ok && hr.spec.Hostname() {
			log.Printf("[WARN] Upstream %q uses a hostname but BOOTSTRAP_DNS is not set", hr.spec.Raw)
		}
	}
}

// buildResolvers parses specs into resolvers, skipping invalid entries.
func (p *Pool) buildResolvers(specs []string) []Resolver {
	var out []Resolver
	for _, raw := range specs {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		spec, err := Parse(raw)
		if err != nil {
			log.Printf("[WARN] Ignoring invalid upstream spec %q: %v", raw, err)
			continue
		}
		out = append(out, p.newResolver(spec))
	}
	return out
}

// newResolver creates the resolver implementation for a spec.
func (p *Pool) newResolver(spec Spec) Resolver {
	if spec.Scheme == SchemeHTTPS {
		return &dohResolver{spec: spec, boot: p.boot}
	}
	return &dnsResolver{spec: spec, boot: p.boot}
}

// SetPrimarySpecs rebuilds the primary resolver set (upstreams.json override
// hot-reload).
func (p *Pool) SetPrimarySpecs(specs []string) {
	p.mu.Lock()
	p.primary = p.buildResolvers(specs)
	p.mu.Unlock()
	p.warnHostnameUpstreams()
}

// ClearRouteCache drops resolvers created for domain-specific routes.
func (p *Pool) ClearRouteCache() {
	p.mu.Lock()
	p.routes = make(map[string]Resolver)
	p.mu.Unlock()
}

// SetHealthProvider installs the health data source (spec → latency ms,
// negative = unhealthy). Called by main after the store is available.
func (p *Pool) SetHealthProvider(fn func() map[string]float64) {
	p.healthFn.Store(fn)
}

// allResolvers returns primary + fallback (for introspection).
func (p *Pool) allResolvers() []Resolver {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := append([]Resolver(nil), p.primary...)
	return append(out, p.fallback...)
}

// healthy filters resolvers by the health provider. Resolvers unknown to the
// health data (e.g. encrypted upstreams the UDP prober cannot check) are
// considered healthy.
func (p *Pool) healthy(rs []Resolver) []Resolver {
	fn, _ := p.healthFn.Load().(func() map[string]float64)
	if fn == nil {
		return rs
	}
	health := fn()
	out := make([]Resolver, 0, len(rs))
	for _, r := range rs {
		lat, known := health[r.String()]
		if known && lat < 0 {
			continue
		}
		out = append(out, r)
	}
	if len(out) == 0 {
		// Never return an empty set while candidates exist: better to try a
		// possibly-unhealthy upstream than to fail every query.
		return rs
	}
	return out
}

// Exchange resolves m through the pool according to the configured mode.
// It returns the response and the upstream spec actually used.
func (p *Pool) Exchange(m *dns.Msg) (*dns.Msg, string, error) {
	p.mu.RLock()
	primary := append([]Resolver(nil), p.primary...)
	fallback := append([]Resolver(nil), p.fallback...)
	p.mu.RUnlock()
	primary = p.healthy(primary)

	resp, used, err := p.exchangeByMode(primary, m)
	if err == nil {
		return resp, used, nil
	}
	if len(fallback) > 0 {
		log.Printf("[DEBUG] All primary upstreams failed (%v); trying fallback", err)
		return p.exchangeByMode(p.healthy(fallback), m)
	}
	return nil, "", err
}

// ExchangeRoute resolves m through a specific route upstream spec (per-domain
// DNS routes). Route resolvers are cached and stats-tracked like primaries.
// On route failure the caller falls back to the normal pool exchange.
func (p *Pool) ExchangeRoute(spec string, m *dns.Msg) (*dns.Msg, string, error) {
	r, err := p.routeResolver(spec)
	if err != nil {
		return nil, spec, err
	}
	resp, err := p.exchange(r, m)
	return resp, spec, err
}

// ExchangeSpecs resolves m through an ad-hoc upstream spec set (per-client
// custom upstreams), using the pool's selection mode. Resolvers are cached
// per distinct spec set.
func (p *Pool) ExchangeSpecs(specs []string, m *dns.Msg) (*dns.Msg, string, error) {
	rs := p.groupResolvers(specs)
	if len(rs) == 0 {
		return nil, "", fmt.Errorf("no usable upstreams in spec set")
	}
	return p.exchangeByMode(rs, m)
}

// groupResolvers returns a cached resolver set for a spec list.
func (p *Pool) groupResolvers(specs []string) []Resolver {
	key := strings.Join(specs, "\x00")
	p.mu.RLock()
	rs, ok := p.groups[key]
	p.mu.RUnlock()
	if ok {
		return rs
	}
	rs = p.buildResolvers(specs)
	p.mu.Lock()
	if cached, exists := p.groups[key]; exists {
		p.mu.Unlock()
		return cached
	}
	if len(p.groups) >= maxResolverGroups {
		for oldestKey := range p.groups {
			delete(p.groups, oldestKey)
			break
		}
	}
	p.groups[key] = rs
	p.mu.Unlock()
	return rs
}

// routeResolver returns a cached resolver for a route spec.
func (p *Pool) routeResolver(raw string) (Resolver, error) {
	p.mu.RLock()
	r, ok := p.routes[raw]
	p.mu.RUnlock()
	if ok {
		return r, nil
	}
	spec, err := Parse(raw)
	if err != nil {
		return nil, err
	}
	r = p.newResolver(spec)
	p.mu.Lock()
	p.routes[raw] = r
	p.mu.Unlock()
	return r, nil
}

// exchangeByMode applies the selection mode to a candidate list.
func (p *Pool) exchangeByMode(candidates []Resolver, m *dns.Msg) (*dns.Msg, string, error) {
	if len(candidates) == 0 {
		return nil, "", fmt.Errorf("no upstreams available")
	}
	switch p.cfg.Mode {
	case ModeParallel:
		return p.exchangeParallel(candidates, m)
	case ModeLoadBalance:
		return p.exchangeLoadBalanced(candidates, m)
	default: // strict
		return p.exchangeStrict(candidates, m)
	}
}

// exchangeStrict tries candidates in order; first success wins.
func (p *Pool) exchangeStrict(candidates []Resolver, m *dns.Msg) (*dns.Msg, string, error) {
	var lastErr error
	for _, r := range candidates {
		resp, err := p.exchange(r, m)
		if err == nil && resp != nil {
			return resp, r.String(), nil
		}
		lastErr = err
	}
	return nil, "", lastErr
}

// exchangeParallel races all candidates; the first valid response wins.
func (p *Pool) exchangeParallel(candidates []Resolver, m *dns.Msg) (*dns.Msg, string, error) {
	type result struct {
		resp *dns.Msg
		spec string
		err  error
	}
	ctx, cancel := context.WithTimeout(context.Background(), exchangeTimeout+time.Second)
	defer cancel()
	results := make(chan result, len(candidates))
	for _, r := range candidates {
		go func(r Resolver) {
			resp, err := p.exchangeContext(ctx, r, m.Copy())
			results <- result{resp: resp, spec: r.String(), err: err}
		}(r)
	}
	var failures []error
	for range candidates {
		select {
		case res := <-results:
			if res.err == nil && res.resp != nil {
				cancel()
				return res.resp, res.spec, nil
			}
			if res.err != nil {
				failures = append(failures, res.err)
			}
		case <-ctx.Done():
			return nil, "", fmt.Errorf("parallel exchange: %w", ctx.Err())
		}
	}
	return nil, "", fmt.Errorf("parallel exchange: all %d upstreams failed: %v", len(candidates), failures)
}

// exchangeLoadBalanced picks candidates in weighted-random order, preferring
// lower latency and fewer failures, then tries them in that order.
func (p *Pool) exchangeLoadBalanced(candidates []Resolver, m *dns.Msg) (*dns.Msg, string, error) {
	ordered := p.weightedOrder(candidates)
	return p.exchangeStrict(ordered, m)
}

// weightedOrder shuffles candidates into weighted-random order. Weight is
// inversely proportional to (1 + EWMA ms) and (1 + failures).
func (p *Pool) weightedOrder(candidates []Resolver) []Resolver {
	weights := make([]float64, len(candidates))
	for i, r := range candidates {
		st := p.statFor(r.String())
		p.statsMu.Lock()
		ewma := st.ewmaMS
		p.statsMu.Unlock()
		if ewma <= 0 {
			ewma = 1
		}
		weights[i] = 1 / (ewma * float64(1+st.failurePenalty.Load()))
	}

	out := make([]Resolver, 0, len(candidates))
	remaining := append([]Resolver(nil), candidates...)
	w := append([]float64(nil), weights...)
	for len(remaining) > 0 {
		total := 0.0
		for _, x := range w {
			total += x
		}
		pick := rand.Float64() * total // #nosec G404 -- weighted upstream selection is not security-sensitive
		idx := 0
		for i, x := range w {
			pick -= x
			if pick <= 0 {
				idx = i
				break
			}
		}
		out = append(out, remaining[idx])
		remaining = append(remaining[:idx], remaining[idx+1:]...)
		w = append(w[:idx], w[idx+1:]...)
	}
	return out
}

// exchange runs one upstream exchange with ECS, stats, and DNS64 handling.
func (p *Pool) exchange(r Resolver, m *dns.Msg) (*dns.Msg, error) {
	ctx, cancel := context.WithTimeout(context.Background(), exchangeTimeout)
	defer cancel()
	return p.exchangeContext(ctx, r, m)
}

func (p *Pool) exchangeContext(ctx context.Context, r Resolver, m *dns.Msg) (*dns.Msg, error) {
	out := p.withECS(m)

	start := time.Now()
	var resp *dns.Msg
	var err error
	if contextual, ok := r.(interface {
		ExchangeContext(context.Context, *dns.Msg) (*dns.Msg, error)
	}); ok {
		resp, err = contextual.ExchangeContext(ctx, out)
	} else {
		resp, err = r.Exchange(out)
	}
	elapsed := float64(time.Since(start).Microseconds()) / 1000.0

	st := p.statFor(r.String())
	if err != nil || resp == nil {
		st.failures.Add(1)
		st.failurePenalty.Add(1)
		return nil, err
	}
	st.successes.Add(1)
	st.failurePenalty.Store(0)
	p.recordLatency(st, elapsed)

	// DNS64: synthesize AAAA from A on empty AAAA answers.
	if p.cfg.DNS64 && len(m.Question) > 0 && m.Question[0].Qtype == dns.TypeAAAA &&
		resp.Rcode == dns.RcodeSuccess && !hasAAAA(resp.Answer) {
		if synthesized := p.synthesizeDNS64(r, m.Question[0].Name); len(synthesized) > 0 {
			resp.Answer = synthesized
		}
	}
	return resp, nil
}

// recordLatency updates the EWMA (alpha = 0.25).
func (p *Pool) recordLatency(st *stat, ms float64) {
	p.statsMu.Lock()
	defer p.statsMu.Unlock()
	if st.ewmaMS == 0 {
		st.ewmaMS = ms
	} else {
		st.ewmaMS = 0.25*ms + 0.75*st.ewmaMS
	}
}

// statFor returns (creating if needed) the stat for a spec.
func (p *Pool) statFor(spec string) *stat {
	p.statsMu.Lock()
	defer p.statsMu.Unlock()
	st, ok := p.stats[spec]
	if !ok {
		st = &stat{}
		p.stats[spec] = st
	}
	return st
}

// StatsSnapshot returns per-upstream stats for metrics endpoints.
func (p *Pool) StatsSnapshot() []StatSnapshot {
	p.mu.RLock()
	resolvers := append([]Resolver(nil), p.primary...)
	resolvers = append(resolvers, p.fallback...)
	p.mu.RUnlock()

	fn, _ := p.healthFn.Load().(func() map[string]float64)
	var health map[string]float64
	if fn != nil {
		health = fn()
	}

	p.statsMu.Lock()
	defer p.statsMu.Unlock()
	out := make([]StatSnapshot, 0, len(resolvers))
	for _, r := range resolvers {
		spec := r.String()
		st := p.stats[spec]
		snap := StatSnapshot{Spec: spec, Healthy: true}
		if st != nil {
			snap.EWMAms = st.ewmaMS
			snap.Failures = st.failures.Load()
			snap.Successes = st.successes.Load()
		}
		if lat, known := health[spec]; known && lat < 0 {
			snap.Healthy = false
		}
		out = append(out, snap)
	}
	return out
}

// withECS attaches the configured EDNS0 client subnet to a copy of the
// query. Without ECS configured the query is forwarded as-is — the client's
// subnet is never passed through (privacy, AdGuard default).
func (p *Pool) withECS(m *dns.Msg) *dns.Msg {
	if p.ecsIP == nil {
		return m
	}
	out := m.Copy()
	// Drop any existing OPT records (preserving the DO bit for DNSSEC
	// passthrough), then attach ours.
	doBit := false
	if opt := m.IsEdns0(); opt != nil {
		doBit = opt.Do()
	}
	extra := out.Extra[:0]
	for _, rr := range out.Extra {
		if rr.Header().Rrtype != dns.TypeOPT {
			extra = append(extra, rr)
		}
	}
	out.Extra = extra

	e := new(dns.EDNS0_SUBNET)
	e.Code = dns.EDNS0SUBNET
	e.Family = p.ecsFamily
	e.SourceNetmask = uint8(p.ecsBits) // #nosec G115 -- ecsBits is bounded to 32/128 at parse time
	e.SourceScope = 0
	e.Address = p.ecsIP

	o := new(dns.OPT)
	o.Hdr.Name = "."
	o.Hdr.Rrtype = dns.TypeOPT
	o.SetUDPSize(1232)
	o.SetDo(doBit)
	o.Option = append(o.Option, e)
	out.Extra = append(out.Extra, o)
	return out
}

// parseECS validates the ECS_CLIENT_SUBNET value (CIDR or plain IP).
func (p *Pool) parseECS(raw string) error {
	raw = strings.TrimSpace(raw)
	if !strings.Contains(raw, "/") {
		if ip := net.ParseIP(raw); ip != nil {
			if ip.To4() != nil {
				raw += "/32"
			} else {
				raw += "/128"
			}
		}
	}
	ip, n, err := net.ParseCIDR(raw)
	if err != nil {
		return err
	}
	p.ecsIP = ip
	bits, _ := n.Mask.Size()
	p.ecsBits = bits
	if ip.To4() != nil {
		p.ecsFamily = 1
	} else {
		p.ecsFamily = 2
	}
	return nil
}

// hasAAAA reports whether the answer contains an AAAA record.
func hasAAAA(answers []dns.RR) bool {
	for _, rr := range answers {
		if _, ok := rr.(*dns.AAAA); ok {
			return true
		}
	}
	return false
}

// synthesizeDNS64 issues an A query for the name and synthesizes AAAA
// records via the configured prefixes.
func (p *Pool) synthesizeDNS64(r Resolver, name string) []dns.RR {
	sub := new(dns.Msg)
	sub.SetQuestion(name, dns.TypeA)
	resp, err := r.Exchange(sub)
	if err != nil || resp == nil {
		return nil
	}
	var out []dns.RR
	for _, rr := range resp.Answer {
		a, ok := rr.(*dns.A)
		if !ok {
			continue
		}
		for _, prefix := range p.dns64Prefixes {
			ones, _ := prefix.Mask.Size()
			if ones != 96 {
				continue
			}
			v6 := make([]byte, 16)
			copy(v6, prefix.IP)
			copy(v6[12:], a.A.To4())
			out = append(out, &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   name,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    a.Hdr.Ttl,
				},
				AAAA: v6,
			})
		}
	}
	return out
}

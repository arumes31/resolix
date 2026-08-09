package upstream

import (
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
	ModeLoadBalance = "load_balance"
	ModeParallel    = "parallel"
	ModeStrict      = "strict"
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
}

// stat tracks per-upstream performance.
type stat struct {
	ewmaMS    float64 // exponentially weighted moving average latency
	failures  atomic.Int64
	successes atomic.Int64
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
	routes   map[string]Resolver // route-spec resolver cache

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
		stats:  make(map[string]*stat),
		boot:   newBootstrapper(cfg.BootstrapServers),
	}
	if cfg.Mode == "" {
		p.cfg.Mode = ModeLoadBalance
	}

	if cfg.ECSClientSubnet != "" {
		if err := p.parseECS(cfg.ECSClientSubnet); err != nil {
			log.Printf("[WARN] Invalid ECS_CLIENT_SUBNET %q: %v (ignoring)", cfg.ECSClientSubnet, err)
		}
	}

	prefixes := cfg.DNS64Prefixes
	if cfg.DNS64 && len(prefixes) == 0 {
		prefixes = []string{"64:ff9b::/96"}
	}
	for _, raw := range prefixes {
		_, n, err := net.ParseCIDR(strings.TrimSpace(raw))
		if err != nil {
			log.Printf("[WARN] Invalid DNS64 prefix %q (ignoring)", raw)
			continue
		}
		p.dns64Prefixes = append(p.dns64Prefixes, n)
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
		// Health probing (internal/health) is UDP-only, so it only covers
		// plain schemeless specs; encrypted upstreams are always considered
		// healthy here.
		lat, known := health[r.String()]
		if known && lat < 0 && !strings.Contains(r.String(), "://") {
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
	primary := p.healthy(p.primary)
	fallback := p.fallback
	p.mu.RUnlock()

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
	}
	results := make(chan result, len(candidates))
	for _, r := range candidates {
		go func(r Resolver) {
			resp, err := p.exchange(r, m.Copy())
			if err == nil && resp != nil {
				results <- result{resp, r.String()}
			}
		}(r)
	}
	timeout := time.After(exchangeTimeout + time.Second)
	for range candidates {
		select {
		case res := <-results:
			return res.resp, res.spec, nil
		case <-timeout:
			return nil, "", fmt.Errorf("parallel exchange: all %d upstreams timed out", len(candidates))
		}
	}
	return nil, "", fmt.Errorf("parallel exchange: all %d upstreams failed", len(candidates))
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
		ewma := st.ewmaMS
		if ewma <= 0 {
			ewma = 1
		}
		weights[i] = 1 / (ewma * float64(1+st.failures.Load()))
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
	out := p.withECS(m)

	start := time.Now()
	resp, err := r.Exchange(out)
	elapsed := float64(time.Since(start).Microseconds()) / 1000.0

	st := p.statFor(r.String())
	if err != nil || resp == nil {
		st.failures.Add(1)
		return nil, err
	}
	st.successes.Add(1)
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
	// Drop any existing OPT records, then attach ours.
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
			if ones > 96 {
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

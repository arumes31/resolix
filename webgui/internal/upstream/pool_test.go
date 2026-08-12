package upstream

import (
	"context"
	"fmt"
	"net"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// ipAnswerHandler answers A queries with the given IP after an optional delay.
func ipAnswerHandler(t *testing.T, ip string, delay time.Duration, hits *atomic.Int32) dns.HandlerFunc {
	t.Helper()
	return func(w dns.ResponseWriter, r *dns.Msg) {
		if hits != nil {
			hits.Add(1)
		}
		if delay > 0 {
			time.Sleep(delay)
		}
		m := new(dns.Msg)
		m.SetReply(r)
		if len(r.Question) > 0 {
			m.Answer = []dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 120},
				A:   net.ParseIP(ip).To4(),
			}}
		}
		_ = w.WriteMsg(m)
	}
}

func answerIP(t *testing.T, resp *dns.Msg) string {
	t.Helper()
	if resp == nil || len(resp.Answer) != 1 {
		t.Fatalf("unexpected answer: %v", resp)
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("not an A record: %v", resp.Answer[0])
	}
	return a.A.String()
}

func TestPoolStrictOrder(t *testing.T) {
	var slowHits, fastHits atomic.Int32
	// Slow (100ms) first, fast second: strict must still use the first.
	slow := startUDPUpstreamHandler(t, ipAnswerHandler(t, "1.1.1.1", 100*time.Millisecond, &slowHits))
	fast := startUDPUpstreamHandler(t, ipAnswerHandler(t, "2.2.2.2", 0, &fastHits))

	pool := NewPool(PoolConfig{Mode: ModeStrict, PrimarySpecs: []string{slow, fast}})
	resp, used, err := pool.Exchange(queryA())
	if err != nil {
		t.Fatal(err)
	}
	if got := answerIP(t, resp); got != "1.1.1.1" {
		t.Errorf("strict answer from %s, want first upstream", got)
	}
	if used != slow {
		t.Errorf("strict used %q, want %q", used, slow)
	}

	// First upstream dead → strict falls to the second.
	pool2 := NewPool(PoolConfig{Mode: ModeStrict, PrimarySpecs: []string{deadAddr(t), fast}})
	resp, used, err = pool2.Exchange(queryA())
	if err != nil {
		t.Fatal(err)
	}
	if got := answerIP(t, resp); got != "2.2.2.2" || used != fast {
		t.Errorf("strict failover: answer=%s used=%q", got, used)
	}
}

func TestPoolChaosFailover(t *testing.T) {
	const timeout = 250 * time.Millisecond
	withTimeout := func(address string) string {
		return "udp://" + address + "?timeout=" + timeout.String()
	}
	assertFailover := func(t *testing.T, primary string, primaryHits *atomic.Int32) {
		t.Helper()
		var fallbackHits atomic.Int32
		fallback := startUDPUpstreamHandler(t, ipAnswerHandler(t, "9.9.9.9", 0, &fallbackHits))
		pool := NewPool(PoolConfig{
			Mode: ModeStrict, PrimarySpecs: []string{withTimeout(primary), fallback},
		})

		started := time.Now()
		response, used, err := pool.Exchange(queryA())
		if err != nil {
			t.Fatalf("failover exchange: %v", err)
		}
		if elapsed := time.Since(started); elapsed > 2*time.Second {
			t.Fatalf("failover exceeded bounded timeout: %s", elapsed)
		}
		if got := answerIP(t, response); got != "9.9.9.9" || used != fallback {
			t.Fatalf("failover answer=%s used=%q, want fallback %q", got, used, fallback)
		}
		if primaryHits.Load() != 1 || fallbackHits.Load() != 1 {
			t.Fatalf("upstream hits primary=%d fallback=%d, want 1/1", primaryHits.Load(), fallbackHits.Load())
		}
	}

	t.Run("packet loss", func(t *testing.T) {
		var hits atomic.Int32
		primary := startUDPUpstreamHandler(t, func(dns.ResponseWriter, *dns.Msg) {
			hits.Add(1) // Deliberately drop the datagram without replying.
		})
		assertFailover(t, primary, &hits)
	})

	t.Run("response delay", func(t *testing.T) {
		var hits atomic.Int32
		primary := startUDPUpstreamHandler(t, ipAnswerHandler(t, "1.1.1.1", 2*timeout, &hits))
		assertFailover(t, primary, &hits)
	})

	t.Run("resolver protocol failure", func(t *testing.T) {
		var hits atomic.Int32
		primary := startUDPUpstreamHandler(t, func(w dns.ResponseWriter, request *dns.Msg) {
			hits.Add(1)
			response := new(dns.Msg)
			response.SetReply(request)
			response.Id++ // A mismatched transaction ID must be rejected.
			_ = w.WriteMsg(response)
		})
		assertFailover(t, primary, &hits)
	})
}

func TestPoolParallelFastestWins(t *testing.T) {
	var slowHits, fastHits atomic.Int32
	slow := startUDPUpstreamHandler(t, ipAnswerHandler(t, "1.1.1.1", 300*time.Millisecond, &slowHits))
	fast := startUDPUpstreamHandler(t, ipAnswerHandler(t, "2.2.2.2", 0, &fastHits))

	pool := NewPool(PoolConfig{Mode: ModeParallel, PrimarySpecs: []string{slow, fast}})
	start := time.Now()
	resp, used, err := pool.Exchange(queryA())
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > 250*time.Millisecond {
		t.Errorf("parallel exchange took %s, want < slow delay", elapsed)
	}
	if got := answerIP(t, resp); got != "2.2.2.2" || used != fast {
		t.Errorf("parallel: answer=%s used=%q, want fastest (2.2.2.2)", got, used)
	}
}

func TestPoolLoadBalanceSpreads(t *testing.T) {
	var hitsA, hitsB atomic.Int32
	a := startUDPUpstreamHandler(t, ipAnswerHandler(t, "1.1.1.1", 0, &hitsA))
	b := startUDPUpstreamHandler(t, ipAnswerHandler(t, "2.2.2.2", 0, &hitsB))

	pool := NewPool(PoolConfig{Mode: ModeLoadBalance, PrimarySpecs: []string{a, b}})
	for i := 0; i < 60; i++ {
		if _, _, err := pool.Exchange(queryA()); err != nil {
			t.Fatal(err)
		}
	}
	if hitsA.Load() == 0 || hitsB.Load() == 0 {
		t.Errorf("load_balance did not spread: A=%d B=%d", hitsA.Load(), hitsB.Load())
	}
}

func TestSelectionWeight(t *testing.T) {
	tests := []struct {
		name           string
		ewmaMS         float64
		failurePenalty int64
		want           float64
	}{
		{name: "unobserved", want: 1},
		{name: "sub-millisecond", ewmaMS: 0.001, want: 1 / 1.001},
		{name: "ten milliseconds", ewmaMS: 9, want: 0.1},
		{name: "one failure", failurePenalty: 1, want: 0.5},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := selectionWeight(test.ewmaMS, test.failurePenalty)
			if diff := got - test.want; diff < -1e-12 || diff > 1e-12 {
				t.Fatalf("selectionWeight(%g, %d) = %g, want %g", test.ewmaMS, test.failurePenalty, got, test.want)
			}
		})
	}
}

func TestPoolSkipsUnhealthy(t *testing.T) {
	var hitsA, hitsB atomic.Int32
	a := startUDPUpstreamHandler(t, ipAnswerHandler(t, "1.1.1.1", 0, &hitsA))
	b := startUDPUpstreamHandler(t, ipAnswerHandler(t, "2.2.2.2", 0, &hitsB))

	pool := NewPool(PoolConfig{Mode: ModeStrict, PrimarySpecs: []string{a, b}})
	pool.SetHealthProvider(func() map[string]float64 {
		return map[string]float64{a: -1, b: 5}
	})
	resp, used, err := pool.Exchange(queryA())
	if err != nil {
		t.Fatal(err)
	}
	if got := answerIP(t, resp); got != "2.2.2.2" || used != b {
		t.Errorf("unhealthy skip: answer=%s used=%q, want second upstream", got, used)
	}
	if hitsA.Load() != 0 {
		t.Errorf("unhealthy upstream was queried %d times", hitsA.Load())
	}
}

func TestPoolFallbackOnlyWhenPrimariesDown(t *testing.T) {
	var primHits, fbHits atomic.Int32
	primary := startUDPUpstreamHandler(t, ipAnswerHandler(t, "1.1.1.1", 0, &primHits))
	fallback := startUDPUpstreamHandler(t, ipAnswerHandler(t, "9.9.9.9", 0, &fbHits))

	// Primary alive → fallback untouched.
	pool := NewPool(PoolConfig{
		Mode:          ModeStrict,
		PrimarySpecs:  []string{primary},
		FallbackSpecs: []string{fallback},
	})
	if _, _, err := pool.Exchange(queryA()); err != nil {
		t.Fatal(err)
	}
	if fbHits.Load() != 0 {
		t.Errorf("fallback used while primary alive (%d hits)", fbHits.Load())
	}

	// Primary dead → fallback answers.
	pool2 := NewPool(PoolConfig{
		Mode:          ModeStrict,
		PrimarySpecs:  []string{deadAddr(t)},
		FallbackSpecs: []string{fallback},
	})
	resp, used, err := pool2.Exchange(queryA())
	if err != nil {
		t.Fatal(err)
	}
	if got := answerIP(t, resp); got != "9.9.9.9" || used != fallback {
		t.Errorf("fallback: answer=%s used=%q", got, used)
	}
}

func TestPoolECSAttached(t *testing.T) {
	var sawECS atomic.Bool
	var sawDO atomic.Bool
	addr := startUDPUpstreamHandler(t, func(w dns.ResponseWriter, r *dns.Msg) {
		if opt := r.IsEdns0(); opt != nil {
			sawDO.Store(opt.Do())
			for _, o := range opt.Option {
				if subnet, ok := o.(*dns.EDNS0_SUBNET); ok {
					if subnet.Address.String() == "192.0.2.0" && subnet.SourceNetmask == 24 {
						sawECS.Store(true)
					}
				}
			}
		}
		m := new(dns.Msg)
		m.SetReply(r)
		_ = w.WriteMsg(m)
	})

	pool := NewPool(PoolConfig{Mode: ModeStrict, PrimarySpecs: []string{addr}, ECSClientSubnet: "192.0.2.0/24"})
	q := queryA()
	q.SetEdns0(1232, true)
	if _, _, err := pool.Exchange(q); err != nil {
		t.Fatal(err)
	}
	if !sawECS.Load() {
		t.Error("upstream query did not carry the ECS option")
	}
	if !sawDO.Load() {
		t.Error("adding ECS cleared the DNSSEC DO bit")
	}

	// Without ECS configured, no EDNS0 subnet is attached (privacy default).
	sawECS.Store(false)
	pool2 := NewPool(PoolConfig{Mode: ModeStrict, PrimarySpecs: []string{addr}})
	if _, _, err := pool2.Exchange(queryA()); err != nil {
		t.Fatal(err)
	}
	if sawECS.Load() {
		t.Error("ECS option attached without configuration")
	}
}

func TestPoolDNS64(t *testing.T) {
	addr := startUDPUpstreamHandler(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if len(r.Question) > 0 && r.Question[0].Qtype == dns.TypeA {
			m.Answer = []dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 120},
				A:   net.ParseIP("93.184.216.34").To4(),
			}}
		}
		// AAAA queries get NOERROR with an empty answer.
		_ = w.WriteMsg(m)
	})

	pool := NewPool(PoolConfig{
		Mode: ModeStrict, PrimarySpecs: []string{addr}, DNS64: true,
		DNS64Prefixes: []string{"64:ff9b::/64", "64:ff9b::/96"},
	})
	q := new(dns.Msg)
	q.SetQuestion("example.org.", dns.TypeAAAA)
	resp, _, err := pool.Exchange(q)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("DNS64 answers = %v, want 1 synthesized AAAA", resp.Answer)
	}
	aaaa, ok := resp.Answer[0].(*dns.AAAA)
	if !ok {
		t.Fatalf("not an AAAA record: %v", resp.Answer[0])
	}
	// 93.184.216.34 → 64:ff9b::5db8:d822
	if want := "64:ff9b::5db8:d822"; aaaa.AAAA.String() != want {
		t.Errorf("synthesized AAAA = %s, want %s", aaaa.AAAA, want)
	}
}

func TestPoolSetPrimarySpecsHotReload(t *testing.T) {
	var hits atomic.Int32
	good := startUDPUpstreamHandler(t, ipAnswerHandler(t, "2.2.2.2", 0, &hits))

	pool := NewPool(PoolConfig{Mode: ModeStrict, PrimarySpecs: []string{deadAddr(t)}})
	if _, _, err := pool.Exchange(queryA()); err == nil {
		t.Fatal("expected failure with dead primary")
	}

	pool.SetPrimarySpecs([]string{good})
	resp, used, err := pool.Exchange(queryA())
	if err != nil {
		t.Fatalf("after reload: %v", err)
	}
	if got := answerIP(t, resp); got != "2.2.2.2" || used != good {
		t.Errorf("after reload: answer=%s used=%q", got, used)
	}
}

func TestBootstrapLookup(t *testing.T) {
	var hits atomic.Int32
	// Fake bootstrap server resolving dns.test → 10.99.0.1 (TTL 300).
	addr := startUDPUpstreamHandler(t, func(w dns.ResponseWriter, r *dns.Msg) {
		hits.Add(1)
		m := new(dns.Msg)
		m.SetReply(r)
		if len(r.Question) > 0 && r.Question[0].Name == "dns.test." && r.Question[0].Qtype == dns.TypeA {
			m.Answer = []dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: "dns.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("10.99.0.1").To4(),
			}}
		}
		_ = w.WriteMsg(m)
	})

	boot := newBootstrapper([]string{addr})
	ips, err := boot.Lookup("dns.test")
	if err != nil {
		t.Fatalf("bootstrap lookup: %v", err)
	}
	if len(ips) != 1 || ips[0] != "10.99.0.1" {
		t.Fatalf("bootstrap ips = %v", ips)
	}

	// Cached: second lookup must not hit the server again.
	if _, err := boot.Lookup("dns.test"); err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 1 {
		t.Errorf("bootstrap server hits = %d, want 1 (cached)", hits.Load())
	}

	// Expire the entry and kill the server: last-known IPs are kept.
	boot.mu.Lock()
	boot.cache["dns.test"].expiresAt = time.Now().Add(-time.Minute)
	boot.servers = []string{deadAddr(t)}
	boot.mu.Unlock()
	ips, err = boot.Lookup("dns.test")
	if err != nil {
		t.Fatalf("expected last-known IPs on failure, got %v", err)
	}
	if len(ips) != 1 || ips[0] != "10.99.0.1" {
		t.Errorf("last-known ips = %v", ips)
	}
}

func TestBootstrapTTLClamp(t *testing.T) {
	boot := newBootstrapper(nil)
	boot.setTTLLimits(60, 600)
	for _, test := range []struct {
		ttl  uint32
		want uint32
	}{{ttl: 0, want: 60}, {ttl: 30, want: 60}, {ttl: 300, want: 300}, {ttl: 3600, want: 600}} {
		if got := boot.clampTTL(test.ttl); got != test.want {
			t.Errorf("clampTTL(%d) = %d, want %d", test.ttl, got, test.want)
		}
	}
}

func TestPoolBoundsResolverGroups(t *testing.T) {
	pool := NewPool(PoolConfig{})
	for i := 0; i <= maxResolverGroups; i++ {
		pool.groupResolvers([]string{fmt.Sprintf("192.0.2.1:%d", 1000+i)})
	}
	pool.mu.RLock()
	count := len(pool.groups)
	pool.mu.RUnlock()
	if count != maxResolverGroups {
		t.Fatalf("resolver groups = %d, want %d", count, maxResolverGroups)
	}
}

func TestPoolIgnoresDNS64PrefixesWhenDisabled(t *testing.T) {
	pool := NewPool(PoolConfig{DNS64Prefixes: []string{"64:ff9b::/96"}})
	if len(pool.dns64Prefixes) != 0 {
		t.Fatalf("DNS64 prefixes loaded while disabled: %v", pool.dns64Prefixes)
	}
}

func TestHostnameUpstreamWithoutBootstrap(t *testing.T) {
	spec, err := Parse("tls://dns.example")
	if err != nil {
		t.Fatal(err)
	}
	r := &dnsResolver{spec: spec, boot: newBootstrapper(nil)}
	if _, err := r.Exchange(queryA()); err == nil {
		t.Error("expected error for hostname upstream without bootstrap")
	}
}

func TestPoolRuntimeSettingsAndCaches(t *testing.T) {
	var bootstrapHits atomic.Int32
	bootstrap := startBootstrapServer(t, "resolver.test", &bootstrapHits)
	primary := startUDPUpstream(t, nil)
	fallback := startUDPUpstreamHandler(t, ipAnswerHandler(t, "9.9.9.9", 0, nil))
	pool := NewPool(PoolConfig{Mode: ModeStrict, PrimarySpecs: []string{primary}})

	if _, err := pool.routeResolver(primary); err != nil {
		t.Fatal(err)
	}
	pool.groupResolvers([]string{primary})
	pool.SetBootstrapServers([]string{bootstrap})
	if !pool.boot.Enabled() || len(pool.routes) != 0 || len(pool.groups) != 0 {
		t.Fatalf("bootstrap reload state: enabled=%v routes=%d groups=%d", pool.boot.Enabled(), len(pool.routes), len(pool.groups))
	}

	pool.SetRuntimeSettings("", []string{fallback}, "2001:db8::1")
	if pool.cfg.Mode != ModeLoadBalance || pool.ecsFamily != 2 || pool.ecsBits != 128 || len(pool.fallback) != 1 {
		t.Fatalf("runtime settings = mode=%q family=%d bits=%d fallback=%d", pool.cfg.Mode, pool.ecsFamily, pool.ecsBits, len(pool.fallback))
	}
	pool.SetRuntimeSettings(ModeParallel, nil, "not-a-subnet")
	if pool.cfg.Mode != ModeParallel || pool.ecsIP != nil {
		t.Fatalf("invalid ECS runtime settings = mode=%q ECS=%v", pool.cfg.Mode, pool.ecsIP)
	}

	if _, err := pool.routeResolver(primary); err != nil {
		t.Fatal(err)
	}
	pool.ClearRouteCache()
	if len(pool.routes) != 0 {
		t.Fatalf("route cache entries = %d, want 0", len(pool.routes))
	}
}

func TestPoolRouteAndSpecExchanges(t *testing.T) {
	address := startUDPUpstream(t, nil)
	pool := NewPool(PoolConfig{Mode: ModeStrict})

	response, used, err := pool.ExchangeRoute(address, queryA())
	if err != nil {
		t.Fatal(err)
	}
	if got := answerIP(t, response); got != testAnswerIP || used != address {
		t.Fatalf("route exchange answer/used = %s/%q", got, used)
	}
	first := pool.routes[address]
	if _, _, err := pool.ExchangeRoute(address, queryA()); err != nil || pool.routes[address] != first {
		t.Fatalf("cached route exchange: err=%v cached=%v", err, pool.routes[address] == first)
	}
	if _, _, err := pool.ExchangeRoute("bad resolver", queryA()); err == nil {
		t.Fatal("invalid route resolver was accepted")
	}

	response, used, err = pool.ExchangeSpecs([]string{address, address}, queryA())
	if err != nil || used != address || answerIP(t, response) != testAnswerIP {
		t.Fatalf("spec exchange answer/used/error = %v/%q/%v", response, used, err)
	}
	if _, _, err := pool.ExchangeSpecs([]string{"bad resolver"}, queryA()); err == nil {
		t.Fatal("empty usable spec set was accepted")
	}
}

func TestPoolStatsSnapshotAndBootstrapStatus(t *testing.T) {
	const timeout = 250 * time.Millisecond
	dead := "udp://" + deadAddr(t) + "?timeout=" + timeout.String() + "&weight=3"
	good := startUDPUpstream(t, nil)
	pool := NewPool(PoolConfig{Mode: ModeStrict, PrimarySpecs: []string{dead, good}})

	for range circuitFailureThreshold {
		if _, _, err := pool.Exchange(queryA()); err != nil {
			t.Fatal(err)
		}
	}
	pool.SetHealthProvider(func() map[string]float64 { return map[string]float64{good: -1} })
	snapshots := pool.StatsSnapshot()
	if len(snapshots) != 2 {
		t.Fatalf("stats snapshots = %d, want 2", len(snapshots))
	}
	if snapshots[0].Failures != circuitFailureThreshold || snapshots[0].Healthy || snapshots[0].Weight != 3 || snapshots[0].CircuitOpenUntil.IsZero() {
		t.Fatalf("failed upstream snapshot = %+v", snapshots[0])
	}
	if snapshots[1].Successes != circuitFailureThreshold || snapshots[1].Healthy || snapshots[1].P50ms < 0 {
		t.Fatalf("successful upstream snapshot = %+v", snapshots[1])
	}

	var hits atomic.Int32
	bootstrap := startBootstrapServer(t, "resolver.test", &hits)
	pool.SetBootstrapServers([]string{bootstrap})
	if _, err := pool.boot.Lookup("resolver.test"); err != nil {
		t.Fatal(err)
	}
	status := pool.BootstrapStatus()
	if len(status) != 1 || status[0].Hostname != "resolver.test" || !slices.Equal(status[0].Addresses, []string{"127.0.0.1"}) || status[0].Stale {
		t.Fatalf("bootstrap status = %+v", status)
	}
	pool.boot.mu.Lock()
	pool.boot.cache["resolver.test"].expiresAt = time.Now().Add(-time.Second)
	pool.boot.mu.Unlock()
	if status = pool.BootstrapStatus(); !status[0].Stale {
		t.Fatalf("expired bootstrap status = %+v", status)
	}
}

func TestPoolProbeAndHelpers(t *testing.T) {
	primary := startUDPUpstream(t, nil)
	fallback := startUDPUpstream(t, nil)
	pool := NewPool(PoolConfig{PrimarySpecs: []string{primary}, FallbackSpecs: []string{fallback}})
	if err := pool.Probe(context.Background(), primary, "health.test"); err != nil {
		t.Fatal(err)
	}
	if err := pool.Probe(context.Background(), fallback, "health.test"); err != nil {
		t.Fatal(err)
	}
	if err := pool.Probe(context.Background(), "not-configured", "health.test"); err == nil {
		t.Fatal("unconfigured probe was accepted")
	}

	if got := latencyPercentile(nil, 0.95); got != 0 {
		t.Fatalf("empty percentile = %v, want 0", got)
	}
	if got := latencyPercentile([]float64{1, 2, 3, 4, 5}, 0.95); got != 5 {
		t.Fatalf("p95 = %v, want 5", got)
	}
	parsed := resolverSpec(stringResolver("tcp://192.0.2.1:5353"))
	if parsed.Scheme != SchemeTCP || parsed.Port != "5353" {
		t.Fatalf("parsed custom resolver spec = %+v", parsed)
	}
	fallbackSpec := resolverSpec(stringResolver("not a resolver"))
	if fallbackSpec.Scheme != SchemeUDP || fallbackSpec.Host != "not a resolver" || fallbackSpec.Port != "53" {
		t.Fatalf("fallback custom resolver spec = %+v", fallbackSpec)
	}
}

type stringResolver string

func (r stringResolver) String() string { return string(r) }

func (stringResolver) Exchange(*dns.Msg) (*dns.Msg, error) {
	return nil, fmt.Errorf("not implemented")
}

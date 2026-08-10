package upstream

import (
	"fmt"
	"net"
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

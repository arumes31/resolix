package dnsserver

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/arumes31/resolix/webgui/internal/dnsroutes"
	"github.com/arumes31/resolix/webgui/internal/models"
	"github.com/arumes31/resolix/webgui/internal/upstream"
)

func TestOptimisticCache(t *testing.T) {
	var hits atomic.Int32
	upstreamAddr := startFakeUpstream(t, &hits) // answers TTL 120

	events := make(chan models.QueryEvent, 10)
	srv := New(Config{
		Addr:            "127.0.0.1",
		Upstreams:       []string{upstreamAddr},
		NodeName:        "test-node",
		CacheMinTTL:     1, // allow the 1s TTL for the test
		CacheMaxTTL:     600,
		CacheOptimistic: true,
	}, func(ev models.QueryEvent, _ bool) { events <- ev })
	serverAddr := startTestServer(t, srv)

	// Shorten the cached TTL by pre-seeding via a 1s-TTL upstream response:
	// clamp with min=1 keeps TTL 1.
	client := &dns.Client{Timeout: 2 * time.Second}
	query := func() (*dns.Msg, error) {
		m := new(dns.Msg)
		m.SetQuestion("example.org.", dns.TypeA)
		resp, _, err := client.Exchange(m, serverAddr)
		if err != nil {
			return nil, err
		}
		return resp, nil
	}
	nextEvent := func() models.QueryEvent {
		t.Helper()
		select {
		case ev := <-events:
			return ev
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for query event")
			return models.QueryEvent{}
		}
	}

	// Prime the cache (upstream TTL 120 → clamped [1,600] stays 120;
	// override by storing a short-lived entry directly).
	resp, err := query()
	if err != nil {
		t.Fatalf("prime query: %v", err)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("prime answer = %v", resp.Answer)
	}
	_ = nextEvent()
	if hits.Load() != 1 {
		t.Fatalf("prime upstream hits = %d", hits.Load())
	}

	// Force the entry to expire quickly for the test.
	key := cacheKey{name: "example.org", qtype: dns.TypeA, qclass: dns.ClassINET}
	srv.cache.mu.Lock()
	el, ok := srv.cache.items[key]
	if !ok {
		srv.cache.mu.Unlock()
		t.Fatalf("cache entry %v is missing", key)
	}
	el.Value = entry{key: key, value: &cacheEntry{
		answers:  el.Value.(entry).value.answers,
		rcode:    dns.RcodeSuccess,
		storedAt: time.Now().Add(-2 * time.Second),
		ttl:      1,
	}}
	srv.cache.mu.Unlock()

	// Stale query: answered from cache (TTL 1) while a background refresh
	// fires. Multiple concurrent stale queries trigger exactly one refresh.
	var wg sync.WaitGroup
	errs := make(chan error, 3)
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := query()
			if err != nil {
				errs <- err
				return
			}
			if len(resp.Answer) != 1 || resp.Answer[0].Header().Ttl != 1 {
				errs <- fmt.Errorf("stale answer = %v, want TTL 1", resp.Answer)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	for i := 0; i < 3; i++ {
		ev := nextEvent()
		if ev.Upstream != "System Cache (stale)" {
			t.Errorf("stale event upstream = %q", ev.Upstream)
		}
	}

	// Wait for the single background refresh.
	deadline := time.Now().Add(2 * time.Second)
	for hits.Load() != 2 {
		if time.Now().After(deadline) {
			t.Fatalf("background refresh did not run once, hits = %d", hits.Load())
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Entry is fresh again.
	resp, err = query()
	if err != nil {
		t.Fatalf("post-refresh query: %v", err)
	}
	if ttl := resp.Answer[0].Header().Ttl; ttl <= 1 {
		t.Errorf("post-refresh TTL = %d, want fresh", ttl)
	}
	_ = nextEvent()
	if hits.Load() != 2 {
		t.Errorf("post-refresh hits = %d, want 2 (cache was fresh)", hits.Load())
	}
}

func TestRoutePrecedenceThroughPool(t *testing.T) {
	var hitsDefault, hitsRoute atomic.Int32
	defaultAddr := startFakeUpstream(t, &hitsDefault)          // 93.184.216.34
	routeAddr := startRouteUpstream(t, &hitsRoute, "10.9.9.9") // route target

	routesFile := filepath.Join(t.TempDir(), "routes.json")
	if err := os.WriteFile(routesFile, []byte(`{"routed.test": "`+routeAddr+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	dr := dnsroutes.New(routesFile)

	pool := upstream.NewPool(upstream.PoolConfig{Mode: upstream.ModeStrict, PrimarySpecs: []string{defaultAddr}})
	events := make(chan models.QueryEvent, 10)
	srv := New(Config{
		Addr:     "127.0.0.1",
		NodeName: "test-node",
		Pool:     pool,
		Routes:   dr,
	}, func(ev models.QueryEvent, _ bool) { events <- ev })
	serverAddr := startTestServer(t, srv)

	client := &dns.Client{Timeout: 2 * time.Second}
	query := func(name string) *dns.Msg {
		t.Helper()
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(name), dns.TypeA)
		resp, _, err := client.Exchange(m, serverAddr)
		if err != nil {
			t.Fatalf("query %s: %v", name, err)
		}
		return resp
	}

	// Routed domain → route upstream.
	resp := query("routed.test")
	if got := resp.Answer[0].(*dns.A).A.String(); got != "10.9.9.9" {
		t.Errorf("routed answer = %s, want 10.9.9.9", got)
	}
	ev := <-events
	if ev.Upstream != routeAddr {
		t.Errorf("routed event upstream = %q, want %q", ev.Upstream, routeAddr)
	}

	// Unrouted domain → default pool upstream.
	resp = query("other.org")
	if got := resp.Answer[0].(*dns.A).A.String(); got != "93.184.216.34" {
		t.Errorf("unrouted answer = %s, want 93.184.216.34", got)
	}
	ev = <-events
	if ev.Upstream != defaultAddr {
		t.Errorf("unrouted event upstream = %q, want %q", ev.Upstream, defaultAddr)
	}

	if hitsRoute.Load() != 1 || hitsDefault.Load() != 1 {
		t.Errorf("hits route=%d default=%d, want 1/1", hitsRoute.Load(), hitsDefault.Load())
	}
}

// startRouteUpstream starts a fake upstream answering with the given IP.
func startRouteUpstream(t *testing.T, hits *atomic.Int32, ip string) string {
	t.Helper()
	pc := mustListenPacket(t)
	fake := &dns.Server{
		PacketConn: pc,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			hits.Add(1)
			m := new(dns.Msg)
			m.SetReply(r)
			if len(r.Question) > 0 {
				m.Answer = []dns.RR{aRecord(r.Question[0].Name, ip, 120)}
			}
			_ = w.WriteMsg(m)
		}),
	}
	go func() { _ = fake.ActivateAndServe() }()
	t.Cleanup(func() { _ = fake.Shutdown() })
	return pc.LocalAddr().String()
}

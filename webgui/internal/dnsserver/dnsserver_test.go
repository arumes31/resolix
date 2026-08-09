package dnsserver

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"tailscale-dnsrewrite/webgui/internal/models"
)

// freePort reserves and releases an ephemeral UDP port on 127.0.0.1 for the
// server under test. The tiny race after Close is acceptable for local tests.
func freePort(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve free port: %v", err)
	}
	defer func() { _ = pc.Close() }()
	return pc.LocalAddr().(*net.UDPAddr).Port
}

// startFakeUpstream starts a UDP DNS server on an ephemeral loopback port
// that answers A queries for example.org with 93.184.216.34 (TTL 120).
func startFakeUpstream(t *testing.T, hits *atomic.Int32) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("fake upstream listen: %v", err)
	}
	fake := &dns.Server{
		PacketConn: pc,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			hits.Add(1)
			m := new(dns.Msg)
			m.SetReply(r)
			if len(r.Question) > 0 {
				m.Answer = []dns.RR{aRecord(r.Question[0].Name, "93.184.216.34", 120)}
			}
			_ = w.WriteMsg(m)
		}),
	}
	go func() { _ = fake.ActivateAndServe() }()
	t.Cleanup(func() { _ = fake.Shutdown() })
	return pc.LocalAddr().String()
}

func TestEndToEndPipeline(t *testing.T) {
	var upstreamHits atomic.Int32
	upstreamAddr := startFakeUpstream(t, &upstreamHits)

	port := freePort(t)
	events := make(chan models.QueryEvent, 10)
	srv := New(Config{
		Addr:        "127.0.0.1",
		Port:        port,
		Upstreams:   []string{upstreamAddr},
		StaticHosts: ParseStaticHosts("static.test:100.64.0.1"),
		NodeName:    "test-node",
	}, func(ev models.QueryEvent) { events <- ev })

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = srv.Start(ctx) }()

	serverAddr := fmt.Sprintf("127.0.0.1:%d", port)
	client := &dns.Client{Timeout: 500 * time.Millisecond}
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

	// Wait for the listener to come up (static domain so no upstream hit).
	deadline := time.Now().Add(2 * time.Second)
	for {
		m := new(dns.Msg)
		m.SetQuestion("warmup.static.test.", dns.TypeA)
		if _, _, err := client.Exchange(m, serverAddr); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("server under test did not start listening")
		}
		time.Sleep(20 * time.Millisecond)
	}
	<-events // discard warmup event

	assertStaticRewritePhase(t, query, nextEvent, &upstreamHits)
	assertForwardedPhase(t, query, nextEvent, upstreamAddr, &upstreamHits)
	assertCacheHitPhase(t, query, nextEvent, &upstreamHits)
}

// assertStaticRewritePhase verifies that a subdomain of a static host is
// answered locally without touching the upstream.
func assertStaticRewritePhase(t *testing.T, query func(string) *dns.Msg, nextEvent func() models.QueryEvent, upstreamHits *atomic.Int32) {
	t.Helper()
	resp := query("www.static.test")
	if len(resp.Answer) != 1 {
		t.Fatalf("static query: got %d answers, want 1", len(resp.Answer))
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok || a.A.String() != "100.64.0.1" {
		t.Fatalf("static query answer = %v, want A 100.64.0.1", resp.Answer[0])
	}
	if a.Hdr.Ttl != staticTTL {
		t.Errorf("static answer TTL = %d, want %d", a.Hdr.Ttl, staticTTL)
	}
	ev := nextEvent()
	if ev.Upstream != "Local Override" || ev.Domain != "www.static.test" || ev.Type != "A" {
		t.Errorf("static event = %+v", ev)
	}
	if ev.ResponseCode != "NOERROR" || ev.Blocked {
		t.Errorf("unexpected event flags: %+v", ev)
	}
	if upstreamHits.Load() != 0 {
		t.Errorf("static query hit the upstream %d times", upstreamHits.Load())
	}
}

// assertForwardedPhase verifies that an unknown domain is forwarded to the
// upstream and the emitted event carries upstream and latency data.
func assertForwardedPhase(t *testing.T, query func(string) *dns.Msg, nextEvent func() models.QueryEvent, upstreamAddr string, upstreamHits *atomic.Int32) {
	t.Helper()
	resp := query("example.org")
	if len(resp.Answer) != 1 || resp.Answer[0].(*dns.A).A.String() != "93.184.216.34" {
		t.Fatalf("forwarded answer = %v, want A 93.184.216.34", resp.Answer)
	}
	if resp.Answer[0].Header().Ttl != 120 {
		t.Errorf("first answer TTL = %d, want 120", resp.Answer[0].Header().Ttl)
	}
	if upstreamHits.Load() != 1 {
		t.Fatalf("upstream hit count = %d, want 1", upstreamHits.Load())
	}
	ev := nextEvent()
	if ev.Upstream != upstreamAddr {
		t.Errorf("forwarded event upstream = %q, want %q", ev.Upstream, upstreamAddr)
	}
	if !ev.Latency.Valid || ev.Latency.Float64 < 0 {
		t.Errorf("forwarded event latency = %+v, want valid >= 0", ev.Latency)
	}
	if ev.Node != "test-node" || ev.ClientIP != "127.0.0.1" {
		t.Errorf("unexpected event identity fields: %+v", ev)
	}
}

// assertCacheHitPhase verifies that a repeated identical query is served
// from the cache: no new upstream hit, decremented TTL, ~0 latency.
func assertCacheHitPhase(t *testing.T, query func(string) *dns.Msg, nextEvent func() models.QueryEvent, upstreamHits *atomic.Int32) {
	t.Helper()
	time.Sleep(1100 * time.Millisecond) // make TTL decrement observable
	resp := query("example.org")
	if len(resp.Answer) != 1 || resp.Answer[0].(*dns.A).A.String() != "93.184.216.34" {
		t.Fatalf("cached answer = %v, want A 93.184.216.34", resp.Answer)
	}
	if ttl := resp.Answer[0].Header().Ttl; ttl == 0 || ttl >= 120 {
		t.Errorf("cached answer TTL = %d, want decremented (<120)", ttl)
	}
	if upstreamHits.Load() != 1 {
		t.Errorf("cache miss: upstream hit count = %d, want still 1", upstreamHits.Load())
	}
	ev := nextEvent()
	if ev.Upstream != "System Cache" {
		t.Errorf("cached event upstream = %q, want %q", ev.Upstream, "System Cache")
	}
	if !ev.Latency.Valid || ev.Latency.Float64 != 0 {
		t.Errorf("cached event latency = %+v, want valid 0", ev.Latency)
	}
}

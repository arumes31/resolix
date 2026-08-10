package dnsserver

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/arumes31/resolix/webgui/internal/models"
)

type scriptedResetConn struct {
	net.PacketConn
	resets int
	calls  int
}

func (c *scriptedResetConn) ReadFrom(p []byte) (int, net.Addr, error) {
	c.calls++
	if c.resets < 0 || c.calls <= c.resets {
		return 0, nil, fmt.Errorf("wrapped reset: %w", syscall.ECONNRESET)
	}
	n := copy(p, "ok")
	return n, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53}, nil
}

func TestResetTolerantConnRetriesWrappedResetsWithLimit(t *testing.T) {
	succeeds := &scriptedResetConn{resets: 2}
	buffer := make([]byte, 8)
	n, _, err := (resetTolerantConn{succeeds}).ReadFrom(buffer)
	if err != nil || string(buffer[:n]) != "ok" || succeeds.calls != 3 {
		t.Fatalf("retry result: n=%d err=%v calls=%d", n, err, succeeds.calls)
	}

	alwaysReset := &scriptedResetConn{resets: -1}
	if _, _, err := (resetTolerantConn{alwaysReset}).ReadFrom(buffer); err == nil {
		t.Fatal("permanently resetting connection did not return an error")
	}
}

// startTestServer runs srv on pre-bound :0 loopback sockets and returns the
// UDP address clients should query. Binding happens before serving starts,
// so there is no port-reservation race between tests.
func startTestServer(t *testing.T, srv *Server) string {
	t.Helper()
	udpConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("test UDP socket: %v", err)
	}
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = udpConn.Close()
		t.Fatalf("test TCP socket: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.StartOn(ctx, udpConn, tcpLn) }()
	t.Cleanup(func() {
		cancel()
		<-done // wait for listeners to fully release the sockets
	})
	return udpConn.LocalAddr().String()
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

	events := make(chan models.QueryEvent, 10)
	srv := New(Config{
		Addr:        "127.0.0.1",
		Upstreams:   []string{upstreamAddr},
		StaticHosts: ParseStaticHosts("static.test:100.64.0.1"),
		NodeName:    "test-node",
	}, func(ev models.QueryEvent, _ bool) { events <- ev })

	serverAddr := startTestServer(t, srv)
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
	for {
		select {
		case event := <-events:
			if event.Domain != "warmup.static.test" {
				t.Fatalf("unexpected event during warmup: %+v", event)
			}
		default:
			goto warmupDrained
		}
	}
warmupDrained:

	assertStaticRewritePhase(t, query, nextEvent, &upstreamHits)
	assertForwardedPhase(t, query, nextEvent, upstreamAddr, &upstreamHits)
	assertCacheHitPhase(t, query, nextEvent, &upstreamHits)
}

func TestUpstreamOPTIsRebuiltPerClientAcrossCache(t *testing.T) {
	var hits atomic.Int32
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fake := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		hits.Add(1)
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = []dns.RR{aRecord(r.Question[0].Name, "93.184.216.34", 120)}
		m.Extra = []dns.RR{
			&dns.TXT{Hdr: dns.RR_Header{Name: "meta.example.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 120}, Txt: []string{"kept"}},
			&dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT, Class: 4096}},
		}
		_ = w.WriteMsg(m)
	})}
	go func() { _ = fake.ActivateAndServe() }()
	t.Cleanup(func() { _ = fake.Shutdown() })

	srv := New(Config{Upstreams: []string{pc.LocalAddr().String()}}, func(models.QueryEvent, bool) {})
	query := func(size uint16, do bool) *dns.Msg {
		m := new(dns.Msg)
		m.SetQuestion("opt.example.", dns.TypeA)
		m.SetEdns0(size, do)
		resp, drop := srv.Resolve(m, "192.0.2.1")
		if drop || resp == nil {
			t.Fatal("query was unexpectedly dropped")
		}
		return resp
	}
	assertOPT := func(resp *dns.Msg, size uint16, do bool) {
		t.Helper()
		count := 0
		for _, rr := range resp.Extra {
			if opt, ok := rr.(*dns.OPT); ok {
				count++
				if opt.UDPSize() != size || opt.Do() != do {
					t.Errorf("OPT = size %d DO %v, want %d/%v", opt.UDPSize(), opt.Do(), size, do)
				}
			}
		}
		if count != 1 {
			t.Errorf("OPT count = %d, want 1", count)
		}
	}

	first := query(1232, true)
	assertOPT(first, 1232, true)
	if len(first.Extra) != 2 {
		t.Fatalf("uncached extras = %v, want TXT plus client OPT", first.Extra)
	}
	second := query(512, false)
	assertOPT(second, 512, false)
	if hits.Load() != 1 {
		t.Fatalf("upstream hits = %d, want cache hit on second query", hits.Load())
	}
}

func TestStaticHostAndUpstreamNormalization(t *testing.T) {
	hosts := ParseStaticHosts(" Example.COM.:192.0.2.10 ")
	if got := hosts["example.com"]; got == nil || got.String() != "192.0.2.10" {
		t.Fatalf("trailing-dot static host = %v", got)
	}

	if got, ok := normalizeUpstream("2001:db8::1#5353"); !ok || got != "[2001:db8::1]:5353" {
		t.Fatalf("IPv6 #port normalization = %q/%v", got, ok)
	}
	for _, input := range []string{"127.0.0.1#", "127.0.0.1#0", "127.0.0.1#65536", "127.0.0.1#nope"} {
		if got, ok := normalizeUpstream(input); ok {
			t.Errorf("normalizeUpstream(%q) = %q, want invalid", input, got)
		}
	}
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

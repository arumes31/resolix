package dnsserver

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"tailscale-dnsrewrite/webgui/internal/models"
	"tailscale-dnsrewrite/webgui/internal/policy"
	"tailscale-dnsrewrite/webgui/internal/rewrites"
)

// policyHarness runs a server under test with a rewrites store and policy.
type policyHarness struct {
	srv      *Server
	query    func(name string, qtype uint16) *dns.Msg
	events   chan models.QueryEvent
	upstream *atomic.Int32
}

func startPolicyServer(t *testing.T, store *rewrites.Store, pol *policy.Policy, upstreamAddr string, hits *atomic.Int32) *policyHarness {
	t.Helper()
	events := make(chan models.QueryEvent, 20)
	srv := New(Config{
		Addr:      "127.0.0.1",
		Upstreams: []string{upstreamAddr},
		NodeName:  "test-node",
		Rewrites:  store,
		Policy:    pol,
		Filter:    nil,
	}, func(ev models.QueryEvent, _ bool) { events <- ev })

	serverAddr := startTestServer(t, srv)
	client := &dns.Client{Timeout: 2 * time.Second}
	h := &policyHarness{srv: srv, events: events, upstream: hits}
	h.query = func(name string, qtype uint16) *dns.Msg {
		t.Helper()
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(name), qtype)
		resp, _, err := client.Exchange(m, serverAddr)
		if err != nil {
			t.Fatalf("query %s: %v", name, err)
		}
		return resp
	}
	return h
}

func (h *policyHarness) nextEvent(t *testing.T) models.QueryEvent {
	t.Helper()
	select {
	case ev := <-h.events:
		return ev
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for query event")
		return models.QueryEvent{}
	}
}

func TestRewritesWire(t *testing.T) {
	var hits atomic.Int32
	upstreamAddr := startFakeUpstream(t, &hits)

	store, err := rewrites.Load("", "rewrite.test:192.0.2.9")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Add("rewrite.test", "TXT", "hello"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Add("gone.test", "NXDOMAIN", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Add("alias.test", "CNAME", "example.org"); err != nil {
		t.Fatal(err)
	}

	h := startPolicyServer(t, store, nil, upstreamAddr, &hits)

	// A rewrite (apex + subdomain).
	resp := h.query("www.rewrite.test", dns.TypeA)
	if len(resp.Answer) != 1 || resp.Answer[0].(*dns.A).A.String() != "192.0.2.9" {
		t.Fatalf("A rewrite answer = %v", resp.Answer)
	}
	ev := h.nextEvent(t)
	if ev.Upstream != "Rewrite" || ev.MatchedRule == "" || ev.BlockReason != "Rewrite" {
		t.Errorf("rewrite event = %+v", ev)
	}

	// TXT rewrite on the same domain.
	resp = h.query("rewrite.test", dns.TypeTXT)
	if len(resp.Answer) != 1 || resp.Answer[0].(*dns.TXT).Txt[0] != "hello" {
		t.Fatalf("TXT rewrite answer = %v", resp.Answer)
	}
	_ = h.nextEvent(t)

	// RCODE rewrite.
	resp = h.query("gone.test", dns.TypeA)
	if resp.Rcode != dns.RcodeNameError {
		t.Errorf("RCODE rewrite rcode = %s, want NXDOMAIN", dns.RcodeToString[resp.Rcode])
	}
	_ = h.nextEvent(t)

	// CNAME chase: CNAME record + upstream answer for the target.
	resp = h.query("alias.test", dns.TypeA)
	if len(resp.Answer) != 2 {
		t.Fatalf("CNAME chase answers = %v, want CNAME + A", resp.Answer)
	}
	cn, ok := resp.Answer[0].(*dns.CNAME)
	if !ok || cn.Target != "example.org." {
		t.Fatalf("first record = %v, want CNAME example.org.", resp.Answer[0])
	}
	if a, ok := resp.Answer[1].(*dns.A); !ok || a.A.String() != "93.184.216.34" {
		t.Fatalf("second record = %v, want A 93.184.216.34", resp.Answer[1])
	}
	if hits.Load() != 1 {
		t.Errorf("chase upstream hits = %d, want 1", hits.Load())
	}
	ev = h.nextEvent(t)
	if ev.Upstream != "Rewrite" {
		t.Errorf("chase event upstream = %q", ev.Upstream)
	}
}

func TestRewriteLiveUpdate(t *testing.T) {
	var hits atomic.Int32
	upstreamAddr := startFakeUpstream(t, &hits)

	store, err := rewrites.Load("", "")
	if err != nil {
		t.Fatal(err)
	}
	h := startPolicyServer(t, store, nil, upstreamAddr, &hits)

	// Before: forwarded to upstream. After Add: answered by the store with
	// no restart — the pipeline consults the store live.
	if _, err := store.Add("live.test", "A", "192.0.2.77"); err != nil {
		t.Fatal(err)
	}
	resp := h.query("live.test", dns.TypeA)
	if len(resp.Answer) != 1 || resp.Answer[0].(*dns.A).A.String() != "192.0.2.77" {
		t.Fatalf("live rewrite answer = %v", resp.Answer)
	}
	if hits.Load() != 0 {
		t.Errorf("rewrite query hit upstream %d times", hits.Load())
	}
	_ = h.nextEvent(t)
}

func TestCNAMEChainLoopCap(t *testing.T) {
	var hits atomic.Int32
	upstreamAddr := startFakeUpstream(t, &hits)

	store, err := rewrites.Load("", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Add("loop-a.test", "CNAME", "loop-b.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Add("loop-b.test", "CNAME", "loop-a.test"); err != nil {
		t.Fatal(err)
	}
	h := startPolicyServer(t, store, nil, upstreamAddr, &hits)

	resp := h.query("loop-a.test", dns.TypeA)
	if resp.Rcode != dns.RcodeServerFailure {
		t.Errorf("loop rcode = %s, want SERVFAIL", dns.RcodeToString[resp.Rcode])
	}
	ev := h.nextEvent(t)
	if ev.ResponseCode != "SERVFAIL" {
		t.Errorf("loop event = %+v", ev)
	}
}

func TestSafeSearchE2E(t *testing.T) {
	var hits atomic.Int32
	upstreamAddr := startFakeUpstream(t, &hits)

	pol := policy.New(policy.Config{SafeSearch: []string{"google"}})
	h := startPolicyServer(t, nil, pol, upstreamAddr, &hits)

	resp := h.query("www.google.com", dns.TypeA)
	if len(resp.Answer) != 2 {
		t.Fatalf("safe-search answers = %v, want CNAME + A", resp.Answer)
	}
	cn, ok := resp.Answer[0].(*dns.CNAME)
	if !ok || cn.Target != "forcesafesearch.google.com." {
		t.Fatalf("safe-search CNAME = %v", resp.Answer[0])
	}
	if a, ok := resp.Answer[1].(*dns.A); !ok || a.A.String() != "93.184.216.34" {
		t.Fatalf("safe-search target answer = %v", resp.Answer[1])
	}
	ev := h.nextEvent(t)
	if ev.Upstream != "SafeSearch" || ev.MatchedRule != "SafeSearch" || ev.BlockReason != "SafeSearch" {
		t.Errorf("safe-search event = %+v", ev)
	}
	if ev.Blocked {
		t.Errorf("safe-search event must not be blocked: %+v", ev)
	}
}

// startMixedUpstream answers A queries with one bogus and one real IP.
func startMixedUpstream(t *testing.T, hits *atomic.Int32) string {
	t.Helper()
	pc := mustListenPacket(t)
	fake := &dns.Server{
		PacketConn: pc,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			hits.Add(1)
			m := new(dns.Msg)
			m.SetReply(r)
			if len(r.Question) > 0 {
				m.Answer = []dns.RR{
					aRecord(r.Question[0].Name, "10.66.66.66", 120),
					aRecord(r.Question[0].Name, "93.184.216.34", 120),
				}
			}
			_ = w.WriteMsg(m)
		}),
	}
	go func() { _ = fake.ActivateAndServe() }()
	t.Cleanup(func() { _ = fake.Shutdown() })
	return pc.LocalAddr().String()
}

func mustListenPacket(t *testing.T) net.PacketConn {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	return pc
}

func TestBogusNXDOMAINConversion(t *testing.T) {
	t.Run("all in range", func(t *testing.T) {
		var hits atomic.Int32
		upstreamAddr := startFakeUpstream(t, &hits) // answers 93.184.216.34
		pol := policy.New(policy.Config{BogusNets: []string{"93.184.216.34"}})
		h := startPolicyServer(t, nil, pol, upstreamAddr, &hits)

		resp := h.query("example.org", dns.TypeA)
		if resp.Rcode != dns.RcodeNameError {
			t.Errorf("rcode = %s, want NXDOMAIN", dns.RcodeToString[resp.Rcode])
		}
		if len(resp.Answer) != 0 {
			t.Errorf("bogus conversion must strip answers: %v", resp.Answer)
		}
		ev := h.nextEvent(t)
		if ev.BlockReason != "BogusNXDOMAIN" || ev.Upstream != upstreamAddr {
			t.Errorf("bogus event = %+v", ev)
		}
		// Converted answers must not poison the cache.
		if got := h.srv.cache.len(); got != 0 {
			t.Errorf("bogus answer cached (len = %d)", got)
		}
	})

	t.Run("mixed passes through", func(t *testing.T) {
		var hits atomic.Int32
		upstreamAddr := startMixedUpstream(t, &hits)
		pol := policy.New(policy.Config{BogusNets: []string{"10.0.0.0/8"}})
		h := startPolicyServer(t, nil, pol, upstreamAddr, &hits)

		resp := h.query("example.org", dns.TypeA)
		if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 2 {
			t.Errorf("mixed response = %v, want passthrough", resp)
		}
	})
}

func TestAAAADisableAndRefuseANY(t *testing.T) {
	var hits atomic.Int32
	upstreamAddr := startFakeUpstream(t, &hits)
	pol := policy.New(policy.Config{AAAADisabled: true, RefuseANY: true})
	h := startPolicyServer(t, nil, pol, upstreamAddr, &hits)

	// AAAA → NOERROR empty (NODATA), upstream untouched.
	resp := h.query("example.org", dns.TypeAAAA)
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 0 {
		t.Errorf("AAAA response = %v, want NOERROR empty", resp)
	}
	ev := h.nextEvent(t)
	if ev.Upstream != "Policy" || ev.BlockReason != "AAAADisabled" {
		t.Errorf("AAAA event = %+v", ev)
	}

	// ANY → REFUSED.
	resp = h.query("example.org", dns.TypeANY)
	if resp.Rcode != dns.RcodeRefused {
		t.Errorf("ANY rcode = %s, want REFUSED", dns.RcodeToString[resp.Rcode])
	}
	ev = h.nextEvent(t)
	if ev.Upstream != "Policy" || ev.BlockReason != "RefusedANY" {
		t.Errorf("ANY event = %+v", ev)
	}

	// A queries still forward normally.
	resp = h.query("example.org", dns.TypeA)
	if len(resp.Answer) != 1 {
		t.Errorf("A response = %v, want forwarded answer", resp)
	}
	_ = h.nextEvent(t)

	if hits.Load() != 1 {
		t.Errorf("upstream hits = %d, want 1 (only the A query)", hits.Load())
	}
}

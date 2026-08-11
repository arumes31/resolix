package dnsserver

import (
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/arumes31/resolix/webgui/internal/clients"
	"github.com/arumes31/resolix/webgui/internal/filter"
	"github.com/arumes31/resolix/webgui/internal/models"
	"github.com/arumes31/resolix/webgui/internal/policy"
	"github.com/arumes31/resolix/webgui/internal/upstream"
)

// writeFilterList writes a filter list to a temp file and returns its path.
func writeFilterList(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "list.txt")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// fakeResponseWriter lets tests invoke ServeDNS directly with an arbitrary
// client address.
type fakeResponseWriter struct {
	remote net.Addr
	last   *dns.Msg
}

func (f *fakeResponseWriter) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53}
}
func (f *fakeResponseWriter) RemoteAddr() net.Addr        { return f.remote }
func (f *fakeResponseWriter) WriteMsg(m *dns.Msg) error   { f.last = m; return nil }
func (f *fakeResponseWriter) Write(b []byte) (int, error) { return len(b), nil }
func (f *fakeResponseWriter) Close() error                { return nil }
func (f *fakeResponseWriter) TsigStatus() error           { return nil }
func (f *fakeResponseWriter) TsigTimersOnly(bool)         {}
func (f *fakeResponseWriter) Hijack()                     {}

// emittedEvent captures the event plus the stats-exclusion flag.
type emittedEvent struct {
	ev  models.QueryEvent
	exc bool
}

// clientHarness invokes ServeDNS directly (no sockets) with a pool and
// optional registry/policy/filter.
type clientHarness struct {
	srv    *Server
	events chan emittedEvent
}

func startClientHarness(t *testing.T, cfg Config) *clientHarness {
	t.Helper()
	cfg.Addr = "127.0.0.1"
	cfg.NodeName = "test-node"
	events := make(chan emittedEvent, 20)
	srv := New(cfg, func(ev models.QueryEvent, exc bool) { events <- emittedEvent{ev, exc} })
	h := &clientHarness{srv: srv, events: events}
	return h
}

func (h *clientHarness) queryFrom(t *testing.T, clientIP, name string) *dns.Msg {
	t.Helper()
	w := &fakeResponseWriter{remote: &net.UDPAddr{IP: net.ParseIP(clientIP), Port: 53000}}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	h.srv.ServeDNS(w, m)
	if w.last == nil {
		t.Fatalf("no response for %s from %s", name, clientIP)
	}
	return w.last
}

func (h *clientHarness) nextEvent(t *testing.T) emittedEvent {
	t.Helper()
	select {
	case e := <-h.events:
		return e
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for query event")
		return emittedEvent{}
	}
}

func (h *clientHarness) expectNoEvent(t *testing.T) {
	t.Helper()
	select {
	case e := <-h.events:
		t.Fatalf("unexpected event emitted: %+v", e.ev)
	case <-time.After(300 * time.Millisecond):
	}
}

// newTestRegistry builds an in-memory registry with the given clients.
func newTestRegistry(t *testing.T, cls ...clients.Client) *clients.Registry {
	t.Helper()
	reg, err := clients.Load("")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cls {
		if err := reg.Add(c); err != nil {
			t.Fatalf("Add %s: %v", c.Name, err)
		}
	}
	return reg
}

func TestPerClientFilteringDisabled(t *testing.T) {
	var hits atomic.Int32
	upstreamAddr := startFakeUpstream(t, &hits)

	eng := filter.New()
	listPath := writeFilterList(t, "||blocked.test^\n")
	eng.AddFileSource(listPath, false)

	reg := newTestRegistry(t, clients.Client{
		Name: "unfiltered", IDs: []string{"100.64.0.20"},
		UseGlobalSettings: false, FilteringEnabled: false,
	})
	pool := upstream.NewPool(upstream.PoolConfig{Mode: upstream.ModeStrict, PrimarySpecs: []string{upstreamAddr}})
	h := startClientHarness(t, Config{
		Pool: pool, Filter: eng, Clients: reg, BlockingMode: "nxdomain",
	})

	// Global client: blocked.
	resp := h.queryFrom(t, "100.64.0.10", "blocked.test")
	if resp.Rcode != dns.RcodeNameError {
		t.Errorf("global client rcode = %s, want NXDOMAIN", dns.RcodeToString[resp.Rcode])
	}
	ev := h.nextEvent(t)
	if !ev.ev.Blocked {
		t.Errorf("global event should be blocked: %+v", ev.ev)
	}

	// Unfiltered client: passthrough to the upstream.
	resp = h.queryFrom(t, "100.64.0.20", "blocked.test")
	if len(resp.Answer) != 1 || resp.Answer[0].(*dns.A).A.String() != "93.184.216.34" {
		t.Errorf("unfiltered client answer = %v, want forwarded", resp.Answer)
	}
	ev = h.nextEvent(t)
	if ev.ev.Blocked {
		t.Errorf("unfiltered client event must not be blocked: %+v", ev.ev)
	}
}

func TestPerClientSafeSearchOverride(t *testing.T) {
	var hits atomic.Int32
	upstreamAddr := startFakeUpstream(t, &hits)

	pol := policy.New(policy.Config{SafeSearch: []string{"google"}})
	reg := newTestRegistry(t, clients.Client{
		Name: "yt-only", IDs: []string{"100.64.0.21"},
		UseGlobalSettings: false, SafeSearchEnabled: true, SafeSearchEngines: []string{"youtube"},
	})
	pool := upstream.NewPool(upstream.PoolConfig{Mode: upstream.ModeStrict, PrimarySpecs: []string{upstreamAddr}})
	h := startClientHarness(t, Config{Pool: pool, Policy: pol, Clients: reg})

	// Global client: google rewritten.
	resp := h.queryFrom(t, "100.64.0.10", "www.google.com")
	if cn, ok := firstAnswer(t, resp).(*dns.CNAME); !ok || cn.Target != "forcesafesearch.google.com." {
		t.Errorf("global safe-search answer = %v", resp.Answer)
	}
	_ = h.nextEvent(t)

	// Override client: google NOT rewritten, youtube rewritten.
	resp = h.queryFrom(t, "100.64.0.21", "www.google.com")
	if a, ok := firstAnswer(t, resp).(*dns.A); !ok || a.A.String() != "93.184.216.34" {
		t.Errorf("override client google answer = %v, want forwarded", resp.Answer)
	}
	_ = h.nextEvent(t)

	resp = h.queryFrom(t, "100.64.0.21", "www.youtube.com")
	if cn, ok := firstAnswer(t, resp).(*dns.CNAME); !ok || cn.Target != "restrict.youtube.com." {
		t.Errorf("override client youtube answer = %v", resp.Answer)
	}
	_ = h.nextEvent(t)
}

func TestCustomUpstreamAndCacheIsolation(t *testing.T) {
	var hitsA, hitsB atomic.Int32
	upstreamA := startFakeUpstream(t, &hitsA)              // 93.184.216.34
	upstreamB := startRouteUpstream(t, &hitsB, "10.9.9.9") // custom client upstream

	reg := newTestRegistry(t, clients.Client{
		Name: "custom", IDs: []string{"100.64.0.30"},
		UseGlobalSettings: false, Upstreams: []string{upstreamB},
	})
	pool := upstream.NewPool(upstream.PoolConfig{Mode: upstream.ModeStrict, PrimarySpecs: []string{upstreamA}})
	h := startClientHarness(t, Config{Pool: pool, Clients: reg})

	// Client with custom upstreams gets B's answer.
	resp := h.queryFrom(t, "100.64.0.30", "cacheme.test")
	if got := firstAnswer(t, resp).(*dns.A).A.String(); got != "10.9.9.9" {
		t.Fatalf("custom client answer = %s, want 10.9.9.9", got)
	}
	if ev := h.nextEvent(t); ev.ev.Upstream != upstreamB {
		t.Errorf("custom event upstream = %q, want %q", ev.ev.Upstream, upstreamB)
	}

	// Global client gets A's answer; the client's answer must not pollute
	// the shared cache (group discriminator).
	resp = h.queryFrom(t, "100.64.0.10", "cacheme.test")
	if got := firstAnswer(t, resp).(*dns.A).A.String(); got != "93.184.216.34" {
		t.Fatalf("global client answer = %s, want 93.184.216.34", got)
	}
	_ = h.nextEvent(t)

	// Second global query: cache hit with the global answer.
	resp = h.queryFrom(t, "100.64.0.10", "cacheme.test")
	if got := firstAnswer(t, resp).(*dns.A).A.String(); got != "93.184.216.34" {
		t.Errorf("global cache answer = %s, want 93.184.216.34", got)
	}
	if ev := h.nextEvent(t); ev.ev.Upstream != "System Cache" {
		t.Errorf("global second query upstream = %q, want System Cache", ev.ev.Upstream)
	}

	// Second custom-client query: cache hit with B's answer (group cache).
	resp = h.queryFrom(t, "100.64.0.30", "cacheme.test")
	if got := firstAnswer(t, resp).(*dns.A).A.String(); got != "10.9.9.9" {
		t.Errorf("custom cache answer = %s, want 10.9.9.9", got)
	}

	if hitsA.Load() != 1 || hitsB.Load() != 1 {
		t.Errorf("upstream hits A=%d B=%d, want 1/1", hitsA.Load(), hitsB.Load())
	}
}

func firstAnswer(t *testing.T, resp *dns.Msg) dns.RR {
	t.Helper()
	if resp == nil || len(resp.Answer) == 0 {
		t.Fatalf("DNS response has no answers: %+v", resp)
	}
	return resp.Answer[0]
}

func TestExcludeFromLogAndStats(t *testing.T) {
	var hits atomic.Int32
	upstreamAddr := startFakeUpstream(t, &hits)
	reg := newTestRegistry(t,
		clients.Client{
			Name: "quiet", IDs: []string{"100.64.0.40"},
			UseGlobalSettings: false, ExcludeFromLog: true,
		},
		clients.Client{
			Name: "nostats", IDs: []string{"100.64.0.41"},
			UseGlobalSettings: false, ExcludeFromStats: true,
		},
	)
	pool := upstream.NewPool(upstream.PoolConfig{Mode: upstream.ModeStrict, PrimarySpecs: []string{upstreamAddr}})
	h := startClientHarness(t, Config{Pool: pool, Clients: reg})

	// exclude_from_log: answered, but no event at all.
	resp := h.queryFrom(t, "100.64.0.40", "quiet.test")
	if len(resp.Answer) != 1 {
		t.Errorf("quiet answer = %v", resp.Answer)
	}
	h.expectNoEvent(t)

	// exclude_from_stats: answered, event emitted with the flag set.
	resp = h.queryFrom(t, "100.64.0.41", "nostats.test")
	if len(resp.Answer) != 1 {
		t.Errorf("nostats answer = %v", resp.Answer)
	}
	ev := h.nextEvent(t)
	if !ev.exc {
		t.Errorf("nostats event must carry excludeFromStats=true: %+v", ev)
	}
}

func TestClientNameWinsOverAlias(t *testing.T) {
	var hits atomic.Int32
	upstreamAddr := startFakeUpstream(t, &hits)
	reg := newTestRegistry(t, clients.Client{
		Name: "registry-name", IDs: []string{"100.64.0.50"}, UseGlobalSettings: true,
	})
	pool := upstream.NewPool(upstream.PoolConfig{Mode: upstream.ModeStrict, PrimarySpecs: []string{upstreamAddr}})
	h := startClientHarness(t, Config{
		Pool:      pool,
		Clients:   reg,
		AliasFunc: func(string) string { return "env-alias" },
	})

	h.queryFrom(t, "100.64.0.50", "example.org")
	if ev := h.nextEvent(t); ev.ev.Alias != "registry-name" {
		t.Errorf("registry client alias = %q, want registry-name", ev.ev.Alias)
	}

	h.queryFrom(t, "100.64.0.99", "other.org")
	if ev := h.nextEvent(t); ev.ev.Alias != "env-alias" {
		t.Errorf("fallback alias = %q, want env-alias", ev.ev.Alias)
	}
}

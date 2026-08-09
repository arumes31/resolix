package dnsserver

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"tailscale-dnsrewrite/webgui/internal/filter"
	"tailscale-dnsrewrite/webgui/internal/models"
)

// filterHarness bundles a server under test with a filter engine and a fake
// upstream for blocking-mode tests.
type filterHarness struct {
	srv        *Server
	engine     *filter.Engine
	query      func(name string, qtype uint16) *dns.Msg
	events     chan models.QueryEvent
	upstream   *atomic.Int32
	serverAddr string
}

// startFilteredServer starts a fake upstream and a server under test whose
// filter blocks blocked.test (with exception allowed.blocked.test) using the
// given blocking mode.
func startFilteredServer(t *testing.T, mode string) *filterHarness {
	t.Helper()

	var hits atomic.Int32
	upstreamAddr := startFakeUpstream(t, &hits)

	eng := filter.New()
	listPath := filepath.Join(t.TempDir(), "blocklist.txt")
	if err := os.WriteFile(listPath, []byte("||blocked.test^\n@@||allowed.blocked.test^\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	eng.AddFileSource(listPath, false)

	events := make(chan models.QueryEvent, 20)
	srv := New(Config{
		Addr:           "127.0.0.1",
		Upstreams:      []string{upstreamAddr},
		NodeName:       "test-node",
		Filter:         eng,
		BlockingMode:   mode,
		BlockCustomIP4: "192.0.2.66",
		BlockCustomIP6: "2001:db8::66",
	}, func(ev models.QueryEvent, _ bool) { events <- ev })

	serverAddr := startTestServer(t, srv)
	client := &dns.Client{Timeout: 500 * time.Millisecond}
	h := &filterHarness{
		srv: srv, engine: eng, events: events, upstream: &hits, serverAddr: serverAddr,
	}
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

	// Wait for the listener (blocked domain → no upstream hit).
	deadline := time.Now().Add(2 * time.Second)
	for {
		m := new(dns.Msg)
		m.SetQuestion("blocked.test.", dns.TypeA)
		if _, _, err := client.Exchange(m, serverAddr); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("filtered server did not start listening")
		}
		time.Sleep(20 * time.Millisecond)
	}
	<-events // discard warmup event
	return h
}

func (h *filterHarness) nextEvent(t *testing.T) models.QueryEvent {
	t.Helper()
	select {
	case ev := <-h.events:
		return ev
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for query event")
		return models.QueryEvent{}
	}
}

func TestBlockingModes(t *testing.T) {
	tests := []struct {
		mode       string
		wantRcode  int
		wantAnswer string // expected A record IP ("" = no answers expected)
	}{
		{"nxdomain", dns.RcodeNameError, ""},
		{"null_ip", dns.RcodeSuccess, "0.0.0.0"},
		{"refused", dns.RcodeRefused, ""},
		{"custom_ip", dns.RcodeSuccess, "192.0.2.66"},
	}

	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			h := startFilteredServer(t, tt.mode)

			resp := h.query("ads.blocked.test", dns.TypeA)
			if resp.Rcode != tt.wantRcode {
				t.Errorf("rcode = %s, want %s", dns.RcodeToString[resp.Rcode], dns.RcodeToString[tt.wantRcode])
			}
			if tt.wantAnswer == "" {
				if len(resp.Answer) != 0 {
					t.Errorf("expected no answers, got %v", resp.Answer)
				}
			} else {
				if len(resp.Answer) != 1 {
					t.Fatalf("expected 1 answer, got %v", resp.Answer)
				}
				a, ok := resp.Answer[0].(*dns.A)
				if !ok || a.A.String() != tt.wantAnswer {
					t.Errorf("answer = %v, want A %s", resp.Answer[0], tt.wantAnswer)
				}
				if a.Hdr.Ttl != staticTTL {
					t.Errorf("blocked answer TTL = %d, want %d", a.Hdr.Ttl, staticTTL)
				}
			}
			if h.upstream.Load() != 0 {
				t.Errorf("blocked query hit the upstream %d times", h.upstream.Load())
			}

			ev := h.nextEvent(t)
			if !ev.Blocked || ev.MatchedRule != "||blocked.test^" || ev.BlockReason != filter.ReasonBlocklist {
				t.Errorf("blocked event = %+v", ev)
			}
			if ev.Upstream != "Filtered" || ev.ResponseCode != dns.RcodeToString[tt.wantRcode] {
				t.Errorf("blocked event upstream/rcode = %+v", ev)
			}

			// Blocked answers must not be cached: cache stays empty, and a
			// repeat query regenerates the same response without the upstream.
			if got := h.srv.cache.len(); got != 0 {
				t.Errorf("blocked answer cached (cache len = %d)", got)
			}
			resp2 := h.query("ads.blocked.test", dns.TypeA)
			if resp2.Rcode != tt.wantRcode {
				t.Errorf("repeat rcode = %s, want %s", dns.RcodeToString[resp2.Rcode], dns.RcodeToString[tt.wantRcode])
			}
			if h.upstream.Load() != 0 {
				t.Errorf("repeat blocked query hit the upstream %d times", h.upstream.Load())
			}
			_ = h.nextEvent(t)
		})
	}
}

func TestBlockingModeNullIPAAAA(t *testing.T) {
	h := startFilteredServer(t, "null_ip")
	resp := h.query("blocked.test", dns.TypeAAAA)
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
		t.Fatalf("AAAA blocked response = %v", resp)
	}
	aaaa, ok := resp.Answer[0].(*dns.AAAA)
	if !ok || aaaa.AAAA.String() != "::" {
		t.Errorf("AAAA answer = %v, want ::", resp.Answer[0])
	}
}

func TestFilterExceptionFallsThroughToUpstream(t *testing.T) {
	h := startFilteredServer(t, "nxdomain")

	// allowed.blocked.test has an exception → forwarded to the fake upstream.
	resp := h.query("allowed.blocked.test", dns.TypeA)
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
		t.Fatalf("exception response = %v", resp)
	}
	if resp.Answer[0].(*dns.A).A.String() != "93.184.216.34" {
		t.Errorf("exception answer = %v, want upstream answer", resp.Answer[0])
	}
	if h.upstream.Load() != 1 {
		t.Errorf("exception query upstream hits = %d, want 1", h.upstream.Load())
	}
	ev := h.nextEvent(t)
	if ev.Blocked {
		t.Errorf("exception event must not be blocked: %+v", ev)
	}
}

func TestFilterPausedSkipsFiltering(t *testing.T) {
	h := startFilteredServer(t, "nxdomain")
	h.engine.Pause(5)

	resp := h.query("blocked.test", dns.TypeA)
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
		t.Fatalf("paused response = %v, want forwarded answer", resp)
	}
	if h.upstream.Load() != 1 {
		t.Errorf("paused query upstream hits = %d, want 1", h.upstream.Load())
	}
	ev := h.nextEvent(t)
	if ev.Blocked {
		t.Errorf("paused event must not be blocked: %+v", ev)
	}

	h.engine.Pause(0) // resume
	resp = h.query("blocked.test", dns.TypeA)
	if resp.Rcode != dns.RcodeNameError {
		t.Errorf("resumed rcode = %s, want NXDOMAIN", dns.RcodeToString[resp.Rcode])
	}
}

func TestStaticRewriteWinsOverFilter(t *testing.T) {
	// A static rewrite for a filtered domain must still answer first
	// (pipeline order: static rewrites → filter).
	var hits atomic.Int32
	upstreamAddr := startFakeUpstream(t, &hits)

	eng := filter.New()
	listPath := filepath.Join(t.TempDir(), "blocklist.txt")
	if err := os.WriteFile(listPath, []byte("||static.test^\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	eng.AddFileSource(listPath, false)

	srv := New(Config{
		Addr:         "127.0.0.1",
		Upstreams:    []string{upstreamAddr},
		StaticHosts:  ParseStaticHosts("static.test:100.64.0.1"),
		NodeName:     "test-node",
		Filter:       eng,
		BlockingMode: "nxdomain",
	}, nil)
	addr := startTestServer(t, srv)

	client := &dns.Client{Timeout: 2 * time.Second}
	m := new(dns.Msg)
	m.SetQuestion("static.test.", dns.TypeA)
	resp, _, err := client.Exchange(m, addr)
	if err != nil {
		t.Fatalf("query static.test: %v", err)
	}
	if len(resp.Answer) != 1 || resp.Answer[0].(*dns.A).A.String() != "100.64.0.1" {
		t.Fatalf("static rewrite lost to filter: %v", resp)
	}
}

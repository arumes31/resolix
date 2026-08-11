package dnsserver

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/arumes31/resolix/webgui/internal/clients"
	"github.com/arumes31/resolix/webgui/internal/models"
	"github.com/arumes31/resolix/webgui/internal/upstream"
)

func TestACLAllowDenyDrop(t *testing.T) {
	var hits atomic.Int32
	upstreamAddr := startFakeUpstream(t, &hits)
	pool := upstream.NewPool(upstream.PoolConfig{Mode: upstream.ModeStrict, PrimarySpecs: []string{upstreamAddr}})

	h := startClientHarness(t, Config{
		Pool:              pool,
		AllowedClients:    "100.64.0.0/10",
		DisallowedClients: "100.64.0.5",
	})

	// Allowed client: answered.
	w := &fakeResponseWriter{remote: &net.UDPAddr{IP: net.ParseIP("100.64.0.10"), Port: 53000}}
	m := new(dns.Msg)
	m.SetQuestion("example.org.", dns.TypeA)
	h.srv.ServeDNS(w, m)
	if w.last == nil || len(w.last.Answer) != 1 {
		t.Fatalf("allowed client: no answer (%v)", w.last)
	}
	_ = h.nextEvent(t)

	// Outside the allowed list: dropped silently, no event.
	w = &fakeResponseWriter{remote: &net.UDPAddr{IP: net.ParseIP("192.168.1.10"), Port: 53000}}
	h.srv.ServeDNS(w, m)
	if w.last != nil {
		t.Fatalf("outsider got a response: %v", w.last)
	}
	h.expectNoEvent(t)

	// Disallowed client: dropped silently (no response at all).
	w = &fakeResponseWriter{remote: &net.UDPAddr{IP: net.ParseIP("100.64.0.5"), Port: 53000}}
	h.srv.ServeDNS(w, m)
	if w.last != nil {
		t.Errorf("disallowed client got a response: %v", w.last)
	}
	if hits.Load() != 1 {
		t.Errorf("upstream hits = %d, want 1 (only the allowed client)", hits.Load())
	}
	deniedDropped, allowlistDropped, _ := h.srv.ACLStats()
	if deniedDropped != 1 || allowlistDropped != 1 {
		t.Errorf("ACL drops = deny:%d allowlist:%d, want 1 each", deniedDropped, allowlistDropped)
	}
}

func TestACLDefaultAllowsAll(t *testing.T) {
	var hits atomic.Int32
	upstreamAddr := startFakeUpstream(t, &hits)
	pool := upstream.NewPool(upstream.PoolConfig{Mode: upstream.ModeStrict, PrimarySpecs: []string{upstreamAddr}})
	h := startClientHarness(t, Config{Pool: pool})

	w := &fakeResponseWriter{remote: &net.UDPAddr{IP: net.ParseIP("203.0.113.7"), Port: 53000}}
	m := new(dns.Msg)
	m.SetQuestion("example.org.", dns.TypeA)
	h.srv.ServeDNS(w, m)
	if w.last == nil || len(w.last.Answer) != 1 {
		t.Error("empty ACL must allow any client")
	}
}

func TestInvalidConfiguredAllowACLDropsAll(t *testing.T) {
	h := startClientHarness(t, Config{AllowedClients: "not-a-cidr"})
	w := &fakeResponseWriter{remote: &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 53000}}
	request := new(dns.Msg)
	request.SetQuestion("example.org.", dns.TypeA)
	h.srv.ServeDNS(w, request)
	if w.last != nil {
		t.Fatalf("invalid configured allow ACL returned a response: %v", w.last)
	}
}

func TestRateLimiter(t *testing.T) {
	rl := newRateLimiter(3)

	// Burst of 3 allowed, 4th limited.
	for i := 0; i < 3; i++ {
		if !rl.allow("100.64.1.5") {
			t.Fatalf("query %d must be allowed", i+1)
		}
	}
	if rl.allow("100.64.1.5") {
		t.Error("4th query in the same /24 must be limited")
	}

	// Different /24 is isolated.
	if !rl.allow("100.64.2.9") {
		t.Error("different /24 must have its own bucket")
	}

	// Refill after a second.
	rl.mu.Lock()
	rl.buckets["100.64.1.0/24"].last = time.Now().Add(-2 * time.Second)
	rl.mu.Unlock()
	if !rl.allow("100.64.1.5") {
		t.Error("bucket must refill over time")
	}

	// Cleanup evicts idle buckets.
	rl.mu.Lock()
	rl.buckets["100.64.1.0/24"].last = time.Now().Add(-time.Hour)
	rl.mu.Unlock()
	before := rl.bucketCount()
	rl.cleanup(10 * time.Minute)
	if rl.bucketCount() >= before {
		t.Errorf("cleanup did not evict idle bucket (before=%d after=%d)", before, rl.bucketCount())
	}
}

func TestRateLimiterBucketBound(t *testing.T) {
	rl := newRateLimiter(1)
	rl.maxBuckets = 1
	if !rl.allow("192.0.2.1") {
		t.Fatal("first subnet was unexpectedly limited")
	}
	if !rl.allow("198.51.100.1") {
		t.Fatal("new subnet was unexpectedly limited after the bucket limit was reached")
	}
	if got := rl.bucketCount(); got != 1 {
		t.Fatalf("bucket count = %d, want 1", got)
	}
	if _, ok := rl.buckets["192.0.2.0/24"]; ok {
		t.Fatal("least-recently-used bucket was not evicted")
	}
}

func TestClearCache(t *testing.T) {
	srv := New(Config{}, nil)
	srv.cache.set(cacheKey{name: "cached.test", qtype: dns.TypeA}, &cacheEntry{
		answers:  []dns.RR{aRecord("cached.test.", "192.0.2.1", 120)},
		rcode:    dns.RcodeSuccess,
		storedAt: time.Now(),
		ttl:      120,
	})
	if got := srv.ClearCache(); got != 1 {
		t.Fatalf("ClearCache() = %d, want 1", got)
	}
	if got := srv.cache.len(); got != 0 {
		t.Fatalf("cache length = %d, want 0", got)
	}
}

func TestRateLimitEndToEnd(t *testing.T) {
	var hits atomic.Int32
	upstreamAddr := startFakeUpstream(t, &hits)
	pool := upstream.NewPool(upstream.PoolConfig{Mode: upstream.ModeStrict, PrimarySpecs: []string{upstreamAddr}})
	h := startClientHarness(t, Config{Pool: pool, RateLimitQPS: 2})

	m := func() *dns.Msg {
		q := new(dns.Msg)
		q.SetQuestion("example.org.", dns.TypeA)
		return q
	}
	w := &fakeResponseWriter{remote: &net.UDPAddr{IP: net.ParseIP("100.64.1.5"), Port: 53000}}

	h.srv.ServeDNS(w, m()) // 1: forwarded
	h.srv.ServeDNS(w, m()) // 2: cache hit
	w3 := &fakeResponseWriter{remote: w.remote}
	h.srv.ServeDNS(w3, m()) // 3: silently dropped (over limit)
	if w3.last != nil {
		t.Fatalf("3rd query returned a response: %v", w3.last)
	}
	if got := h.srv.RateLimitDropped(); got != 1 {
		t.Errorf("dropped = %d, want 1", got)
	}
}

func TestPrivatePTR(t *testing.T) {
	var hits atomic.Int32
	upstreamAddr := startFakeUpstream(t, &hits)
	reg := newTestRegistry(t, clients.Client{
		Name: "kids-pc", IDs: []string{"100.64.0.60"}, UseGlobalSettings: true,
	})
	pool := upstream.NewPool(upstream.PoolConfig{Mode: upstream.ModeStrict, PrimarySpecs: []string{upstreamAddr}})
	h := startClientHarness(t, Config{
		Pool:       pool,
		Clients:    reg,
		PrivatePTR: true,
		AliasFunc: func(ip string) string {
			if ip == "100.64.0.61" {
				return "alias host" // sanitized to alias-host
			}
			return ""
		},
	})

	// Registry client name wins.
	ptrQuery := func(name string) *dns.Msg {
		t.Helper()
		w := &fakeResponseWriter{remote: &net.UDPAddr{IP: net.ParseIP("100.64.0.99"), Port: 53000}}
		m := new(dns.Msg)
		m.SetQuestion(name, dns.TypePTR)
		h.srv.ServeDNS(w, m)
		return w.last
	}

	resp := ptrQuery("60.0.64.100.in-addr.arpa.")
	if !resp.Authoritative {
		t.Fatal("private PTR response is not authoritative")
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("registry PTR answer = %v", resp.Answer)
	}
	if ptr := resp.Answer[0].(*dns.PTR); ptr.Ptr != "kids-pc.lan." {
		t.Errorf("registry PTR = %q, want kids-pc.lan.", ptr.Ptr)
	}
	if ev := h.nextEvent(t); ev.ev.Upstream != "Private PTR" {
		t.Errorf("PTR event upstream = %q", ev.ev.Upstream)
	}

	// Alias fallback (sanitized).
	resp = ptrQuery("61.0.64.100.in-addr.arpa.")
	if len(resp.Answer) == 0 {
		t.Fatalf("alias PTR response has no answers: %+v", resp)
	}
	if ptr := resp.Answer[0].(*dns.PTR); ptr.Ptr != "alias-host.lan." {
		t.Errorf("alias PTR = %q, want alias-host.lan.", ptr.Ptr)
	}
	_ = h.nextEvent(t)

	// Unknown private address → forwarded to upstream.
	before := hits.Load()
	_ = ptrQuery("70.0.64.100.in-addr.arpa.")
	if hits.Load() != before+1 {
		t.Error("unknown private PTR was not forwarded")
	}
	_ = h.nextEvent(t)

	// Public address → always forwarded, never answered locally.
	before = hits.Load()
	resp = ptrQuery("8.8.8.8.in-addr.arpa.")
	if hits.Load() != before+1 {
		t.Error("public PTR must be forwarded")
	}
	for _, rr := range resp.Answer {
		if _, ok := rr.(*dns.PTR); ok {
			t.Errorf("public PTR answered locally: %v", rr)
		}
	}
	_ = h.nextEvent(t)
}

func TestArpaToIP(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"1.2.168.192.in-addr.arpa", "192.168.2.1"},
		{"1.2.168.192.in-addr.arpa.", "192.168.2.1"},
		{"8.8.8.8.in-addr.arpa", "8.8.8.8"},
		{".2.168.192.in-addr.arpa", ""},
		{"0001.2.168.192.in-addr.arpa", ""},
		{"bad.in-addr.arpa", ""},
		{"1.2.3.in-addr.arpa", ""},
		{"example.com", ""},
		// 2001:db8::1 reversed nibble form
		{"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa", "2001:db8::1"},
	}
	for _, tt := range tests {
		got := arpaToIP(tt.in)
		gotStr := ""
		if got != nil {
			gotStr = got.String()
		}
		if gotStr != tt.want {
			t.Errorf("arpaToIP(%q) = %q, want %q", tt.in, gotStr, tt.want)
		}
	}
}

func TestDNSSECPassthrough(t *testing.T) {
	var sawDO atomic.Bool
	upstreamAddr := startUDPUpstreamForDNSSEC(t, &sawDO)

	pool := upstream.NewPool(upstream.PoolConfig{Mode: upstream.ModeStrict, PrimarySpecs: []string{upstreamAddr}})
	h := startClientHarness(t, Config{Pool: pool, DNSSEC: true})

	h.queryFrom(t, "100.64.0.10", "example.org")
	if !sawDO.Load() {
		t.Error("upstream query did not carry the DO bit")
	}
	ev := h.nextEvent(t)
	if ev.ev.DNSSEC != "secure" {
		t.Errorf("event DNSSEC = %q, want secure (AD bit set by upstream)", ev.ev.DNSSEC)
	}

	// A cache hit must preserve the upstream AD bit and secure event status.
	h.queryFrom(t, "100.64.0.10", "example.org")
	if ev := h.nextEvent(t); ev.ev.DNSSEC != "secure" || ev.ev.Upstream != "System Cache" {
		t.Errorf("cached event: DNSSEC=%q upstream=%q", ev.ev.DNSSEC, ev.ev.Upstream)
	}
}

func TestDNSSECDisabledClearsClientDO(t *testing.T) {
	var sawDO atomic.Bool
	upstreamAddr := startUDPUpstreamForDNSSEC(t, &sawDO)
	pool := upstream.NewPool(upstream.PoolConfig{Mode: upstream.ModeStrict, PrimarySpecs: []string{upstreamAddr}})
	h := startClientHarness(t, Config{Pool: pool, DNSSEC: false})

	m := new(dns.Msg)
	m.SetQuestion("example.org.", dns.TypeA)
	m.SetEdns0(4096, true)
	w := &fakeResponseWriter{remote: &net.UDPAddr{IP: net.ParseIP("100.64.0.10"), Port: 53000}}
	h.srv.ServeDNS(w, m)
	if w.last == nil || len(w.last.Answer) != 1 {
		t.Fatalf("answer = %v", w.last)
	}
	if sawDO.Load() {
		t.Error("upstream query carried DO while DNSSEC was disabled")
	}
	if ev := h.nextEvent(t); ev.ev.DNSSEC != "" {
		t.Errorf("event DNSSEC = %q, want empty while disabled", ev.ev.DNSSEC)
	}
}

// startUDPUpstreamForDNSSEC answers A queries and sets the AD bit when the
// query carried the DO bit; it records DO-bit sightings.
func startUDPUpstreamForDNSSEC(t *testing.T, sawDO *atomic.Bool) string {
	t.Helper()
	pc := mustListenPacket(t)
	fake := &dns.Server{
		PacketConn: pc,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			m := new(dns.Msg)
			m.SetReply(r)
			if opt := r.IsEdns0(); opt != nil && opt.Do() {
				sawDO.Store(true)
				m.AuthenticatedData = true
			}
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

func TestDoTRoundTrip(t *testing.T) {
	var hits atomic.Int32
	upstreamAddr := startFakeUpstream(t, &hits)
	pool := upstream.NewPool(upstream.PoolConfig{Mode: upstream.ModeStrict, PrimarySpecs: []string{upstreamAddr}})

	events := make(chan models.QueryEvent, 5)
	srv := New(Config{
		Addr:     "127.0.0.1",
		NodeName: "test-node",
		Pool:     pool,
	}, func(ev models.QueryEvent, _ bool) { events <- ev })

	// Pre-bound UDP/TCP plus a TLS listener with a self-signed cert.
	udpConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cert := selfSignedCertForDoT(t)
	tlsLn, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.startOn(ctx, udpConn, tcpLn, tlsLn) }()
	t.Cleanup(func() { cancel(); <-done })

	client := &dns.Client{
		Net:     "tcp-tls",
		Timeout: 2 * time.Second,
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true, // #nosec G402 -- test-only: self-signed test cert
			MinVersion:         tls.VersionTLS12,
		},
	}
	m := new(dns.Msg)
	m.SetQuestion("example.org.", dns.TypeA)
	resp, _, err := client.Exchange(m, tlsLn.Addr().String())
	if err != nil {
		t.Fatalf("DoT exchange: %v", err)
	}
	if len(resp.Answer) != 1 || resp.Answer[0].(*dns.A).A.String() != "93.184.216.34" {
		t.Fatalf("DoT answer = %v", resp.Answer)
	}
	select {
	case <-events:
	case <-time.After(2 * time.Second):
		t.Fatal("no event from DoT query")
	}
}

func TestDoTWithoutCertsFails(t *testing.T) {
	srv := New(Config{
		Addr:       "127.0.0.1",
		Port:       0,
		NodeName:   "test-node",
		DoTEnabled: true, // no cert/key configured
	}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := srv.Start(ctx); err == nil {
		t.Error("expected startup failure when DoT is enabled without certs")
	}
}

// selfSignedCertForDoT generates a self-signed certificate for tests.
func selfSignedCertForDoT(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

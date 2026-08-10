package upstream

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// testAnswerIP is the A record every test upstream answers with (unless a
// custom handler says otherwise).
const testAnswerIP = "93.184.216.34"

type closeTrackingTransport struct {
	base   http.RoundTripper
	closed atomic.Bool
}

func (t *closeTrackingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return t.base.RoundTrip(request)
}

func (t *closeTrackingTransport) CloseIdleConnections() {
	t.closed.Store(true)
	if closer, ok := t.base.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

// startUDPUpstream starts a fake UDP DNS server on an ephemeral loopback
// port answering A queries with testAnswerIP.
func startUDPUpstream(t *testing.T, hits *atomic.Int32) string {
	t.Helper()
	return startUDPUpstreamHandler(t, func(w dns.ResponseWriter, r *dns.Msg) {
		if hits != nil {
			hits.Add(1)
		}
		m := new(dns.Msg)
		m.SetReply(r)
		if len(r.Question) > 0 {
			m.Answer = []dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 120},
				A:   net.ParseIP(testAnswerIP).To4(),
			}}
		}
		_ = w.WriteMsg(m)
	})
}

// startUDPUpstreamHandler starts a fake UDP DNS server with a custom handler.
func startUDPUpstreamHandler(t *testing.T, handler dns.HandlerFunc) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: handler}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

// deadAddr returns an address with a closed UDP port (a server that was
// started and immediately shut down).
func deadAddr(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().String()
	_ = pc.Close()
	return addr
}

// selfSignedCert generates a self-signed certificate for 127.0.0.1 (IP SAN).
func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
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
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func queryA() *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion("example.org.", dns.TypeA)
	return m
}

func TestUDPResolver(t *testing.T) {
	var hits atomic.Int32
	addr := startUDPUpstream(t, &hits)

	spec, err := Parse(addr)
	if err != nil {
		t.Fatal(err)
	}
	r := &dnsResolver{spec: spec}
	resp, err := r.Exchange(queryA())
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if len(resp.Answer) != 1 || resp.Answer[0].(*dns.A).A.String() != testAnswerIP {
		t.Fatalf("answer = %v", resp.Answer)
	}
	if hits.Load() != 1 {
		t.Errorf("hits = %d", hits.Load())
	}
}

func TestDoTResolver(t *testing.T) {
	cert := selfSignedCert(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{
		Listener: ln,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			m := new(dns.Msg)
			m.SetReply(r)
			if len(r.Question) > 0 {
				m.Answer = []dns.RR{&dns.A{
					Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 120},
					A:   net.ParseIP(testAnswerIP).To4(),
				}}
			}
			_ = w.WriteMsg(m)
		}),
	}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })

	// Test-only TLS override (self-signed cert is not in system roots).
	testTLSConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402 -- test-only hook, required for the self-signed test cert
	t.Cleanup(func() { testTLSConfig = nil })

	spec, err := Parse("tls://" + ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	r := &dnsResolver{spec: spec}
	resp, err := r.Exchange(queryA())
	if err != nil {
		t.Fatalf("DoT exchange: %v", err)
	}
	if len(resp.Answer) != 1 || resp.Answer[0].(*dns.A).A.String() != testAnswerIP {
		t.Fatalf("DoT answer = %v", resp.Answer)
	}
}

func TestDoHResolver(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ct := r.Header.Get("Content-Type"); ct != "application/dns-message" {
			t.Errorf("content-type = %q", ct)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
			return
		}
		req := new(dns.Msg)
		if err := req.Unpack(body); err != nil {
			t.Errorf("unpack: %v", err)
			return
		}
		m := new(dns.Msg)
		m.SetReply(req)
		if len(req.Question) > 0 {
			m.Answer = []dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 120},
				A:   net.ParseIP(testAnswerIP).To4(),
			}}
		}
		wire, _ := m.Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(wire)
	}))
	defer server.Close()

	testHTTPClient = server.Client()
	t.Cleanup(func() { testHTTPClient = nil })

	spec, err := Parse(server.URL + "/dns-query")
	if err != nil {
		t.Fatal(err)
	}
	r := &dohResolver{spec: spec}
	resp, err := r.Exchange(queryA())
	if err != nil {
		t.Fatalf("DoH exchange: %v", err)
	}
	if len(resp.Answer) != 1 || resp.Answer[0].(*dns.A).A.String() != testAnswerIP {
		t.Fatalf("DoH answer = %v", resp.Answer)
	}
}

func TestDoHHTTPClientConcurrentInitialization(t *testing.T) {
	spec, err := Parse("https://1.1.1.1/dns-query")
	if err != nil {
		t.Fatal(err)
	}
	r := &dohResolver{spec: spec}
	clients := make(chan *http.Client, 32)
	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			clients <- r.httpClient()
		}()
	}
	wg.Wait()
	close(clients)
	for client := range clients {
		if client != r.client {
			t.Fatal("concurrent initialization returned different clients")
		}
	}
}

func TestProbeRejectsUnsuccessfulRcode(t *testing.T) {
	addr := startUDPUpstreamHandler(t, func(w dns.ResponseWriter, request *dns.Msg) {
		response := new(dns.Msg)
		response.SetRcode(request, dns.RcodeServerFailure)
		_ = w.WriteMsg(response)
	})
	if err := Probe(context.Background(), addr, "health.test", nil); err == nil {
		t.Fatal("Probe accepted SERVFAIL response")
	}
}

func TestProbeClosesDoHIdleConnections(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		wire, err := io.ReadAll(request.Body)
		if err != nil {
			t.Errorf("read request: %v", err)
			return
		}
		query := new(dns.Msg)
		if err := query.Unpack(wire); err != nil {
			t.Errorf("unpack request: %v", err)
			return
		}
		response := new(dns.Msg)
		response.SetReply(query)
		packed, err := response.Pack()
		if err != nil {
			t.Errorf("pack response: %v", err)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(packed)
	}))
	defer server.Close()

	client := server.Client()
	transport := &closeTrackingTransport{base: client.Transport}
	client.Transport = transport
	testHTTPClient = client
	t.Cleanup(func() { testHTTPClient = nil })

	if err := Probe(context.Background(), server.URL+"/dns-query", "health.test", nil); err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if !transport.closed.Load() {
		t.Fatal("Probe left DoH transport idle connections open")
	}
}

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
	"slices"
	"strings"
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

func startBootstrapServer(t *testing.T, host string, hits *atomic.Int32) string {
	t.Helper()
	return startUDPUpstreamHandler(t, func(w dns.ResponseWriter, request *dns.Msg) {
		hits.Add(1)
		response := new(dns.Msg)
		response.SetReply(request)
		if len(request.Question) > 0 && request.Question[0].Name == dns.Fqdn(host) && request.Question[0].Qtype == dns.TypeA {
			response.Answer = []dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 120},
				A:   net.ParseIP("127.0.0.1").To4(),
			}}
		}
		_ = w.WriteMsg(response)
	})
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

func TestDoTResolverUsesBootstrapServer(t *testing.T) {
	const hostname = "dot.bootstrap.test"
	var bootstrapHits atomic.Int32
	var queriesMu sync.Mutex
	var encryptedQueries []string
	bootstrapAddress := startBootstrapServer(t, hostname, &bootstrapHits)

	cert := selfSignedCert(t)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	server := &dns.Server{Listener: listener, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		queriesMu.Lock()
		encryptedQueries = append(encryptedQueries, request.Question[0].Name)
		queriesMu.Unlock()
		response := new(dns.Msg)
		response.SetReply(request)
		response.Answer = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 120},
			A:   net.ParseIP(testAnswerIP).To4(),
		}}
		_ = w.WriteMsg(response)
	})}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })

	testTLSConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402 -- test-only self-signed fixture
	t.Cleanup(func() { testTLSConfig = nil })
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	spec, err := Parse("tls://" + net.JoinHostPort(hostname, port))
	if err != nil {
		t.Fatal(err)
	}
	pool := NewPool(PoolConfig{
		Mode:             ModeStrict,
		PrimarySpecs:     []string{spec.Raw},
		BootstrapServers: []string{bootstrapAddress},
	})
	response, _, err := pool.Exchange(queryA())
	if err != nil {
		t.Fatalf("DoT exchange through bootstrap: %v", err)
	}
	if err := pool.Probe(context.Background(), spec.Raw, "health.test"); err != nil {
		t.Fatalf("DoT pool probe: %v", err)
	}
	queriesMu.Lock()
	gotQueries := append([]string(nil), encryptedQueries...)
	queriesMu.Unlock()
	if len(response.Answer) != 1 || bootstrapHits.Load() != 1 {
		t.Fatalf("DoT answer/bootstrap hits = %v/%d", response.Answer, bootstrapHits.Load())
	}
	if !slices.Equal(gotQueries, []string{"example.org.", "health.test."}) {
		t.Fatalf("DoT encrypted queries = %v", gotQueries)
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

func TestDoHResolverRejectsInvalidResponseMetadata(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		changeID    bool
		wantError   string
	}{
		{name: "content type", contentType: "text/plain", wantError: "invalid content type"},
		{name: "message ID", contentType: "application/dns-message", changeID: true, wantError: "message ID mismatch"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				wire, err := io.ReadAll(request.Body)
				if err != nil {
					t.Errorf("read body: %v", err)
					return
				}
				query := new(dns.Msg)
				if err := query.Unpack(wire); err != nil {
					t.Errorf("unpack query: %v", err)
					return
				}
				response := new(dns.Msg)
				response.SetReply(query)
				if test.changeID {
					response.Id++
				}
				packed, err := response.Pack()
				if err != nil {
					t.Errorf("pack response: %v", err)
					return
				}
				w.Header().Set("Content-Type", test.contentType)
				_, _ = w.Write(packed)
			}))
			defer server.Close()

			testHTTPClient = server.Client()
			defer func() { testHTTPClient = nil }()
			spec, err := Parse(server.URL + "/dns-query")
			if err != nil {
				t.Fatal(err)
			}
			_, err = (&dohResolver{spec: spec}).Exchange(queryA())
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("Exchange error = %v, want %q", err, test.wantError)
			}
		})
	}
}

func TestDoHResolverRejectsInvalidHTTPAndDNSResponses(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		wire, err := io.ReadAll(request.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
			return
		}
		query := new(dns.Msg)
		if err := query.Unpack(wire); err != nil {
			t.Errorf("unpack query: %v", err)
			return
		}
		response := new(dns.Msg)
		response.SetReply(query)
		switch request.URL.Path {
		case "/status":
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		case "/content-type":
			w.Header().Set("Content-Type", "text/plain")
		case "/message-id":
			response.Id++
			w.Header().Set("Content-Type", "application/dns-message")
		case "/not-response":
			response.Response = false
			w.Header().Set("Content-Type", "application/dns-message")
		}
		packed, err := response.Pack()
		if err != nil {
			t.Errorf("pack response: %v", err)
			return
		}
		_, _ = w.Write(packed)
	}))
	t.Cleanup(server.Close)

	testHTTPClient = server.Client()
	t.Cleanup(func() { testHTTPClient = nil })
	for _, test := range []struct {
		path string
		want string
	}{
		{path: "/status", want: "status 503"},
		{path: "/content-type", want: "invalid content type"},
		{path: "/message-id", want: "message ID mismatch"},
		{path: "/not-response", want: "not a DNS response"},
	} {
		t.Run(test.path, func(t *testing.T) {
			spec, err := Parse(server.URL + test.path)
			if err != nil {
				t.Fatal(err)
			}
			_, err = (&dohResolver{spec: spec}).Exchange(queryA())
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Exchange() error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestDoHResolverUsesBootstrapServer(t *testing.T) {
	const hostname = "doh.bootstrap.test"
	var bootstrapHits atomic.Int32
	var queriesMu sync.Mutex
	var encryptedQueries []string
	bootstrapAddress := startBootstrapServer(t, hostname, &bootstrapHits)

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		wire, err := io.ReadAll(request.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
			return
		}
		query := new(dns.Msg)
		if err := query.Unpack(wire); err != nil {
			t.Errorf("unpack query: %v", err)
			return
		}
		queriesMu.Lock()
		encryptedQueries = append(encryptedQueries, query.Question[0].Name)
		queriesMu.Unlock()
		response := new(dns.Msg)
		response.SetReply(query)
		response.Answer = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 120},
			A:   net.ParseIP(testAnswerIP).To4(),
		}}
		packed, err := response.Pack()
		if err != nil {
			t.Errorf("pack response: %v", err)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(packed)
	}))
	defer server.Close()

	testTLSConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402 -- test-only self-signed fixture
	t.Cleanup(func() { testTLSConfig = nil })
	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	spec, err := Parse("https://" + net.JoinHostPort(hostname, port) + "/dns-query")
	if err != nil {
		t.Fatal(err)
	}
	pool := NewPool(PoolConfig{
		Mode:             ModeStrict,
		PrimarySpecs:     []string{spec.Raw},
		BootstrapServers: []string{bootstrapAddress},
	})
	response, _, err := pool.Exchange(queryA())
	if err != nil {
		t.Fatalf("DoH exchange through bootstrap: %v", err)
	}
	if err := pool.Probe(context.Background(), spec.Raw, "health.test"); err != nil {
		t.Fatalf("DoH pool probe: %v", err)
	}
	queriesMu.Lock()
	gotQueries := append([]string(nil), encryptedQueries...)
	queriesMu.Unlock()
	if len(response.Answer) != 1 || bootstrapHits.Load() != 1 {
		t.Fatalf("DoH answer/bootstrap hits = %v/%d", response.Answer, bootstrapHits.Load())
	}
	if !slices.Equal(gotQueries, []string{"example.org.", "health.test."}) {
		t.Fatalf("DoH encrypted queries = %v", gotQueries)
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

func TestProbeAcceptsNXDOMAINResponse(t *testing.T) {
	addr := startUDPUpstreamHandler(t, func(w dns.ResponseWriter, request *dns.Msg) {
		response := new(dns.Msg)
		response.SetRcode(request, dns.RcodeNameError)
		_ = w.WriteMsg(response)
	})
	if err := Probe(context.Background(), addr, "health.test", nil); err != nil {
		t.Fatalf("Probe rejected valid NXDOMAIN response: %v", err)
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

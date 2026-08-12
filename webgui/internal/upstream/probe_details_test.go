package upstream

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestProbeDetailedUDPReportsSuccessAndFailure(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		address := startUDPUpstream(t, nil)
		report, err := ProbeDetailed(context.Background(), address, "health.test", nil)
		if err != nil {
			t.Fatal(err)
		}
		if !report.Healthy || report.Failure != nil || report.DNSMessageID == 0 {
			t.Fatalf("successful report = %+v", report)
		}
		if report.Endpoint != address || report.TimingsMS["total"] < 0 {
			t.Fatalf("endpoint/timings = %q/%v", report.Endpoint, report.TimingsMS)
		}
	})

	t.Run("rcode failure", func(t *testing.T) {
		address := startUDPUpstreamHandler(t, func(w dns.ResponseWriter, request *dns.Msg) {
			response := new(dns.Msg)
			response.SetRcode(request, dns.RcodeServerFailure)
			_ = w.WriteMsg(response)
		})
		report, err := ProbeDetailed(context.Background(), address, "health.test", nil)
		if err != nil {
			t.Fatal(err)
		}
		if report.Healthy || report.Failure == nil || report.Failure.Code != "dns_rcode" {
			t.Fatalf("failed report = %+v", report)
		}
	})

	t.Run("bootstrap failure", func(t *testing.T) {
		report, err := ProbeDetailed(context.Background(), "tls://missing.example", "health.test", nil)
		if err != nil {
			t.Fatal(err)
		}
		if report.Failure == nil || report.Failure.Phase != "bootstrap" || report.Failure.Code != "resolution" {
			t.Fatalf("bootstrap report = %+v", report)
		}
	})

	if _, err := ProbeDetailed(context.Background(), "not a resolver", "health.test", nil); err == nil {
		t.Fatal("invalid resolver specification was accepted")
	}
}

func TestProbeDetailedDoT(t *testing.T) {
	certificate := selfSignedCert(t)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{certificate}})
	if err != nil {
		t.Fatal(err)
	}
	server := &dns.Server{Listener: listener, Handler: ipAnswerHandler(t, testAnswerIP, 0, nil)}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })
	testTLSConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402 -- isolated self-signed fixture
	t.Cleanup(func() { testTLSConfig = nil })

	report, err := ProbeDetailed(context.Background(), "tls://"+listener.Addr().String(), "health.test", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Healthy || report.TLSServerName != "127.0.0.1" || report.TLSExpiresAt.IsZero() {
		t.Fatalf("DoT report = %+v", report)
	}
}

func TestProbeDetailedDoH(t *testing.T) {
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
	t.Cleanup(server.Close)
	testHTTPClient = server.Client()
	t.Cleanup(func() { testHTTPClient = nil })

	report, err := ProbeDetailed(context.Background(), server.URL+"/dns-query", "health.test", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Healthy || report.HTTPStatus != http.StatusOK || report.ContentType != "application/dns-message" {
		t.Fatalf("DoH report = %+v", report)
	}
}

func TestProbeDetailedDoHFailure(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	t.Cleanup(server.Close)
	testHTTPClient = server.Client()
	t.Cleanup(func() { testHTTPClient = nil })

	report, err := ProbeDetailed(context.Background(), server.URL+"/dns-query", "health.test", nil)
	if err != nil {
		t.Fatal(err)
	}
	if report.Healthy || report.Failure == nil || report.Failure.Phase != "http" || report.Failure.Code != "http_status" {
		t.Fatalf("DoH failure report = %+v", report)
	}
}

func TestProbeReportFailureClassification(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		wantPhase string
		wantCode  string
	}{
		{name: "timeout", err: context.DeadlineExceeded, wantPhase: "dns", wantCode: "timeout"},
		{name: "certificate", err: errors.New("TLS certificate invalid"), wantPhase: "tls", wantCode: "certificate"},
		{name: "content type", err: errors.New("DoH invalid content type"), wantPhase: "http", wantCode: "content_type"},
		{name: "message id", err: errors.New("HTTP message ID mismatch"), wantPhase: "http", wantCode: "message_id"},
		{name: "status", err: errors.New("HTTP status 503"), wantPhase: "http", wantCode: "http_status"},
		{name: "rcode", err: errors.New("DNS rcode SERVFAIL"), wantPhase: "dns", wantCode: "dns_rcode"},
		{name: "resolve", err: errors.New("bootstrap resolve failed"), wantPhase: "bootstrap", wantCode: "resolution"},
		{name: "connect", err: errors.New("dial connect refused"), wantPhase: "tcp", wantCode: "network"},
		{name: "network", err: errors.New("broken pipe"), wantPhase: "dns", wantCode: "network"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := failurePhase(test.err); got != test.wantPhase {
				t.Fatalf("failurePhase() = %q, want %q", got, test.wantPhase)
			}
			if got := failureCode(test.err); got != test.wantCode {
				t.Fatalf("failureCode() = %q, want %q", got, test.wantCode)
			}
			report := ProbeReport{Healthy: true}
			report.fail(test.wantPhase, test.err)
			if report.Healthy || report.Failure == nil || !strings.Contains(report.Failure.Message, test.err.Error()) {
				t.Fatalf("fail() report = %+v", report)
			}
		})
	}
}

func TestValidateProbeResponse(t *testing.T) {
	if err := validateProbeResponse("udp://test", nil); err == nil {
		t.Fatal("nil response was accepted")
	}
	for _, rcode := range []int{dns.RcodeSuccess, dns.RcodeNameError} {
		if err := validateProbeResponse("udp://test", &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: rcode}}); err != nil {
			t.Fatalf("rcode %d rejected: %v", rcode, err)
		}
	}
	if err := validateProbeResponse("udp://test", &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeRefused}}); err == nil {
		t.Fatal("REFUSED response was accepted")
	}
	if got := millisecondsSince(time.Now().Add(-time.Millisecond)); got < 0.5 {
		t.Fatalf("millisecondsSince() = %f, want at least 0.5", got)
	}
}

func TestProbeDoTConnectFailure(t *testing.T) {
	address := deadTCPAddress(t)
	spec, err := Parse("tls://" + address)
	if err != nil {
		t.Fatal(err)
	}
	report := ProbeReport{TimingsMS: make(map[string]float64)}
	query := new(dns.Msg)
	query.SetQuestion("health.test.", dns.TypeA)
	if _, err := probeDoTDetailed(context.Background(), spec, []string{address}, query, &report); err == nil {
		t.Fatal("closed TCP endpoint did not fail")
	}
}

func deadTCPAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	return address
}

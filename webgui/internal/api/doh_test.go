package api

import (
	"bytes"
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/miekg/dns"

	"tailscale-dnsrewrite/webgui/internal/config"
	"tailscale-dnsrewrite/webgui/internal/dnsserver"
)

func newDoHTestServer(t *testing.T, token string) (*Server, []byte) {
	t.Helper()
	cfg := &config.Config{
		BaseURL:        "/",
		MaxRequestSize: 1 << 20,
		DoHEnabled:     true,
		DoHPath:        "/dns-query",
		DoHAuthToken:   token,
	}
	s := testServer(cfg)
	s.SetDNSServer(dnsserver.New(dnsserver.Config{
		NodeName:    "test-node",
		StaticHosts: map[string]net.IP{"example.test": net.ParseIP("192.0.2.25")},
	}, nil))

	query := new(dns.Msg)
	query.SetQuestion("example.test.", dns.TypeA)
	wire, err := query.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return s, wire
}

func requireDoHAnswer(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %q", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); got != "application/dns-message" {
		t.Fatalf("Content-Type = %q", got)
	}
	msg := new(dns.Msg)
	if err := msg.Unpack(rec.Body.Bytes()); err != nil {
		t.Fatalf("unpack response: %v", err)
	}
	if len(msg.Answer) != 1 {
		t.Fatalf("answers = %v", msg.Answer)
	}
	a, ok := msg.Answer[0].(*dns.A)
	if !ok || a.A.String() != "192.0.2.25" {
		t.Fatalf("answer = %v", msg.Answer[0])
	}
}

func TestDoHPrivateClientPOST(t *testing.T) {
	s, wire := newDoHTestServer(t, "")
	req := httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader(wire))
	req.RemoteAddr = "100.64.0.10:53000"
	req.Header.Set("Content-Type", "application/dns-message")
	rec := httptest.NewRecorder()
	s.SetupMux().ServeHTTP(rec, req)
	requireDoHAnswer(t, rec)
}

func TestDoHBearerTokenGET(t *testing.T) {
	s, wire := newDoHTestServer(t, "test-token")
	encoded := base64.RawURLEncoding.EncodeToString(wire)
	req := httptest.NewRequest(http.MethodGet, "/dns-query?dns="+encoded, nil)
	req.RemoteAddr = "203.0.113.10:53000"
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	s.SetupMux().ServeHTTP(rec, req)
	requireDoHAnswer(t, rec)
}

func TestDoHAccessControl(t *testing.T) {
	t.Run("public client without configured token", func(t *testing.T) {
		s, wire := newDoHTestServer(t, "")
		req := httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader(wire))
		req.RemoteAddr = "203.0.113.10:53000"
		req.Header.Set("Content-Type", "application/dns-message")
		rec := httptest.NewRecorder()
		s.SetupMux().ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
		}
	})

	t.Run("missing bearer token", func(t *testing.T) {
		s, wire := newDoHTestServer(t, "test-token")
		req := httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader(wire))
		req.RemoteAddr = "100.64.0.10:53000"
		req.Header.Set("Content-Type", "application/dns-message")
		rec := httptest.NewRecorder()
		s.SetupMux().ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
		}
		if got := rec.Header().Get("WWW-Authenticate"); got != "Bearer" {
			t.Fatalf("WWW-Authenticate = %q", got)
		}
	})
}

func TestDoHRequestValidation(t *testing.T) {
	s, _ := newDoHTestServer(t, "test-token")

	tests := []struct {
		name        string
		method      string
		body        string
		contentType string
		want        int
	}{
		{name: "method", method: http.MethodPut, want: http.StatusMethodNotAllowed},
		{name: "content type", method: http.MethodPost, body: "bad", contentType: "text/plain", want: http.StatusUnsupportedMediaType},
		{name: "malformed message", method: http.MethodPost, body: "bad", contentType: "application/dns-message", want: http.StatusBadRequest},
		{name: "oversized message", method: http.MethodPost, body: strings.Repeat("x", 65537), contentType: "application/dns-message", want: http.StatusRequestEntityTooLarge},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/dns-query", strings.NewReader(tt.body))
			req.RemoteAddr = "203.0.113.10:53000"
			req.Header.Set("Authorization", "Bearer test-token")
			if tt.contentType != "" {
				req.Header.Set("Content-Type", tt.contentType)
			}
			rec := httptest.NewRecorder()
			s.SetupMux().ServeHTTP(rec, req)
			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d, body = %q", rec.Code, tt.want, rec.Body.String())
			}
			if tt.want == http.StatusMethodNotAllowed && rec.Header().Get("Allow") != "GET, POST" {
				t.Fatalf("Allow = %q", rec.Header().Get("Allow"))
			}
		})
	}
}

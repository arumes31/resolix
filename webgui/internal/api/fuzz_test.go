package api

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/miekg/dns"

	"tailscale-dnsrewrite/webgui/internal/config"
	"tailscale-dnsrewrite/webgui/internal/dnsserver"
)

func FuzzDoHGETPayload(f *testing.F) {
	query := new(dns.Msg)
	query.SetQuestion("example.test.", dns.TypeAAAA)
	wire, _ := query.Pack()
	f.Add(base64.RawURLEncoding.EncodeToString(wire))
	server := testServer(&config.Config{
		BaseURL:        "/",
		MaxRequestSize: 1 << 20,
		DoHEnabled:     true,
		DoHPath:        "/dns-query",
		DoHAuthToken:   "fuzz-token",
	})
	server.SetDNSServer(dnsserver.New(dnsserver.Config{}, nil))
	handler := server.SetupMux()
	f.Fuzz(func(_ *testing.T, encoded string) {
		req := httptest.NewRequest(http.MethodGet, "/dns-query?dns="+url.QueryEscape(encoded), nil)
		req.Header.Set("Authorization", "Bearer fuzz-token")
		handler.ServeHTTP(httptest.NewRecorder(), req)
	})
}

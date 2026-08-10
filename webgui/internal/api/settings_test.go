package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/arumes31/resolix/webgui/internal/config"
	"github.com/arumes31/resolix/webgui/internal/dnsserver"
	"github.com/arumes31/resolix/webgui/internal/filter"
	"github.com/arumes31/resolix/webgui/internal/policy"
)

func TestCheckCSRFRequiresMatchingCookieAndHeader(t *testing.T) {
	server := testServer(&config.Config{WebUsername: "admin", WebPassword: "password"})
	req := httptest.NewRequest(http.MethodPost, "/api/cache/clear", nil)
	req.AddCookie(&http.Cookie{
		Name: csrfCookieName, Value: "token", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
	req.Header.Set("X-CSRF-Token", "token")
	if rec := httptest.NewRecorder(); !server.checkCSRF(rec, req) {
		t.Fatalf("matching CSRF token rejected: status=%d body=%q", rec.Code, rec.Body.String())
	}

	req.Header.Set("X-CSRF-Token", "wrong")
	rec := httptest.NewRecorder()
	if server.checkCSRF(rec, req) || rec.Code != http.StatusForbidden {
		t.Fatalf("mismatched CSRF token result=%d", rec.Code)
	}
}

func TestQuerylogActionRejectsUnsafeDomainCharacters(t *testing.T) {
	server := testServer(&config.Config{HistoryDir: t.TempDir()})
	server.SetFilter(filter.New())
	for _, domain := range []string{"bad_domain.test", "bad^domain.test", "-" + strings.Repeat("a", 64) + ".test"} {
		t.Run(domain, func(t *testing.T) {
			body := bytes.NewBufferString(`{"domain":` + strconv.Quote(domain) + `}`)
			req := httptest.NewRequest(http.MethodPost, "/api/querylog/block", body)
			rec := httptest.NewRecorder()
			server.handleQuerylogAction(rec, req, true)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%q", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestCacheClearEndpoint(t *testing.T) {
	s := testServer(&config.Config{BaseURL: "/", MaxRequestSize: 1 << 20})
	s.SetDNSServer(dnsserver.New(dnsserver.Config{}, nil))
	mux := s.SetupMux()

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/cache/clear", nil))
	if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != http.MethodPost {
		t.Fatalf("GET: status=%d Allow=%q", rec.Code, rec.Header().Get("Allow"))
	}

	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/cache/clear", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("POST: status=%d body=%q", rec.Code, rec.Body.String())
	}
	var body struct {
		Status  string `json:"status"`
		Cleared int    `json:"cleared"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Status != "ok" || body.Cleared != 0 {
		t.Fatalf("response = %+v", body)
	}
}

func TestServicesEndpoint(t *testing.T) {
	s := testServer(&config.Config{
		BaseURL:         "/",
		MaxRequestSize:  1 << 20,
		BlockedServices: "facebook, tiktok",
	})
	s.SetDNSServer(dnsserver.New(dnsserver.Config{}, nil))
	rec := httptest.NewRecorder()
	s.SetupMux().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/services", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q", rec.Code, rec.Body.String())
	}
	var body struct {
		Services []struct {
			ID      string `json:"id"`
			Enabled bool   `json:"enabled"`
		} `json:"services"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if want := len(policy.ServiceIDs()); len(body.Services) != want {
		t.Fatalf("service count = %d, want %d", len(body.Services), want)
	}
	seenEnabled := map[string]bool{}
	for _, service := range body.Services {
		if service.Enabled {
			seenEnabled[service.ID] = true
		}
	}
	if !seenEnabled["facebook"] || !seenEnabled["tiktok"] || len(seenEnabled) != 2 {
		t.Fatalf("enabled services = %v", seenEnabled)
	}
}

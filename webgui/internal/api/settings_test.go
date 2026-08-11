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

func TestFilteringUpdateEndpoint(t *testing.T) {
	controller := testServer(&config.Config{
		Mode:        config.ModeController,
		WebUsername: "admin",
		WebPassword: "password",
	})
	controller.SetFilter(filter.New())

	recorder := httptest.NewRecorder()
	controller.handleFilteringUpdate(recorder, httptest.NewRequest(http.MethodGet, "/api/filtering/update", nil))
	if recorder.Code != http.StatusMethodNotAllowed || recorder.Header().Get("Allow") != http.MethodPost {
		t.Fatalf("GET: status=%d Allow=%q", recorder.Code, recorder.Header().Get("Allow"))
	}

	recorder = httptest.NewRecorder()
	controller.handleFilteringUpdate(recorder, httptest.NewRequest(http.MethodPost, "/api/filtering/update", nil))
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF: status=%d body=%q", recorder.Code, recorder.Body.String())
	}

	request := httptest.NewRequest(http.MethodPost, "/api/filtering/update", nil)
	request.AddCookie(&http.Cookie{
		Name: csrfCookieName, Value: "token", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
	request.Header.Set("X-CSRF-Token", "token")
	recorder = httptest.NewRecorder()
	controller.handleFilteringUpdate(recorder, request)
	if recorder.Code != http.StatusAccepted || !strings.Contains(recorder.Body.String(), `"status":"scheduled"`) {
		t.Fatalf("controller: status=%d body=%q", recorder.Code, recorder.Body.String())
	}

	agent := testServer(&config.Config{Mode: config.ModeAgent})
	agent.SetFilter(filter.New())
	recorder = httptest.NewRecorder()
	agent.handleFilteringUpdate(recorder, httptest.NewRequest(http.MethodPost, "/api/filtering/update", nil))
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("agent: status=%d body=%q", recorder.Code, recorder.Body.String())
	}
}

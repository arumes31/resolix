package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
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

func TestCacheStatusEndpoint(t *testing.T) {
	s := testServer(&config.Config{BaseURL: "/", MaxRequestSize: 1 << 20})
	s.SetDNSServer(dnsserver.New(dnsserver.Config{CacheSize: 17}, nil))
	mux := s.SetupMux()

	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/cache/status", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET status=%d body=%q", recorder.Code, recorder.Body.String())
	}
	var response struct {
		Stats dnsserver.CacheStats `json:"stats"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Stats.Capacity != 17 || response.Stats.Entries != 0 {
		t.Fatalf("cache status = %+v", response.Stats)
	}

	recorder = httptest.NewRecorder()
	mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/cache/status?entries=invalid", nil))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("invalid entries status=%d body=%q", recorder.Code, recorder.Body.String())
	}

	recorder = httptest.NewRecorder()
	mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/api/cache/status", nil))
	if recorder.Code != http.StatusMethodNotAllowed || recorder.Header().Get("Allow") != http.MethodGet {
		t.Fatalf("POST status=%d Allow=%q", recorder.Code, recorder.Header().Get("Allow"))
	}
}

func TestFilteringUpdateEndpoint(t *testing.T) {
	controller := testServer(&config.Config{
		Mode:        config.ModeController,
		WebUsername: "admin",
		WebPassword: "password",
	})
	controller.SetFilter(filter.New())
	subscriptions, err := filter.LoadSubscriptionStore(
		filepath.Join(t.TempDir(), "filter-subscriptions.json"),
		[]filter.Subscription{
			{Name: "test", URL: "https://example.com/list.txt", Enabled: true},
			{Name: "other", URL: "https://other.example/list.txt", Enabled: true},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	controller.SetSubscriptionStore(subscriptions)
	before, err := controller.currentConfigSnapshot()
	if err != nil {
		t.Fatal(err)
	}

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
	after, err := controller.currentConfigSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if before.Revision == after.Revision || subscriptions.List()[0].RefreshGeneration == "" {
		t.Fatalf("manual refresh did not change synchronized configuration revision: before=%q after=%q", before.Revision, after.Revision)
	}
	previous := subscriptions.List()
	targetedRequest := httptest.NewRequest(
		http.MethodPost,
		"/api/filtering/update?id="+url.QueryEscape(previous[0].ID),
		nil,
	)
	targetedRequest.AddCookie(&http.Cookie{
		Name: csrfCookieName, Value: "token", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
	targetedRequest.Header.Set("X-CSRF-Token", "token")
	recorder = httptest.NewRecorder()
	controller.handleFilteringUpdate(recorder, targetedRequest)
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("targeted refresh: status=%d body=%q", recorder.Code, recorder.Body.String())
	}
	refreshed := subscriptions.List()
	if refreshed[0].RefreshGeneration == previous[0].RefreshGeneration ||
		refreshed[1].RefreshGeneration != previous[1].RefreshGeneration {
		t.Fatalf("targeted refresh generations: before=%+v after=%+v", previous, refreshed)
	}

	agent := testServer(&config.Config{Mode: config.ModeAgent})
	agent.SetFilter(filter.New())
	recorder = httptest.NewRecorder()
	agent.handleFilteringUpdate(recorder, httptest.NewRequest(http.MethodPost, "/api/filtering/update", nil))
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("agent: status=%d body=%q", recorder.Code, recorder.Body.String())
	}
}

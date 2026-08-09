package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"tailscale-dnsrewrite/webgui/internal/config"
	"tailscale-dnsrewrite/webgui/internal/dnsserver"
)

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
	if len(body.Services) != 14 {
		t.Fatalf("service count = %d, want 14", len(body.Services))
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

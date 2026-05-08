package main

import (
	"encoding/json"
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"tailscale-dnsrewrite/webgui/internal/api"
	"tailscale-dnsrewrite/webgui/internal/config"
	"tailscale-dnsrewrite/webgui/internal/models"
	"tailscale-dnsrewrite/webgui/internal/parser"
	"tailscale-dnsrewrite/webgui/internal/storage"
)

func setupTest() (*config.Config, *storage.Store, *parser.Parser, *api.Server) {
	cfg := config.LoadConfig()
	cfg.MaxEvents = 100
	store := storage.NewStore(cfg)
	prs := parser.NewParser(store)
	tmpl := template.Must(template.New("test").Parse("{{range .Events}}{{.Domain}}{{end}}"))
	srv := api.NewServer(cfg, store, prs, tmpl)
	return cfg, store, prs, srv
}

func TestParseLogBytes(t *testing.T) {
	_, store, prs, _ := setupTest()
	node := "test-node"

	// 1. Test Query
	line1 := []byte("dnsmasq[123]: query[A] google.com from 192.168.1.1")
	prs.ParseLogBytes(line1, node)

	events := store.GetRecentEvents(0)
	if len(events) != 1 {
		t.Errorf("Expected 1 event, got %d", len(events))
	}
	if events[0].Domain != "google.com" || events[0].ClientIP != "192.168.1.1" {
		t.Errorf("Incorrect query parsing: %+v", events[0])
	}

	// 2. Test Forwarded
	line2 := []byte("dnsmasq[123]: forwarded google.com to 8.8.8.8")
	prs.ParseLogBytes(line2, node)

	if store.GetUpstream(node, "google.com") != "8.8.8.8" {
		t.Errorf("Expected upstream 8.8.8.8, got %s", store.GetUpstream(node, "google.com"))
	}

	// 3. Test Reply (Latency)
	line3 := []byte("dnsmasq[123]: reply google.com is 1.2.3.4")
	prs.ParseLogBytes(line3, node)

	events = store.GetRecentEvents(0)
	if events[0].Upstream != "8.8.8.8" {
		t.Errorf("Expected upstream 8.8.8.8 in event, got %s", events[0].Upstream)
	}
	if events[0].Latency < 0 {
		t.Error("Latency should be >= 0")
	}
}

func TestApiEvents(t *testing.T) {
	cfg, store, _, srv := setupTest()
	now := time.Now().Unix()

	store.AddEvent(models.QueryEvent{UnixTime: now - 10, Domain: "old.com", Node: cfg.NodeName})
	store.AddEvent(models.QueryEvent{UnixTime: now, Domain: "new.com", Node: cfg.NodeName})

	handler := srv.SetupMux()

	// 1. Test all events
	req := httptest.NewRequest("GET", "/api/events", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	var resp []models.QueryEvent
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to unmarshal events: %v", err)
	}
	if len(resp) != 2 {
		t.Errorf("Expected 2 events, got %d", len(resp))
	}
}

func TestApiStats(t *testing.T) {
	cfg, _, prs, srv := setupTest()

	prs.ParseLogBytes([]byte("query[A] domain1.com from 1.1.1.1"), cfg.NodeName)
	prs.ParseLogBytes([]byte("query[A] domain1.com from 1.1.1.1"), cfg.NodeName)
	prs.ParseLogBytes([]byte("query[A] domain2.com from 2.2.2.2"), "node2")

	handler := srv.SetupMux()
	req := httptest.NewRequest("GET", "/api/stats", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	var resp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to unmarshal stats: %v", err)
	}

	if resp["total"].(float64) != 3 {
		t.Errorf("Expected total 3, got %v", resp["total"])
	}
}

func TestRootHandler(t *testing.T) {
	cfg, _, prs, srv := setupTest()
	prs.ParseLogBytes([]byte("dnsmasq[1]: query[A] root.com from 1.1.1.1"), cfg.NodeName)

	handler := srv.SetupMux()
	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if !strings.Contains(rr.Body.String(), "root.com") {
		t.Error("Dashboard did not contain injected event")
	}
}

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"tailscale-dnsrewrite/webgui/internal/api"
	"tailscale-dnsrewrite/webgui/internal/config"
	"tailscale-dnsrewrite/webgui/internal/forwarder"
	"tailscale-dnsrewrite/webgui/internal/models"
	"tailscale-dnsrewrite/webgui/internal/parser"
	"tailscale-dnsrewrite/webgui/internal/storage"
)

func setupTest() (*config.Config, *storage.Store, *parser.Parser, *api.Server) {
	cfg := config.LoadConfig()
	cfg.MaxEvents = 1000
	tmp, err := os.MkdirTemp("", "history-test")
	if err != nil {
		panic(fmt.Sprintf("failed to create temp dir: %v", err))
	}
	cfg.HistoryDir = tmp
	store := storage.NewStore(cfg)
	store.Init()
	prs := parser.NewParser(store, false)
	tmpl := template.Must(template.New("test").Parse("{{range .Events}}{{.Domain}}{{end}}"))
	srv := api.NewServer(cfg, store, prs, tmpl)
	return cfg, store, prs, srv
}

func TestParseLogBytes(t *testing.T) {
	_, store, prs, _ := setupTest()
	defer func() { _ = os.RemoveAll(store.GetConfig().HistoryDir) }()
	node := "test-node"

	// 1. Test Query
	line1 := []byte("Jan 02 15:04:05 dnsmasq[123]: query[A] google.com from 192.168.1.1")
	prs.ParseLogBytes(line1, node)

	events := store.GetRecentEvents(0)
	if len(events) != 1 {
		t.Errorf("Expected 1 event, got %d", len(events))
	}
	if events[0].Domain != "google.com" || events[0].ClientIP != "192.168.1.1" {
		t.Errorf("Incorrect query parsing: %+v", events[0])
	}

	// 2. Test Forwarded
	line2 := []byte("Jan 02 15:04:05 dnsmasq[123]: forwarded google.com to 8.8.8.8")
	prs.ParseLogBytes(line2, node)

	// 3. Test Reply (Latency)
	line3 := []byte("Jan 02 15:04:05 dnsmasq[123]: reply google.com is 1.2.3.4")
	prs.ParseLogBytes(line3, node)

	events = store.GetRecentEvents(0)
	if events[0].Upstream != "8.8.8.8" {
		t.Errorf("Expected upstream 8.8.8.8 in event, got %s", events[0].Upstream)
	}
	if events[0].Latency.Valid && events[0].Latency.Float64 < 0 {
		t.Error("Latency should be >= 0")
	}

	// 4. Test Feature #200: Internal Override Recognition
	line4 := []byte("Jan 02 15:04:05 dnsmasq[123]: query[A] private.local from 100.64.1.2")
	prs.ParseLogBytes(line4, node)
	line5 := []byte("Jan 02 15:04:05 dnsmasq[123]: forwarded private.local to 127.0.0.1#5353")
	prs.ParseLogBytes(line5, node)
	line6 := []byte("Jan 02 15:04:05 dnsmasq[123]: reply private.local is 10.0.0.5")
	prs.ParseLogBytes(line6, node)

	events = store.GetRecentEvents(0)
	if events[0].Domain != "private.local" {
		t.Errorf("Expected domain private.local, got %s", events[0].Domain)
	}
	if events[0].Upstream != "Local Override" {
		t.Errorf("Expected 'Local Override' for 127.0.0.1#5353, got %s", events[0].Upstream)
	}
}

func TestApiIngest(t *testing.T) {
	_, store, _, srv := setupTest()
	defer func() { _ = os.RemoveAll(store.GetConfig().HistoryDir) }()

	payload := map[string]interface{}{
		"node": "slave-1",
		"batch": []string{
			"Jan 02 15:04:05 dnsmasq[1]: query[A] d1.com from 1.1.1.1",
			"Jan 02 15:04:05 dnsmasq[1]: query[A] d2.com from 2.2.2.2",
		},
	}
	data, _ := json.Marshal(payload)

	req := httptest.NewRequest("POST", "/api/ingest", bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	srv.SetupMux().ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Errorf("Expected status 204, got %d", rr.Code)
	}

	events := store.GetRecentEvents(0)
	if len(events) != 2 {
		t.Errorf("Expected 2 events, got %d", len(events))
	}
}

func TestApiEvents(t *testing.T) {
	cfg, store, _, srv := setupTest()
	defer func() { _ = os.RemoveAll(store.GetConfig().HistoryDir) }()
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
	cfg, store, prs, srv := setupTest()
	defer func() { _ = os.RemoveAll(store.GetConfig().HistoryDir) }()

	nowStr := time.Now().Format("Jan 02 15:04:05")
	prs.ParseLogBytes([]byte(nowStr+" dnsmasq[1]: query[A] domain1.com from 1.1.1.1"), cfg.NodeName)
	prs.ParseLogBytes([]byte(nowStr+" dnsmasq[1]: query[A] domain1.com from 1.1.1.1"), cfg.NodeName)
	prs.ParseLogBytes([]byte(nowStr+" dnsmasq[1]: query[A] domain2.com from 2.2.2.2"), "node2")

	store.ArchiveStep(time.Now())

	handler := srv.SetupMux()
	req := httptest.NewRequest("GET", "/api/stats", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	var resp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to unmarshal stats: %v", err)
	}

	val, ok := resp["total"].(float64)
	if !ok {
		t.Fatalf("Expected float64 for total, got %T", resp["total"])
	}
	if val != 3 {
		t.Errorf("Expected total 3, got %v", val)
	}
}

func TestRootHandler(t *testing.T) {
	cfg, store, prs, srv := setupTest()
	defer func() { _ = os.RemoveAll(store.GetConfig().HistoryDir) }()
	prs.ParseLogBytes([]byte("Jan 02 15:04:05 dnsmasq[1]: query[A] root.com from 1.1.1.1"), cfg.NodeName)

	handler := srv.SetupMux()
	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if !strings.Contains(rr.Body.String(), "root.com") {
		t.Error("Dashboard did not contain injected event")
	}
}

func TestConcurrency(t *testing.T) {
	_, store, prs, srv := setupTest()
	defer func() { _ = os.RemoveAll(store.GetConfig().HistoryDir) }()
	handler := srv.SetupMux()

	const workers = 10
	const iterations = 50

	done := make(chan bool)

	// Concurrent Ingestors
	for i := 0; i < workers; i++ {
		go func(id int) {
			for j := 0; j < iterations; j++ {
				line := []byte(fmt.Sprintf("Jan 02 15:04:05 dnsmasq[1]: query[A] domain-%d-%d.com from 1.1.1.1", id, j))
				prs.ParseLogBytes(line, "node-1")

				payload := map[string]interface{}{
					"node": "slave-1",
					"batch": []string{
						fmt.Sprintf("Jan 02 15:04:05 dnsmasq[1]: query[A] batch-%d-%d.com from 2.2.2.2", id, j),
					},
				}
				data, _ := json.Marshal(payload)
				req := httptest.NewRequest("POST", "/api/ingest", bytes.NewBuffer(data))
				rr := httptest.NewRecorder()
				handler.ServeHTTP(rr, req)
			}
			done <- true
		}(i)
	}

	for i := 0; i < workers; i++ {
		<-done
	}

	events := store.GetRecentEvents(0)
	expected := workers * iterations * 2
	if len(events) < expected {
		t.Errorf("Expected at least %d events, got %d", expected, len(events))
	}
}

func TestApiIngestAuth(t *testing.T) {
	cfg, store, _, srv := setupTest()
	defer func() { _ = os.RemoveAll(store.GetConfig().HistoryDir) }()

	cfg.IngestSecret = "secret123"
	handler := srv.SetupMux()

	payload := map[string]interface{}{
		"node":  "slave-1",
		"batch": []string{"Jan 02 15:04:05 dnsmasq[1]: query[A] d1.com from 1.1.1.1"},
	}
	data, _ := json.Marshal(payload)

	// 1. Unauthorized
	req := httptest.NewRequest("POST", "/api/ingest", bytes.NewBuffer(data))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", rr.Code)
	}

	// 2. Authorized
	req = httptest.NewRequest("POST", "/api/ingest", bytes.NewBuffer(data))
	req.Header.Set("Authorization", "Bearer secret123")
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Errorf("Expected status 204, got %d", rr.Code)
	}
}

func TestParseLogMalformed(t *testing.T) {
	_, store, prs, _ := setupTest()
	defer func() { _ = os.RemoveAll(store.GetConfig().HistoryDir) }()

	// Test short query[
	line := []byte("Jan 02 15:04:05 dnsmasq[1]: query[")
	ev := prs.ParseLogBytes(line, "node")
	if ev != nil {
		t.Error("Expected nil for malformed query[")
	}

	// Test exactly query[A] (length 8)
	line2 := []byte("Jan 02 15:04:05 dnsmasq[1]: query[A] ok.com from 1.1.1.1")
	ev2 := prs.ParseLogBytes(line2, "node")
	if ev2 == nil || ev2.Type != "A" {
		t.Errorf("Expected successful parse for query[A], got %+v", ev2)
	}
}

func TestArchiveStep(t *testing.T) {
	cfg, store, _, _ := setupTest()
	defer func() { _ = os.RemoveAll(store.GetConfig().HistoryDir) }()

	now := time.Now().Unix()
	// Add some old events
	store.AddEvent(models.QueryEvent{UnixTime: now - 7200, Domain: "old1.com", Node: cfg.NodeName})
	store.AddEvent(models.QueryEvent{UnixTime: now - 3601, Domain: "old2.com", Node: cfg.NodeName})
	// Add a new event
	store.AddEvent(models.QueryEvent{UnixTime: now, Domain: "new.com", Node: cfg.NodeName})

	archived := store.ArchiveStep(time.Now())
	if archived != 3 {
		t.Errorf("Expected 3 events archived, got %d", archived)
	}

	// Verify data exists in sqlite via stats
	stats := store.GetStats()
	if total, ok := stats["total"].(int64); !ok || total < 1 {
		t.Errorf("Expected > 0 total events in SQLite after archive, got %v", total)
	}
}

func TestForwarder_NoPanic(t *testing.T) {
	_ = t // Ignore unused param warning
	cfg := &config.Config{Mode: "slave", MasterURL: "http://localhost:12345", NodeName: "slave-1"}
	fwd := forwarder.NewForwarder(cfg)

	// Test Enqueue adds to backlog
	fwd.Enqueue("line1")
	fwd.Enqueue("line2")

	// Verify backlog indirectly or via reflection if needed,
	// but let's just ensure no panic and basic functionality.
	// We can't easily test the Start() loop without a mock server here.
}

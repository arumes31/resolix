package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func resetState() {
	eventsMu.Lock()
	events = make([]QueryEvent, maxEvents)
	head = 0
	count = 0
	eventsMu.Unlock()

	pendingMu.Lock()
	pendingQueries = make(map[string]map[string]time.Time)
	pendingUpstreams = make(map[string]map[string]string)
	pendingMu.Unlock()

	statsMu.Lock()
	hourlyStats = make(map[int64]int)
	statsMu.Unlock()

	windowDomainCounts = make(map[string]int)
	windowClientCounts = make(map[string]int)
}

func TestParseLogBytes(t *testing.T) {
	resetState()
	node := "test-node"

	// 1. Test Query
	line1 := []byte("dnsmasq[123]: query[A] google.com from 192.168.1.1")
	parseLogBytes(line1, node)

	eventsMu.RLock()
	if count != 1 {
		t.Errorf("Expected 1 event, got %d", count)
	}
	if events[0].Domain != "google.com" || events[0].ClientIP != "192.168.1.1" {
		t.Errorf("Incorrect query parsing: %+v", events[0])
	}
	eventsMu.RUnlock()

	// 2. Test Forwarded
	line2 := []byte("dnsmasq[123]: forwarded google.com to 8.8.8.8")
	parseLogBytes(line2, node)
	
	pendingMu.Lock()
	if pendingUpstreams[node]["google.com"] != "8.8.8.8" {
		t.Errorf("Expected upstream 8.8.8.8, got %s", pendingUpstreams[node]["google.com"])
	}
	pendingMu.Unlock()

	// 3. Test Reply (Latency)
	line3 := []byte("dnsmasq[123]: reply google.com is 1.2.3.4")
	parseLogBytes(line3, node)

	eventsMu.RLock()
	if events[0].Upstream != "8.8.8.8" {
		t.Errorf("Expected upstream 8.8.8.8 in event, got %s", events[0].Upstream)
	}
	if events[0].Latency < 0 {
		t.Error("Latency should be >= 0")
	}
	eventsMu.RUnlock()

	// 4. Test Cached
	resetState()
	parseLogBytes([]byte("query[A] cached.com from 1.1.1.1"), node)
	parseLogBytes([]byte("cached cached.com is 1.1.1.1"), node)
	eventsMu.RLock()
	if events[0].Upstream != "System Cache" {
		t.Errorf("Expected System Cache, got %s", events[0].Upstream)
	}
	eventsMu.RUnlock()

	// 5. Test Config
	resetState()
	parseLogBytes([]byte("query[A] config.com from 1.1.1.1"), node)
	parseLogBytes([]byte("config config.com is 1.1.1.1"), node)
	eventsMu.RLock()
	if events[0].Upstream != "Local Override" {
		t.Errorf("Expected Local Override, got %s", events[0].Upstream)
	}
	eventsMu.RUnlock()
}

func TestIncrementalStats(t *testing.T) {
	resetState()
	// Reduce maxEvents for testing rotation
	oldMax := maxEvents
	maxEvents = 2
	events = make([]QueryEvent, maxEvents)
	defer func() { 
		maxEvents = oldMax 
		events = make([]QueryEvent, maxEvents)
	}()

	parseLogBytes([]byte("query[A] a.com from 1.1.1.1"), "n1")
	parseLogBytes([]byte("query[A] b.com from 2.2.2.2"), "n1")
	
	if windowDomainCounts["a.com"] != 1 || windowDomainCounts["b.com"] != 1 {
		t.Errorf("Initial counts wrong: %+v", windowDomainCounts)
	}

	// Overwrite a.com
	parseLogBytes([]byte("query[A] c.com from 3.3.3.3"), "n1")
	
	if windowDomainCounts["a.com"] != 0 {
		t.Errorf("Expected a.com count to be 0 after overwrite, got %d", windowDomainCounts["a.com"])
	}
	if windowDomainCounts["c.com"] != 1 {
		t.Errorf("Expected c.com count to be 1, got %d", windowDomainCounts["c.com"])
	}
}

func TestApiIngest(t *testing.T) {
	resetState()
	handler := setupMux()

	payload := map[string]interface{}{
		"node": "slave-1",
		"batch": []string{
			"query[A] d1.com from 1.1.1.1",
			"query[A] d2.com from 2.2.2.2",
		},
	}
	data, _ := json.Marshal(payload)
	
	req := httptest.NewRequest("POST", "/api/ingest", bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Errorf("Expected status 204, got %d", rr.Code)
	}

	if count != 2 {
		t.Errorf("Expected 2 events, got %d", count)
	}
}

func TestApiEvents(t *testing.T) {
	resetState()
	handler := setupMux()
	now := time.Now().Unix()

	// Inject events directly
	eventsMu.Lock()
	events[0] = QueryEvent{UnixTime: now - 10, Domain: "old.com", Node: "n1"}
	events[1] = QueryEvent{UnixTime: now, Domain: "new.com", Node: "n1"}
	head = 2
	count = 2
	eventsMu.Unlock()

	// 1. Test all events
	req := httptest.NewRequest("GET", "/api/events", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	var resp []QueryEvent
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to unmarshal events: %v", err)
	}
	if len(resp) != 2 {
		t.Errorf("Expected 2 events, got %d", len(resp))
	}

	// 2. Test since parameter
	req = httptest.NewRequest("GET", fmt.Sprintf("/api/events?since=%d", now-5), nil)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to unmarshal events: %v", err)
	}
	if len(resp) != 1 || resp[0].Domain != "new.com" {
		t.Errorf("Expected 1 new event, got %d", len(resp))
	}
}

func TestApiStats(t *testing.T) {
	resetState()
	handler := setupMux()
	now := time.Now().Unix()

	// Inject some logs to populate window counts and hourly stats
	parseLogBytes([]byte("query[A] domain1.com from 1.1.1.1"), "node1")
	parseLogBytes([]byte("query[A] domain1.com from 1.1.1.1"), "node1")
	parseLogBytes([]byte("query[A] domain2.com from 2.2.2.2"), "node2")

	// Manually inject some hourly stats
	statsMu.Lock()
	hourlyStats[now/3600] = 3
	hourlyStats[now/3600-1] = 5
	statsMu.Unlock()

	req := httptest.NewRequest("GET", "/api/stats", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to unmarshal stats: %v", err)
	}

	if resp["total"].(float64) != 3 {
		t.Errorf("Expected total 3, got %v", resp["total"])
	}

	topDomains := resp["top_domains"].([]interface{})
	if len(topDomains) == 0 || topDomains[0].(map[string]interface{})["key"] != "domain1.com" {
		t.Errorf("Top domains incorrect: %+v", topDomains)
	}

	nodes := resp["nodes"].(map[string]interface{})
	if nodes["node1"].(map[string]interface{})["rph"].(float64) != 2 {
		t.Errorf("Node1 RPH incorrect: %v", nodes["node1"])
	}

	if resp["rpd"].(float64) != 8 { // 3 + 5
		t.Errorf("Expected RPD 8, got %v", resp["rpd"])
	}
}

func TestApiSimulate(t *testing.T) {
	resetState()
	handler := setupMux()

	// Testing with a real domain (might fail if no internet, but usually google.com works)
	req := httptest.NewRequest("GET", "/api/simulate?domain=google.com", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to unmarshal simulate response: %v", err)
	}
	if resp["status"] != "success" {
		t.Errorf("Expected success, got %v", resp["status"])
	}

	// Test missing domain
	req = httptest.NewRequest("GET", "/api/simulate", nil)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", rr.Code)
	}
}

func TestGzipMiddleware(t *testing.T) {
	resetState()
	handler := setupMux()

	req := httptest.NewRequest("GET", "/api/events", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Header().Get("Content-Encoding") != "gzip" {
		t.Error("Expected Content-Encoding: gzip")
	}
}

func TestPendingCleanup(t *testing.T) {
	resetState()
	node := "test-node"
	
	pendingMu.Lock()
	pendingQueries[node] = make(map[string]time.Time)
	// Add one fresh and one stale query
	pendingQueries[node]["fresh.com"] = time.Now()
	pendingQueries[node]["stale.com"] = time.Now().Add(-20 * time.Second)
	pendingUpstreams[node] = map[string]string{
		"fresh.com": "1.1.1.1",
		"stale.com": "2.2.2.2",
	}
	pendingMu.Unlock()

	// Logic from startPendingCleanup
	pendingMu.Lock()
	now := time.Now()
	for node, queries := range pendingQueries {
		for dom, start := range queries {
			if now.Sub(start) > 10*time.Second {
				delete(queries, dom)
				delete(pendingUpstreams[node], dom)
			}
		}
		if len(queries) == 0 {
			delete(pendingQueries, node)
			delete(pendingUpstreams, node)
		}
	}
	pendingMu.Unlock()

	pendingMu.Lock()
	if _, ok := pendingQueries[node]["fresh.com"]; !ok {
		t.Error("Fresh query was incorrectly cleaned up")
	}
	if _, ok := pendingQueries[node]["stale.com"]; ok {
		t.Error("Stale query was not cleaned up")
	}
	pendingMu.Unlock()
}

func TestConcurrency(t *testing.T) {
	resetState()
	handler := setupMux()
	
	const workers = 10
	const iterations = 100
	
	done := make(chan bool)
	
	// Concurrent Ingestors
	for i := 0; i < workers; i++ {
		go func(id int) {
			for j := 0; j < iterations; j++ {
				line := []byte(fmt.Sprintf("query[A] domain-%d-%d.com from 1.1.1.1", id, j))
				parseLogBytes(line, "node-1")
				
				payload := map[string]interface{}{
					"node": "slave-1",
					"batch": []string{
						fmt.Sprintf("query[A] batch-%d-%d.com from 2.2.2.2", id, j),
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
	
	// Concurrent Readers
	for i := 0; i < workers; i++ {
		go func() {
			for j := 0; j < iterations; j++ {
				req := httptest.NewRequest("GET", "/api/stats", nil)
				rr := httptest.NewRecorder()
				handler.ServeHTTP(rr, req)
				
				req2 := httptest.NewRequest("GET", "/api/events", nil)
				rr2 := httptest.NewRecorder()
				handler.ServeHTTP(rr2, req2)
				
				time.Sleep(1 * time.Millisecond)
			}
			done <- true
		}()
	}
	
	for i := 0; i < workers*2; i++ {
		<-done
	}
	
	if count > maxEvents {
		t.Errorf("Count %d exceeds maxEvents %d", count, maxEvents)
	}
}

func TestSendBatch(t *testing.T) {
	// Mock Master Server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("Expected POST request, got %s", r.Method)
		}
		if r.URL.Path != "/api/ingest" {
			t.Errorf("Expected path /api/ingest, got %s", r.URL.Path)
		}
		
		var payload struct {
			Node  string   `json:"node"`
			Batch []string `json:"batch"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("Failed to decode payload: %v", err)
		}
		
		if payload.Node != "test-node" {
			t.Errorf("Expected node test-node, got %s", payload.Node)
		}
		if len(payload.Batch) != 2 || payload.Batch[0] != "line1" {
			t.Errorf("Incorrect batch content: %v", payload.Batch)
		}
		
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()

	client := ts.Client()
	err := sendBatch(client, "test-node", ts.URL, []string{"line1", "line2"})
	
	if err != nil {
		t.Errorf("sendBatch failed: %v", err)
	}
	
	// Test error response
	ts2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts2.Close()
	
	err = sendBatch(ts2.Client(), "test-node", ts2.URL, []string{"line1"})
	if err == nil {
		t.Error("Expected error from sendBatch for 500 status, got nil")
	}
}

func TestHistoryArchiverLogic(t *testing.T) {
	tempDir, _ := os.MkdirTemp("", "history-test")
	defer os.RemoveAll(tempDir)
	
	oldHistoryDir := historyDir
	historyDir = tempDir
	defer func() { historyDir = oldHistoryDir }()

	// Mock an event to archive
	now := time.Now()
	e := QueryEvent{
		UnixTime: now.Add(-2 * time.Hour).Unix(),
		Domain:   "archive.com",
		Node:     "n1",
	}
	
	eventsMu.Lock()
	events[0] = e
	head = 1
	count = 1
	eventsMu.Unlock()
	
	lastArchivedTime = now.Add(-3 * time.Hour).Unix()
	
	// Manually trigger what's inside the ticker
	cutoff := now.Add(-1 * time.Hour).Unix()
	var toArchive []QueryEvent
	eventsMu.RLock()
	for i := 0; i < count; i++ {
		idx := (head - 1 - i + maxEvents) % maxEvents
		if events[idx].UnixTime > lastArchivedTime && events[idx].UnixTime <= cutoff {
			toArchive = append(toArchive, events[idx])
		}
	}
	eventsMu.RUnlock()

	if len(toArchive) != 1 {
		t.Fatalf("Expected 1 event to archive, got %d", len(toArchive))
	}
	
	dateStr := time.Unix(toArchive[0].UnixTime, 0).Format("2006-01-02")
	path := fmt.Sprintf("%s/history-%s.jsonl", historyDir, dateStr)
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err := json.NewEncoder(f).Encode(toArchive[0]); err != nil {
		t.Errorf("Failed to encode event: %v", err)
	}
	f.Close()
	
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Error("History file was not created")
	}
}


func TestArchiveStep(t *testing.T) {
	tempDir, _ := os.MkdirTemp("", "archive-test")
	defer os.RemoveAll(tempDir)
	
	oldHistoryDir := historyDir
	historyDir = tempDir
	defer func() { historyDir = oldHistoryDir }()

	resetState()
	now := time.Now()
	lastArchivedTime = now.Add(-3 * time.Hour).Unix()
	
	// Add an event from 2 hours ago
	e := QueryEvent{
		UnixTime: now.Add(-2 * time.Hour).Unix(),
		Domain:   "old.com",
		Node:     "n1",
	}
	eventsMu.Lock()
	events[0] = e
	head = 1
	count = 1
	eventsMu.Unlock()

	archived := archiveStep(now)
	if archived != 1 {
		t.Errorf("Expected 1 archived event, got %d", archived)
	}

	// Verify file exists
	dateStr := time.Unix(e.UnixTime, 0).Format("2006-01-02")
	path := fmt.Sprintf("%s/history-%s.jsonl", historyDir, dateStr)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Error("Archive file not found")
	}
}

func TestCleanupStep(t *testing.T) {
	resetState()
	now := time.Now()
	
	pendingMu.Lock()
	pendingQueries["n1"] = map[string]time.Time{
		"stale.com": now.Add(-20 * time.Second),
		"fresh.com": now.Add(-2 * time.Second),
	}
	pendingMu.Unlock()

	cleaned := cleanupStep(now)
	if cleaned != 1 {
		t.Errorf("Expected 1 cleaned query, got %d", cleaned)
	}

	pendingMu.Lock()
	if _, ok := pendingQueries["n1"]["stale.com"]; ok {
		t.Error("stale.com should have been cleaned")
	}
	if _, ok := pendingQueries["n1"]["fresh.com"]; !ok {
		t.Error("fresh.com should NOT have been cleaned")
	}
	pendingMu.Unlock()
}

func TestIngestReader(t *testing.T) {
	resetState()
	
	logs := "dnsmasq[1]: query[A] d1.com from 1.1.1.1\ndnsmasq[1]: query[A] d2.com from 2.2.2.2\n"
	reader := bytes.NewReader([]byte(logs))
	
	ingestReader(reader)
	
	// Wait a bit for workers to process
	time.Sleep(100 * time.Millisecond)

	eventsMu.RLock()
	if count != 2 {
		t.Errorf("Expected 2 events from reader, got %d", count)
	}
	eventsMu.RUnlock()
}

func TestHistoryRetention(t *testing.T) {
	tempDir, _ := os.MkdirTemp("", "retention-test")
	defer os.RemoveAll(tempDir)
	
	oldHistoryDir := historyDir
	historyDir = tempDir
	defer func() { historyDir = oldHistoryDir }()

	// Create a very old file
	oldPath := tempDir + "/history-2020-01-01.jsonl"
	_ = os.WriteFile(oldPath, []byte("{}"), 0644)
	
	// Set mod time to 10 days ago
	oldTime := time.Now().Add(-240 * time.Hour)
	_ = os.Chtimes(oldPath, oldTime, oldTime)

	archiveStep(time.Now())

	if _, err := os.Stat(oldPath); !os.IsNotExist(err) {
		t.Error("Old history file should have been deleted")
	}
}

func TestRootHandler(t *testing.T) {
	resetState()
	handler := setupMux()
	
	// Inject an event
	parseLogBytes([]byte("dnsmasq[1]: query[A] root.com from 1.1.1.1"), "local")
	
	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	
	if rr.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", rr.Code)
	}
	
	if !strings.Contains(rr.Body.String(), "root.com") {
		t.Error("Dashboard did not contain injected event")
	}
}

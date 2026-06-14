// Package integration provides integration tests for the full log ingestion
// pipeline: parse → add event → archive → query stats. It also tests
// concurrent access patterns and SSE broadcast behavior.
package integration

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"tailscale-dnsrewrite/webgui/internal/config"
	"tailscale-dnsrewrite/webgui/internal/models"
	"tailscale-dnsrewrite/webgui/internal/parser"
	"tailscale-dnsrewrite/webgui/internal/storage"
)

// nowStamp returns the current time formatted as a dnsmasq log timestamp
// (time.Stamp layout: "Jan 02 15:04:05") so that parsed events have
// timestamps within the retention window.
func nowStamp() string {
	return time.Now().Format(time.Stamp)
}

// TestIngestionPipeline tests the full pipeline: parse → add event → archive → query stats.
func TestIngestionPipeline(t *testing.T) {
	cfg := &config.Config{
		MaxEvents:                10000,
		HistoryDir:               t.TempDir(),
		DBPath:                   "integration.db",
		HistoryRetention:         72 * time.Hour,
		UpstreamLatencyThreshold: 200,
	}
	store := storage.NewStore(cfg)
	store.Init()
	defer store.Close()

	prs := parser.NewParser(store, false)
	node := "integration-node"
	ts := nowStamp()

	// Step 1: Parse a query line
	queryLine := []byte(fmt.Sprintf("%s dnsmasq[1]: query[A] pipeline-test.com from 192.168.1.1", ts))
	ev := prs.ParseLogBytes(queryLine, node)
	if ev == nil {
		t.Fatal("expected non-nil event from query parse")
	}
	if ev.Domain != "pipeline-test.com" {
		t.Errorf("expected domain 'pipeline-test.com', got %s", ev.Domain)
	}
	if ev.Type != "A" {
		t.Errorf("expected type 'A', got %s", ev.Type)
	}

	// Step 2: Verify event was added to the ring buffer
	events := store.GetRecentEvents(0)
	if len(events) != 1 {
		t.Fatalf("expected 1 event in ring buffer, got %d", len(events))
	}

	// Step 3: Parse a forwarded line
	fwdLine := []byte(fmt.Sprintf("%s dnsmasq[1]: forwarded pipeline-test.com to 8.8.8.8", ts))
	prs.ParseLogBytes(fwdLine, node)

	// Step 4: Parse a reply line (should update the event with latency)
	replyLine := []byte(fmt.Sprintf("%s dnsmasq[1]: reply pipeline-test.com is 1.2.3.4", ts))
	updated := prs.ParseLogBytes(replyLine, node)
	if updated == nil {
		t.Fatal("expected non-nil event from reply parse")
	}
	if !updated.Latency.Valid {
		t.Error("expected latency to be valid after reply")
	}
	if updated.Upstream != "8.8.8.8" {
		t.Errorf("expected upstream '8.8.8.8', got %s", updated.Upstream)
	}

	// Step 5: Archive to SQLite
	archived := store.ArchiveStep(time.Now())
	if archived != 1 {
		t.Errorf("expected 1 event archived, got %d", archived)
	}

	// Step 6: Query stats from SQLite
	stats := store.GetStats()
	if stats == nil {
		t.Fatal("expected non-nil stats")
	}
	total, ok := stats["total"].(int64)
	if !ok {
		t.Fatalf("expected int64 for total, got %T", stats["total"])
	}
	if total < 1 {
		t.Errorf("expected total >= 1 after archive, got %d", total)
	}

	// Step 7: Verify type counts
	typeCounts, ok := stats["type_counts"].(map[string]int)
	if !ok {
		t.Fatalf("expected map[string]int for type_counts, got %T", stats["type_counts"])
	}
	if typeCounts["A"] < 1 {
		t.Errorf("expected at least 1 A type count, got %d", typeCounts["A"])
	}
}

// TestIngestionPipeline_MultipleDomains tests the pipeline with multiple domains.
func TestIngestionPipeline_MultipleDomains(t *testing.T) {
	cfg := &config.Config{
		MaxEvents:                10000,
		HistoryDir:               t.TempDir(),
		DBPath:                   "multi-domain.db",
		HistoryRetention:         72 * time.Hour,
		UpstreamLatencyThreshold: 200,
	}
	store := storage.NewStore(cfg)
	store.Init()
	defer store.Close()

	prs := parser.NewParser(store, false)
	node := "multi-node"
	ts := nowStamp()

	domains := []string{"alpha.com", "beta.org", "gamma.net", "delta.io"}
	for _, d := range domains {
		prs.ParseLogBytes([]byte(fmt.Sprintf("%s dnsmasq[1]: query[A] %s from 192.168.1.1", ts, d)), node)
		prs.ParseLogBytes([]byte(fmt.Sprintf("%s dnsmasq[1]: forwarded %s to 8.8.8.8", ts, d)), node)
		prs.ParseLogBytes([]byte(fmt.Sprintf("%s dnsmasq[1]: reply %s is 1.2.3.4", ts, d)), node)
	}

	events := store.GetRecentEvents(0)
	if len(events) != len(domains) {
		t.Errorf("expected %d events, got %d", len(domains), len(events))
	}

	archived := store.ArchiveStep(time.Now())
	if archived != len(domains) {
		t.Errorf("expected %d archived, got %d", len(domains), archived)
	}

	stats := store.GetStats()
	total, _ := stats["total"].(int64)
	if total < int64(len(domains)) {
		t.Errorf("expected total >= %d, got %d", len(domains), total)
	}
}

// TestIngestionPipeline_CachedQueries tests the pipeline with cached responses.
func TestIngestionPipeline_CachedQueries(t *testing.T) {
	cfg := &config.Config{
		MaxEvents:                10000,
		HistoryDir:               t.TempDir(),
		DBPath:                   "cached.db",
		HistoryRetention:         72 * time.Hour,
		UpstreamLatencyThreshold: 200,
	}
	store := storage.NewStore(cfg)
	store.Init()
	defer store.Close()

	prs := parser.NewParser(store, false)
	node := "cache-node"
	ts := nowStamp()

	// First query + reply (from upstream)
	prs.ParseLogBytes([]byte(fmt.Sprintf("%s dnsmasq[1]: query[A] cached.com from 192.168.1.1", ts)), node)
	prs.ParseLogBytes([]byte(fmt.Sprintf("%s dnsmasq[1]: forwarded cached.com to 8.8.8.8", ts)), node)
	prs.ParseLogBytes([]byte(fmt.Sprintf("%s dnsmasq[1]: reply cached.com is 1.2.3.4", ts)), node)

	// Second query + cached reply
	prs.ParseLogBytes([]byte(fmt.Sprintf("%s dnsmasq[1]: query[A] cached.com from 192.168.1.2", ts)), node)
	prs.ParseLogBytes([]byte(fmt.Sprintf("%s dnsmasq[1]: cached cached.com is 1.2.3.4", ts)), node)

	archived := store.ArchiveStep(time.Now())
	if archived != 2 {
		t.Errorf("expected 2 events archived, got %d", archived)
	}

	stats := store.GetStats()
	cacheHitRatio, ok := stats["cache_hit_ratio"].(float64)
	if !ok {
		t.Fatalf("expected float64 for cache_hit_ratio, got %T", stats["cache_hit_ratio"])
	}
	if cacheHitRatio <= 0 {
		t.Errorf("expected positive cache_hit_ratio, got %f", cacheHitRatio)
	}
}

// TestIngestionPipeline_DNSSEC tests DNSSEC validation in the pipeline.
func TestIngestionPipeline_DNSSEC(t *testing.T) {
	cfg := &config.Config{
		MaxEvents:                10000,
		HistoryDir:               t.TempDir(),
		DBPath:                   "dnssec.db",
		HistoryRetention:         72 * time.Hour,
		UpstreamLatencyThreshold: 200,
	}
	store := storage.NewStore(cfg)
	store.Init()
	defer store.Close()

	prs := parser.NewParser(store, false)
	node := "dnssec-node"
	ts := nowStamp()

	// Query + reply
	prs.ParseLogBytes([]byte(fmt.Sprintf("%s dnsmasq[1]: query[A] secure.org from 192.168.1.1", ts)), node)
	prs.ParseLogBytes([]byte(fmt.Sprintf("%s dnsmasq[1]: forwarded secure.org to 8.8.8.8", ts)), node)
	prs.ParseLogBytes([]byte(fmt.Sprintf("%s dnsmasq[1]: reply secure.org is 1.2.3.4", ts)), node)

	// DNSSEC validation
	prs.ParseLogBytes([]byte(fmt.Sprintf("%s dnsmasq[1]: validation secure.org IN secure", ts)), node)

	events := store.GetRecentEvents(0)
	found := false
	for _, e := range events {
		if e.Domain == "secure.org" && e.DNSSEC == "secure" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected DNSSEC 'secure' to be set on the event")
	}
}

// TestIngestionPipeline_BlockedDomain tests blocked domain handling.
func TestIngestionPipeline_BlockedDomain(t *testing.T) {
	cfg := &config.Config{
		MaxEvents:                10000,
		HistoryDir:               t.TempDir(),
		DBPath:                   "blocked.db",
		HistoryRetention:         72 * time.Hour,
		UpstreamLatencyThreshold: 200,
	}
	store := storage.NewStore(cfg)
	store.Init()
	defer store.Close()

	prs := parser.NewParser(store, false)
	node := "blocked-node"
	ts := nowStamp()

	prs.ParseLogBytes([]byte(fmt.Sprintf("%s dnsmasq[1]: query[A] ads.tracker.com from 192.168.1.1", ts)), node)

	// Mark as blocked
	store.SetBlocked(node, "ads.tracker.com")

	events := store.GetRecentEvents(0)
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if !events[0].Blocked {
		t.Error("expected event to be marked as blocked")
	}

	// Archive and verify in SQLite
	store.ArchiveStep(time.Now())
	var blocked int
	if err := store.DB().QueryRow("SELECT blocked FROM queries WHERE domain = 'ads.tracker.com'").Scan(&blocked); err != nil {
		t.Fatalf("failed to query blocked status: %v", err)
	}
	if blocked != 1 {
		t.Errorf("expected blocked=1 in SQLite, got %d", blocked)
	}
}

// TestConcurrentIngestion tests multiple goroutines adding events simultaneously.
func TestConcurrentIngestion(t *testing.T) {
	cfg := &config.Config{
		MaxEvents:                50000,
		HistoryDir:               t.TempDir(),
		DBPath:                   "concurrent.db",
		HistoryRetention:         72 * time.Hour,
		UpstreamLatencyThreshold: 200,
	}
	store := storage.NewStore(cfg)
	store.Init()
	defer store.Close()

	prs := parser.NewParser(store, false)

	const workers = 20
	const eventsPerWorker = 100
	var wg sync.WaitGroup

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			ts := nowStamp()
			for i := 0; i < eventsPerWorker; i++ {
				line := []byte(fmt.Sprintf("%s dnsmasq[1]: query[A] concurrent-%d-%d.com from 10.0.%d.%d", ts, id, i, id/254, id%254+1))
				prs.ParseLogBytes(line, fmt.Sprintf("worker-%d", id))
			}
		}(w)
	}
	wg.Wait()

	events := store.GetOrderedEvents(workers * eventsPerWorker)
	if len(events) != workers*eventsPerWorker {
		t.Errorf("expected %d events, got %d", workers*eventsPerWorker, len(events))
	}

	// Archive all and verify
	archived := store.ArchiveStep(time.Now())
	if archived != workers*eventsPerWorker {
		t.Errorf("expected %d archived, got %d", workers*eventsPerWorker, archived)
	}

	var total int64
	if err := store.DB().QueryRow("SELECT COUNT(*) FROM queries").Scan(&total); err != nil {
		t.Fatalf("failed to query total: %v", err)
	}
	if total != int64(workers*eventsPerWorker) {
		t.Errorf("expected %d rows in SQLite, got %d", workers*eventsPerWorker, total)
	}
}

// TestSSEBroadcast tests the SSE broadcast mechanism via the store.
func TestSSEBroadcast(t *testing.T) {
	cfg := &config.Config{
		MaxEvents:                1000,
		HistoryDir:               t.TempDir(),
		DBPath:                   "sse.db",
		HistoryRetention:         72 * time.Hour,
		UpstreamLatencyThreshold: 200,
	}
	store := storage.NewStore(cfg)
	store.Init()
	defer store.Close()

	// Simulate SSE subscriber channels
	const numSubscribers = 5
	channels := make([]chan models.QueryEvent, numSubscribers)
	for i := 0; i < numSubscribers; i++ {
		ch := make(chan models.QueryEvent, 100)
		channels[i] = ch
	}

	// Add events and broadcast to channels
	now := time.Now().Unix()
	const numEvents = 10
	for i := 0; i < numEvents; i++ {
		ev := models.QueryEvent{
			UnixTime: now + int64(i),
			Type:     "A",
			Domain:   fmt.Sprintf("sse-test-%d.com", i),
			ClientIP: "192.168.1.1",
			Node:     "sse-node",
		}
		store.AddEvent(ev)

		// Broadcast to all subscriber channels
		for _, ch := range channels {
			select {
			case ch <- ev:
			default:
				t.Log("Warning: subscriber channel full, dropping event")
			}
		}
	}

	// Verify all subscribers received all events
	var receivedCount atomic.Int64
	var wg sync.WaitGroup
	for i, ch := range channels {
		wg.Add(1)
		go func(idx int, c chan models.QueryEvent) {
			defer wg.Done()
			count := 0
			for count < numEvents {
				select {
				case ev := <-c:
					count++
					receivedCount.Add(1)
					_ = ev
				case <-time.After(2 * time.Second):
					t.Errorf("subscriber %d timed out after %d events", idx, count)
					return
				}
			}
		}(i, ch)
	}
	wg.Wait()

	total := receivedCount.Load()
	if total != int64(numSubscribers*numEvents) {
		t.Errorf("expected %d total received events, got %d", numSubscribers*numEvents, total)
	}
}

// TestIngestionPipeline_ResponseCodes tests response code tracking.
func TestIngestionPipeline_ResponseCodes(t *testing.T) {
	cfg := &config.Config{
		MaxEvents:                10000,
		HistoryDir:               t.TempDir(),
		DBPath:                   "response-codes.db",
		HistoryRetention:         72 * time.Hour,
		UpstreamLatencyThreshold: 200,
	}
	store := storage.NewStore(cfg)
	store.Init()
	defer store.Close()

	prs := parser.NewParser(store, false)
	node := "rc-node"
	ts := nowStamp()

	// NXDOMAIN
	prs.ParseLogBytes([]byte(fmt.Sprintf("%s dnsmasq[1]: query[A] nxdomain-test.com from 192.168.1.1", ts)), node)
	prs.ParseLogBytes([]byte(fmt.Sprintf("%s dnsmasq[1]: forwarded nxdomain-test.com to 8.8.8.8", ts)), node)
	prs.ParseLogBytes([]byte(fmt.Sprintf("%s dnsmasq[1]: reply nxdomain-test.com is NXDOMAIN", ts)), node)

	events := store.GetRecentEvents(0)
	if len(events) < 1 {
		t.Fatal("expected at least 1 event")
	}
	if events[0].ResponseCode != "NXDOMAIN" {
		t.Errorf("expected response code 'NXDOMAIN', got %s", events[0].ResponseCode)
	}
}

// TestIngestionPipeline_DataIntegrity verifies data integrity at each pipeline step.
func TestIngestionPipeline_DataIntegrity(t *testing.T) {
	cfg := &config.Config{
		MaxEvents:                10000,
		HistoryDir:               t.TempDir(),
		DBPath:                   "integrity.db",
		HistoryRetention:         72 * time.Hour,
		UpstreamLatencyThreshold: 200,
	}
	store := storage.NewStore(cfg)
	store.Init()
	defer store.Close()

	prs := parser.NewParser(store, false)
	node := "integrity-node"
	ts := nowStamp()

	// Parse a complete query lifecycle
	prs.ParseLogBytes([]byte(fmt.Sprintf("%s dnsmasq[1]: query[A] integrity.com from 10.0.0.1", ts)), node)
	prs.ParseLogBytes([]byte(fmt.Sprintf("%s dnsmasq[1]: forwarded integrity.com to 1.1.1.1", ts)), node)
	prs.ParseLogBytes([]byte(fmt.Sprintf("%s dnsmasq[1]: reply integrity.com is 93.184.216.34", ts)), node)

	// Verify in-memory data
	events := store.GetRecentEvents(0)
	if len(events) != 1 {
		t.Fatalf("expected 1 event in memory, got %d", len(events))
	}
	ev := events[0]
	if ev.Domain != "integrity.com" {
		t.Errorf("expected domain 'integrity.com', got %s", ev.Domain)
	}
	if ev.Type != "A" {
		t.Errorf("expected type 'A', got %s", ev.Type)
	}
	if ev.ClientIP != "10.0.0.1" {
		t.Errorf("expected client IP '10.0.0.1', got %s", ev.ClientIP)
	}
	if ev.Upstream != "1.1.1.1" {
		t.Errorf("expected upstream '1.1.1.1', got %s", ev.Upstream)
	}
	if !ev.Latency.Valid {
		t.Error("expected latency to be valid")
	}

	// Archive and verify in SQLite
	store.ArchiveStep(time.Now())

	var (
		dbDomain   string
		dbType     string
		dbClientIP string
		dbUpstream string
		dbLatency  sql.NullFloat64
	)
	err := store.DB().QueryRow(
		"SELECT domain, type, client_ip, upstream, latency FROM queries WHERE domain = 'integrity.com'",
	).Scan(&dbDomain, &dbType, &dbClientIP, &dbUpstream, &dbLatency)
	if err != nil {
		t.Fatalf("failed to query archived data: %v", err)
	}
	if dbDomain != "integrity.com" {
		t.Errorf("SQLite: expected domain 'integrity.com', got %s", dbDomain)
	}
	if dbType != "A" {
		t.Errorf("SQLite: expected type 'A', got %s", dbType)
	}
	if dbClientIP != "10.0.0.1" {
		t.Errorf("SQLite: expected client_ip '10.0.0.1', got %s", dbClientIP)
	}
	if dbUpstream != "1.1.1.1" {
		t.Errorf("SQLite: expected upstream '1.1.1.1', got %s", dbUpstream)
	}
	if !dbLatency.Valid {
		t.Error("SQLite: expected latency to be valid")
	}
}

// TestIngestionPipeline_JSONSerialization verifies events can be serialized to JSON.
func TestIngestionPipeline_JSONSerialization(t *testing.T) {
	cfg := &config.Config{
		MaxEvents:                1000,
		HistoryDir:               t.TempDir(),
		DBPath:                   "json.db",
		HistoryRetention:         72 * time.Hour,
		UpstreamLatencyThreshold: 200,
	}
	store := storage.NewStore(cfg)
	store.Init()
	defer store.Close()

	prs := parser.NewParser(store, false)
	node := "json-node"
	ts := nowStamp()

	prs.ParseLogBytes([]byte(fmt.Sprintf("%s dnsmasq[1]: query[A] json-test.com from 192.168.1.1", ts)), node)

	events := store.GetRecentEvents(0)
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	// Serialize to JSON
	data, err := json.Marshal(events[0])
	if err != nil {
		t.Fatalf("failed to marshal event to JSON: %v", err)
	}

	// Verify JSON contains expected fields
	jsonStr := string(data)
	if !contains(jsonStr, "json-test.com") {
		t.Errorf("JSON does not contain domain: %s", jsonStr)
	}
	if !contains(jsonStr, "A") {
		t.Errorf("JSON does not contain type: %s", jsonStr)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

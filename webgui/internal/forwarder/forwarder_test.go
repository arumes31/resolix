// Package forwarder provides unit tests for the Forwarder type, covering
// batch queuing, retry mechanisms, stop behavior, and authentication.
package forwarder

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"tailscale-dnsrewrite/webgui/internal/config"
	"tailscale-dnsrewrite/webgui/internal/configsync"
	"tailscale-dnsrewrite/webgui/internal/models"
)

// testEvents builds query events with the given domains for "test-node".
func testEvents(domains ...string) []models.QueryEvent {
	events := make([]models.QueryEvent, len(domains))
	for i, d := range domains {
		events[i] = models.QueryEvent{
			UnixTime: time.Now().Unix(),
			Type:     "A",
			Domain:   d,
			ClientIP: "192.0.2.1",
			Node:     "test-node",
		}
	}
	return events
}

func TestSyncDNSConfigAppliesOnlyValidNewRevision(t *testing.T) {
	snapshot := configsync.NewSnapshot([]string{"1.1.1.1"}, nil, nil, "||example.test^\n", nil, nil)
	master := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/sync/dns-config" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(snapshot)
	}))
	defer master.Close()

	forwarder := NewForwarder(&config.Config{Mode: "slave", MasterURL: master.URL, MaxRequestSize: 1 << 20})
	var calls atomic.Int32
	forwarder.SetDNSConfigFn(func(got configsync.Snapshot) error {
		if got.Revision != snapshot.Revision {
			t.Fatalf("revision = %q, want %q", got.Revision, snapshot.Revision)
		}
		calls.Add(1)
		return nil
	})
	forwarder.syncDNSConfig(master.Client())
	forwarder.syncDNSConfig(master.Client())
	if calls.Load() != 1 || forwarder.ConfigRevision() != snapshot.Revision {
		t.Fatalf("calls/revision = %d/%q", calls.Load(), forwarder.ConfigRevision())
	}
}

// decodeJSONBody handles both gzip-compressed and uncompressed request bodies.
func decodeJSONBody(r *http.Request, v interface{}) error {
	var reader io.Reader = r.Body
	if r.Header.Get("Content-Encoding") == "gzip" {
		gzReader, err := gzip.NewReader(r.Body)
		if err != nil {
			return err
		}
		defer func() { _ = gzReader.Close() }()
		reader = gzReader
	}
	return json.NewDecoder(reader).Decode(v)
}

func TestNewForwarder(t *testing.T) {
	cfg := &config.Config{Mode: "slave", MasterURL: "http://localhost:12345", NodeName: "test-node"}
	fwd := NewForwarder(cfg)
	if fwd == nil {
		t.Fatal("NewForwarder returned nil")
	}
}

func TestEnqueue_SlaveMode(t *testing.T) {
	cfg := &config.Config{Mode: "slave", MasterURL: "http://localhost:12345", NodeName: "test-node"}
	fwd := NewForwarder(cfg)

	fwd.EnqueueEvent(models.QueryEvent{Domain: "line1.example.com", Node: "test-node"})
	fwd.EnqueueEvent(models.QueryEvent{Domain: "line2.example.com", Node: "test-node"})

	fwd.backlogMu.Lock()
	count := len(fwd.backlog)
	fwd.backlogMu.Unlock()

	if count != 2 {
		t.Errorf("expected 2 items in backlog, got %d", count)
	}
}

func TestEnqueue_MasterMode(t *testing.T) {
	cfg := &config.Config{Mode: "master", NodeName: "test-node"}
	fwd := NewForwarder(cfg)

	fwd.EnqueueEvent(models.QueryEvent{Domain: "line1.example.com", Node: "test-node"})

	fwd.backlogMu.Lock()
	count := len(fwd.backlog)
	fwd.backlogMu.Unlock()

	if count != 0 {
		t.Errorf("expected 0 items in backlog for master mode, got %d", count)
	}
}

func TestEnqueue_NoMasterURL(t *testing.T) {
	cfg := &config.Config{Mode: "slave", MasterURL: "", NodeName: "test-node"}
	fwd := NewForwarder(cfg)

	fwd.EnqueueEvent(models.QueryEvent{Domain: "line1.example.com", Node: "test-node"})

	fwd.backlogMu.Lock()
	count := len(fwd.backlog)
	fwd.backlogMu.Unlock()

	if count != 0 {
		t.Errorf("expected 0 items in backlog when no MasterURL, got %d", count)
	}
}

func TestEnqueue_MaxBacklogSize(t *testing.T) {
	cfg := &config.Config{
		Mode:           "slave",
		MasterURL:      "http://localhost:12345",
		NodeName:       "test-node",
		MaxBacklogSize: 2048, // Small limit (a few events)
	}
	fwd := NewForwarder(cfg)

	// Add events that will exceed the max backlog size
	for i := 0; i < 200; i++ {
		fwd.EnqueueEvent(models.QueryEvent{Domain: fmt.Sprintf("line-%d-this-is-a-longer-domain-to-exceed-size.example.com", i), Node: "test-node"})
	}

	fwd.backlogMu.Lock()
	count := len(fwd.backlog)
	totalSize := fwd.backlogTotalSize
	fwd.backlogMu.Unlock()

	// The backlog must never exceed MaxBacklogSize in bytes.
	if totalSize > cfg.MaxBacklogSize {
		t.Errorf("expected backlog total size <= MaxBacklogSize=%d, got size=%d count=%d", cfg.MaxBacklogSize, totalSize, count)
	}
	// The count should be much less than 200 since items were dropped
	if count >= 200 {
		t.Errorf("expected some items to be dropped, got count=%d", count)
	}
}

func TestSendBatch_Success(t *testing.T) {
	var receivedEvents []models.QueryEvent
	var requestCount atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)

		// Verify content type
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("expected Content-Type application/json, got %s", ct)
		}

		if err := decodeJSONBody(r, &receivedEvents); err != nil {
			t.Errorf("failed to decode payload: %v", err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	cfg := &config.Config{
		Mode:      "slave",
		MasterURL: server.URL,
		NodeName:  "test-node",
		BaseURL:   "",
	}
	fwd := NewForwarder(cfg)

	client := &http.Client{Timeout: 5 * time.Second}
	events := testEvents("one.example.com", "two.example.com", "three.example.com")
	err := fwd.sendBatch(client, events, nil)
	if err != nil {
		t.Fatalf("sendBatch failed: %v", err)
	}

	if requestCount.Load() != 1 {
		t.Errorf("expected 1 request, got %d", requestCount.Load())
	}
	if len(receivedEvents) != 3 {
		t.Errorf("expected 3 batch items, got %d", len(receivedEvents))
	}
	for _, ev := range receivedEvents {
		if ev.Node != "test-node" {
			t.Errorf("expected node 'test-node', got %s", ev.Node)
		}
	}
}

func TestSendBatch_WithIngestSecret(t *testing.T) {
	var receivedAuth string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	cfg := &config.Config{
		Mode:         "slave",
		MasterURL:    server.URL,
		NodeName:     "test-node",
		IngestSecret: "my-secret-token",
		BaseURL:      "",
	}
	fwd := NewForwarder(cfg)

	client := &http.Client{Timeout: 5 * time.Second}
	err := fwd.sendBatch(client, testEvents("line1.example.com"), nil)
	if err != nil {
		t.Fatalf("sendBatch failed: %v", err)
	}

	expected := "Bearer my-secret-token"
	if receivedAuth != expected {
		t.Errorf("expected Authorization '%s', got '%s'", expected, receivedAuth)
	}
}

func TestSendBatch_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	cfg := &config.Config{
		Mode:      "slave",
		MasterURL: server.URL,
		NodeName:  "test-node",
		BaseURL:   "",
	}
	fwd := NewForwarder(cfg)

	client := &http.Client{Timeout: 5 * time.Second}
	err := fwd.sendBatch(client, testEvents("line1.example.com"), nil)
	if err == nil {
		t.Error("expected error for 500 response, got nil")
	}
}

func TestSendBatch_ConnectionRefused(t *testing.T) {
	cfg := &config.Config{
		Mode:      "slave",
		MasterURL: "http://localhost:0", // Port 0 is invalid/unreachable
		NodeName:  "test-node",
		BaseURL:   "",
	}
	fwd := NewForwarder(cfg)

	client := &http.Client{Timeout: 1 * time.Second}
	err := fwd.sendBatch(client, testEvents("line1.example.com"), nil)
	if err == nil {
		t.Error("expected error for connection refused, got nil")
	}
}

func TestSendBatch_WithHealth(t *testing.T) {
	var receivedHealth map[string]float64

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]interface{}
		_ = decodeJSONBody(r, &payload)
		if h, ok := payload["health"].(map[string]interface{}); ok {
			receivedHealth = make(map[string]float64)
			for k, v := range h {
				if f, ok := v.(float64); ok {
					receivedHealth[k] = f
				}
			}
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	cfg := &config.Config{
		Mode:      "slave",
		MasterURL: server.URL,
		NodeName:  "test-node",
		BaseURL:   "",
	}
	fwd := NewForwarder(cfg)

	client := &http.Client{Timeout: 5 * time.Second}
	health := map[string]float64{"8.8.8.8": 15.5, "1.1.1.1": 8.2}
	err := fwd.sendBatch(client, nil, health)
	if err != nil {
		t.Fatalf("sendBatch with health failed: %v", err)
	}

	if len(receivedHealth) != 2 {
		t.Errorf("expected 2 health entries, got %d", len(receivedHealth))
	}
	if receivedHealth["8.8.8.8"] != 15.5 {
		t.Errorf("expected health 15.5 for 8.8.8.8, got %f", receivedHealth["8.8.8.8"])
	}
}

func TestStop(_ *testing.T) {
	cfg := &config.Config{Mode: "slave", MasterURL: "http://localhost:12345", NodeName: "test-node"}
	fwd := NewForwarder(cfg)

	// Stop should not panic
	fwd.Stop()

	// Double stop should not panic (sync.Once)
	fwd.Stop()
}

func TestStart_MasterMode(t *testing.T) {
	cfg := &config.Config{Mode: "master", NodeName: "test-node"}
	fwd := NewForwarder(cfg)

	// Start should return nil immediately in master mode
	err := fwd.Start()
	if err != nil {
		t.Errorf("expected nil for master mode Start, got %v", err)
	}
}

func TestStart_StopDrain(t *testing.T) {
	var receivedCount atomic.Int32
	delivered := make(chan struct{}, 1)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		receivedCount.Add(1)
		w.WriteHeader(http.StatusNoContent)
		select {
		case delivered <- struct{}{}:
		default:
		}
	}))
	defer server.Close()

	cfg := &config.Config{
		Mode:                       "slave",
		MasterURL:                  server.URL,
		NodeName:                   "test-node",
		BaseURL:                    "",
		HeartbeatInterval:          1 * time.Hour,
		SyncAliasesInterval:        1 * time.Hour,
		SyncDNSRoutesInterval:      1 * time.Hour,
		SyncUpstreamHealthInterval: 1 * time.Hour,
	}
	fwd := NewForwarder(cfg)

	// Enqueue some lines
	fwd.EnqueueEvent(models.QueryEvent{Domain: "drain1.example.com", Node: "test-node"})
	fwd.EnqueueEvent(models.QueryEvent{Domain: "drain2.example.com", Node: "test-node"})

	// Start the forwarder in a goroutine
	done := make(chan error, 1)
	go func() {
		done <- fwd.Start()
	}()

	select {
	case <-delivered:
	case <-time.After(5 * time.Second):
		t.Fatal("forwarder did not deliver backlog")
	}

	// Stop the forwarder
	fwd.Stop()

	// Wait for Start to return
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Start returned error after Stop: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Start did not return after Stop within timeout")
	}
}

func TestRetryMechanism(t *testing.T) {
	var attemptCount atomic.Int32
	delivered := make(chan struct{})
	var deliveredOnce sync.Once

	// Server that fails first 2 ingest attempts, then succeeds.
	// Only POST /api/ingest requests are counted so concurrent startup
	// heartbeat/sync requests cannot skew the retry count.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/ingest" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		count := attemptCount.Add(1)
		if count <= 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		deliveredOnce.Do(func() { close(delivered) })
	}))
	defer server.Close()

	cfg := &config.Config{
		Mode:                       "slave",
		MasterURL:                  server.URL,
		NodeName:                   "test-node",
		BaseURL:                    "",
		HeartbeatInterval:          1 * time.Hour,
		SyncAliasesInterval:        1 * time.Hour,
		SyncDNSRoutesInterval:      1 * time.Hour,
		SyncUpstreamHealthInterval: 1 * time.Hour,
	}
	fwd := NewForwarder(cfg)

	// Enqueue a line
	fwd.EnqueueEvent(models.QueryEvent{Domain: "retry.example.com", Node: "test-node"})

	done := make(chan error, 1)
	go func() {
		done <- fwd.Start()
	}()

	select {
	case <-delivered:
	case <-time.After(10 * time.Second):
		t.Fatal("forwarder retries did not reach a success")
	}
	fwd.Stop()

	select {
	case <-done:
		// Forwarder exited
	case <-time.After(5 * time.Second):
		t.Fatal("Forwarder did not exit after Stop")
	}

	// Should have attempted at least 3 times (2 failures + 1 success)
	if attemptCount.Load() < 3 {
		t.Errorf("expected at least 3 attempts, got %d", attemptCount.Load())
	}
}

func TestBatchSizeLimit(t *testing.T) {
	var batchSizes []int
	var mu sync.Mutex
	fullBatch := make(chan struct{}, 1)

	// Record only POST /api/ingest batches so heartbeat/sync requests are ignored.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/ingest" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		var events []models.QueryEvent
		_ = decodeJSONBody(r, &events)
		mu.Lock()
		batchSizes = append(batchSizes, len(events))
		mu.Unlock()
		if len(events) == 100 {
			select {
			case fullBatch <- struct{}{}:
			default:
			}
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	cfg := &config.Config{
		Mode:                       "slave",
		MasterURL:                  server.URL,
		NodeName:                   "test-node",
		BaseURL:                    "",
		HeartbeatInterval:          1 * time.Hour,
		SyncAliasesInterval:        1 * time.Hour,
		SyncDNSRoutesInterval:      1 * time.Hour,
		SyncUpstreamHealthInterval: 1 * time.Hour,
	}
	fwd := NewForwarder(cfg)

	// Enqueue more than 100 lines
	for i := 0; i < 150; i++ {
		fwd.EnqueueEvent(models.QueryEvent{Domain: fmt.Sprintf("batch-line-%d.example.com", i), Node: "test-node"})
	}

	done := make(chan error, 1)
	go func() {
		done <- fwd.Start()
	}()

	select {
	case <-fullBatch:
	case <-time.After(5 * time.Second):
		t.Fatal("forwarder did not send a full batch")
	}
	fwd.Stop()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Forwarder did not exit")
	}

	mu.Lock()
	sizes := append([]int(nil), batchSizes...)
	mu.Unlock()

	// A full batch should reach exactly the 100-line limit
	found := false
	for _, n := range sizes {
		if n == 100 {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected a received batch of exactly 100 lines, got batch sizes %v", sizes)
	}
}

func TestReportHealth_SlaveMode(t *testing.T) {
	var receivedHealth map[string]interface{}
	var mu sync.Mutex
	received := make(chan struct{}, 1)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]interface{}
		_ = decodeJSONBody(r, &payload)
		if h, ok := payload["health"]; ok {
			if hm, ok := h.(map[string]interface{}); ok {
				mu.Lock()
				receivedHealth = hm
				mu.Unlock()
				select {
				case received <- struct{}{}:
				default:
				}
			}
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	cfg := &config.Config{
		Mode:      "slave",
		MasterURL: server.URL,
		NodeName:  "test-node",
		BaseURL:   "",
	}
	fwd := NewForwarder(cfg)

	health := map[string]float64{"8.8.8.8": 12.3}
	fwd.ReportHealth(health)

	select {
	case <-received:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for health report")
	}

	mu.Lock()
	defer mu.Unlock()
	if receivedHealth == nil {
		t.Error("expected health data to be received by server")
	}
}

func TestReportHealth_MasterMode(_ *testing.T) {
	cfg := &config.Config{Mode: "master", NodeName: "test-node"}
	fwd := NewForwarder(cfg)

	// Should not panic in master mode
	fwd.ReportHealth(map[string]float64{"8.8.8.8": 12.3})
}

func TestCalculateBackoff(t *testing.T) {
	tests := []struct {
		attempt int
		minTime time.Duration
		maxTime time.Duration
	}{
		{0, 1 * time.Second, 1500 * time.Millisecond},
		{1, 1 * time.Second, 1500 * time.Millisecond},
		{2, 2 * time.Second, 2500 * time.Millisecond},
		{3, 4 * time.Second, 4500 * time.Millisecond},
		{4, 8 * time.Second, 8500 * time.Millisecond},
		{5, 16 * time.Second, 16500 * time.Millisecond},
		{6, 30 * time.Second, 30500 * time.Millisecond},
		{10, 30 * time.Second, 30500 * time.Millisecond}, // capped at 30s
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("attempt_%d", tt.attempt), func(t *testing.T) {
			// Run multiple times to account for jitter
			for i := 0; i < 10; i++ {
				backoff := calculateBackoff(tt.attempt, time.Second)
				if backoff < tt.minTime || backoff > tt.maxTime {
					t.Errorf("calculateBackoff(%d) = %v, want between %v and %v",
						tt.attempt, backoff, tt.minTime, tt.maxTime)
				}
			}
		})
	}
}

func TestSyncFromMasterRejectsOversizedGzipResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		writer := gzip.NewWriter(w)
		_, _ = writer.Write([]byte("response-too-large"))
		_ = writer.Close()
	}))
	defer server.Close()
	fwd := NewForwarder(&config.Config{MasterURL: server.URL, MaxRequestSize: 4})
	if _, err := fwd.syncFromMaster(server.Client(), "/sync"); err == nil {
		t.Fatal("expected oversized response error")
	}
}

func TestGzipCompress(t *testing.T) {
	// Small payload: gzip overhead makes it larger, so should return false
	smallData := []byte(`{"node":"test"}`)
	compressed, useGzip := gzipCompress(smallData)
	if useGzip {
		t.Errorf("expected gzip to not be used for small payload (compressed=%d, original=%d)", len(compressed), len(smallData))
	}

	// Large payload: gzip should compress and return true
	largeData := make([]byte, 2000)
	for i := range largeData {
		largeData[i] = byte('a' + (i % 26))
	}
	compressed, useGzip = gzipCompress(largeData)
	if !useGzip {
		t.Error("expected gzip to be used for large payload")
	}
	if len(compressed) >= len(largeData) {
		t.Errorf("expected compressed size (%d) to be less than original (%d)", len(compressed), len(largeData))
	}

	// Verify the compressed data can be decompressed
	reader, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		t.Fatalf("failed to create gzip reader: %v", err)
	}
	decompressed, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("failed to decompress: %v", err)
	}
	_ = reader.Close()
	if string(decompressed) != string(largeData) {
		t.Error("decompressed data does not match original")
	}
}

func TestVersionHeaders(t *testing.T) {
	var nodeVersion, goVersion, buildInfo string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nodeVersion = r.Header.Get("X-Node-Version")
		goVersion = r.Header.Get("X-Go-Version")
		buildInfo = r.Header.Get("X-Node-Build")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	cfg := &config.Config{
		Mode:      "slave",
		MasterURL: server.URL,
		NodeName:  "test-node",
		BaseURL:   "",
	}
	fwd := NewForwarder(cfg)

	client := &http.Client{Timeout: 5 * time.Second}
	_ = fwd.sendBatch(client, testEvents("line1.example.com"), nil)

	if nodeVersion != Version {
		t.Errorf("expected X-Node-Version '%s', got '%s'", Version, nodeVersion)
	}
	if goVersion == "" {
		t.Error("expected non-empty X-Go-Version header")
	}
	if buildInfo == "" {
		t.Error("expected non-empty X-Node-Build header")
	}
}

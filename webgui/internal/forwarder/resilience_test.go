package forwarder

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/arumes31/resolix/webgui/internal/config"
	"github.com/arumes31/resolix/webgui/internal/models"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func resilienceConfig(controllerURL, historyDir string) *config.Config {
	return &config.Config{
		Mode:                       config.ModeAgent,
		ControllerURL:              controllerURL,
		NodeName:                   "resilient-agent",
		HistoryDir:                 historyDir,
		MaxBacklogSize:             1 << 20,
		ForwarderRetryInterval:     time.Millisecond,
		HeartbeatInterval:          time.Hour,
		SyncAliasesInterval:        time.Hour,
		SyncDNSRoutesInterval:      time.Hour,
		SyncUpstreamHealthInterval: time.Hour,
	}
}

func TestPersistentBacklogSurvivesRestart(t *testing.T) {
	historyDir := t.TempDir()
	cfg := resilienceConfig("https://100.64.0.1", historyDir)
	first := NewForwarder(cfg)
	first.EnqueueEvent(models.QueryEvent{
		UnixTime: time.Now().Unix(), Domain: "durable.example", CacheStatus: "stale", CacheTTL: 9,
	})
	if err := first.flushBacklog(); err != nil {
		t.Fatalf("persist backlog: %v", err)
	}

	restored := NewForwarder(cfg)
	status := restored.SnapshotStatus(time.Now())
	if status.BacklogDepth != 1 || status.BacklogBytes == 0 {
		t.Fatalf("restored status = %+v", status)
	}
	if status.PersistentBacklogPath != filepath.Join(historyDir, backlogStateFile) {
		t.Fatalf("backlog path = %q", status.PersistentBacklogPath)
	}
	restored.backlogMu.Lock()
	event := restored.backlog[0].event
	restored.backlogMu.Unlock()
	if event.Domain != "durable.example" || event.CacheStatus != "stale" || event.CacheTTL != 9 {
		t.Fatalf("restored event = %+v", event)
	}
}

func TestPersistentBacklogTruncationMatchesMemoryAndDropAccounting(t *testing.T) {
	historyDir := t.TempDir()
	cfg := resilienceConfig("https://100.64.0.1", historyDir)
	cfg.MaxBacklogSize = 0
	forwarder := NewForwarder(cfg)
	for index := 0; index < 10; index++ {
		forwarder.EnqueueEvent(models.QueryEvent{
			UnixTime: time.Now().Unix(), Domain: "bounded-persistence.example", Node: "resilient-agent",
		})
	}
	before := forwarder.SnapshotStatus(time.Now())
	cfg.MaxBacklogSize = before.BacklogBytes
	if err := forwarder.flushBacklog(); err != nil {
		t.Fatalf("flush bounded backlog: %v", err)
	}
	after := forwarder.SnapshotStatus(time.Now())
	if after.BacklogDepth >= before.BacklogDepth || after.Dropped != int64(before.BacklogDepth-after.BacklogDepth) {
		t.Fatalf("before=%+v after=%+v", before, after)
	}
	restored := NewForwarder(cfg)
	if got := restored.SnapshotStatus(time.Now()).BacklogDepth; got != after.BacklogDepth {
		t.Fatalf("restored depth = %d, in-memory depth = %d", got, after.BacklogDepth)
	}
}

func TestForwarderRecoversFromPacketLossDelayAndHTTPFailure(t *testing.T) {
	var served atomic.Int32
	delivered := make(chan struct{})
	var deliveredOnce sync.Once
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/api/ingest" {
			writer.WriteHeader(http.StatusNoContent)
			return
		}
		attempt := served.Add(1)
		if attempt == 1 {
			time.Sleep(25 * time.Millisecond)
			writer.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
		deliveredOnce.Do(func() { close(delivered) })
	}))
	defer server.Close()

	baseTransport := server.Client().Transport
	var transportAttempts atomic.Int32
	client := server.Client()
	client.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method == http.MethodPost && request.URL.Path == "/api/ingest" &&
			transportAttempts.Add(1) == 1 {
			return nil, io.ErrUnexpectedEOF
		}
		return baseTransport.RoundTrip(request)
	})

	forwarder := NewForwarder(resilienceConfig(server.URL, ""))
	forwarder.httpClient = client
	forwarder.EnqueueEvent(models.QueryEvent{Domain: "chaos.example", Node: "resilient-agent"})
	started := time.Now()
	done := make(chan error, 1)
	go func() { done <- forwarder.Start() }()
	select {
	case <-delivered:
	case <-time.After(5 * time.Second):
		forwarder.Stop()
		t.Fatal("event was not delivered after transport and HTTP failures")
	}
	forwarder.Stop()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("forwarder stopped with error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("forwarder did not stop")
	}

	status := forwarder.SnapshotStatus(time.Now())
	if transportAttempts.Load() < 3 || served.Load() < 2 || status.Retries < 2 || status.Sent != 1 {
		t.Fatalf("attempts=%d served=%d status=%+v", transportAttempts.Load(), served.Load(), status)
	}
	if time.Since(started) < 25*time.Millisecond {
		t.Fatal("delayed failure path was not exercised")
	}
	if endpoint := status.Endpoints["ingest"]; endpoint.LastSuccess.IsZero() || endpoint.LastError != "" {
		t.Fatalf("ingest endpoint status = %+v", endpoint)
	}
}

func TestAdaptiveBatchShrinksAfterPayloadRejection(t *testing.T) {
	var mu sync.Mutex
	batchSizes := make([]int, 0, 2)
	secondBatch := make(chan struct{})
	var secondOnce sync.Once
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/api/ingest" {
			writer.WriteHeader(http.StatusNoContent)
			return
		}
		var events []models.QueryEvent
		if err := decodeJSONBody(request, &events); err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		mu.Lock()
		batchSizes = append(batchSizes, len(events))
		attempt := len(batchSizes)
		mu.Unlock()
		if attempt == 1 {
			writer.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
		secondOnce.Do(func() { close(secondBatch) })
	}))
	defer server.Close()

	forwarder := NewForwarder(resilienceConfig(server.URL, ""))
	forwarder.httpClient = server.Client()
	for index := 0; index < 120; index++ {
		forwarder.EnqueueEvent(models.QueryEvent{Domain: "adaptive.example", Node: "resilient-agent"})
	}
	done := make(chan error, 1)
	go func() { done <- forwarder.Start() }()
	select {
	case <-secondBatch:
	case <-time.After(5 * time.Second):
		forwarder.Stop()
		t.Fatal("adaptive retry was not sent")
	}
	forwarder.Stop()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("forwarder did not stop")
	}
	mu.Lock()
	got := append([]int(nil), batchSizes...)
	mu.Unlock()
	if len(got) < 2 || got[0] != initialForwardBatchSize || got[1] != initialForwardBatchSize/2 {
		t.Fatalf("batch sizes = %v, want prefix [100 50]", got)
	}
}

func TestAdaptiveBatchNeverExceedsControllerLimit(t *testing.T) {
	const eventCount = 225

	var mu sync.Mutex
	batchSizes := make([]int, 0, 3)
	delivered := make(chan struct{})
	var deliveredOnce sync.Once
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/api/ingest" {
			writer.WriteHeader(http.StatusNoContent)
			return
		}
		var events []models.QueryEvent
		if err := decodeJSONBody(request, &events); err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		mu.Lock()
		batchSizes = append(batchSizes, len(events))
		total := 0
		for _, size := range batchSizes {
			total += size
		}
		mu.Unlock()
		writer.WriteHeader(http.StatusNoContent)
		if total >= eventCount {
			deliveredOnce.Do(func() { close(delivered) })
		}
	}))
	defer server.Close()

	forwarder := NewForwarder(resilienceConfig(server.URL, ""))
	forwarder.httpClient = server.Client()
	for range eventCount {
		forwarder.EnqueueEvent(models.QueryEvent{Domain: "bounded.example", Node: "resilient-agent"})
	}
	done := make(chan error, 1)
	go func() { done <- forwarder.Start() }()
	select {
	case <-delivered:
	case <-time.After(5 * time.Second):
		forwarder.Stop()
		t.Fatal("events were not delivered")
	}
	forwarder.Stop()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("forwarder stopped with error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("forwarder did not stop")
	}

	mu.Lock()
	got := append([]int(nil), batchSizes...)
	mu.Unlock()
	for _, size := range got {
		if size > 100 {
			t.Fatalf("batch sizes = %v, controller limit is 100", got)
		}
	}
}

func TestRetryAfterParsingAndResponse(t *testing.T) {
	now := time.Date(2026, time.August, 11, 12, 0, 0, 0, time.UTC)
	if got := parseRetryAfter("17", now); got != 17*time.Second {
		t.Fatalf("delta Retry-After = %s", got)
	}
	if got := parseRetryAfter(now.Add(45*time.Second).Format(http.TimeFormat), now); got != 45*time.Second {
		t.Fatalf("date Retry-After = %s", got)
	}
	if got := parseRetryAfter("999999", now); got != maxRetryAfter {
		t.Fatalf("capped Retry-After = %s", got)
	}

	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Retry-After", "3")
		writer.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()
	forwarder := NewForwarder(resilienceConfig(server.URL, t.TempDir()))
	err := forwarder.sendBatch(server.Client(), testEvents("limited.example"), nil)
	var statusError *responseStatusError
	if !errors.As(err, &statusError) || statusError.status != http.StatusTooManyRequests ||
		statusError.retryAfter != 3*time.Second {
		t.Fatalf("error = %#v", err)
	}
}

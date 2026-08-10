package forwarder

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/arumes31/resolix/webgui/internal/config"
	"github.com/arumes31/resolix/webgui/internal/configsync"
	"github.com/arumes31/resolix/webgui/internal/controllertls"
	"github.com/arumes31/resolix/webgui/internal/models"
)

// Version is set at build time via -ldflags.
var Version = "dev"

type backlogItem struct {
	event models.QueryEvent
	size  int64
}

// Forwarder handles sending batches of query events from agent to controller.
type Forwarder struct {
	cfg              *config.Config
	stopChan         chan struct{}
	stopOnce         sync.Once
	healthOnce       sync.Once
	backlogMu        sync.Mutex
	backlog          []backlogItem
	backlogTotalSize int64
	wakeChan         chan struct{}
	healthReports    chan map[string]float64
	httpClient       *http.Client
	transportErr     error
	retries          atomic.Int64
	dropped          atomic.Int64
	sent             atomic.Int64

	// Sync state (Items 90, 91, 94)
	syncedAliases map[string]string
	syncedRoutes  map[string]string
	syncedHealth  map[string]map[string]float64
	syncMu        sync.RWMutex

	// DNSRoutes and ClientAliases setters for applying synced data
	setDNSRoutesFn      func(routes map[string]string)
	setAliasesFn        func(aliases map[string]string)
	setUpstreamHealthFn func(node string, health map[string]float64)
	setDNSConfigFn      func(snapshot configsync.Snapshot) error
	configRevision      string
}

// NewForwarder creates a new log forwarder for agent nodes.
func NewForwarder(cfg *config.Config) *Forwarder {
	f := &Forwarder{
		stopChan:      make(chan struct{}),
		wakeChan:      make(chan struct{}, 1),
		healthReports: make(chan map[string]float64, 1),
		cfg:           cfg,
		syncedAliases: make(map[string]string),
		syncedRoutes:  make(map[string]string),
		syncedHealth:  make(map[string]map[string]float64),
	}
	if cfg.Mode == config.ModeAgent && cfg.ControllerURL != "" {
		_, f.transportErr = controllerEndpoint(cfg, "/api/sync/dns-config")
	}
	if f.transportErr == nil {
		f.httpClient, f.transportErr = newControllerHTTPClient(cfg)
	}
	return f
}

func newControllerHTTPClient(cfg *config.Config) (*http.Client, error) {
	client := &http.Client{
		Timeout:       10 * time.Second,
		CheckRedirect: rejectControllerRedirect,
	}
	if cfg.Mode != config.ModeAgent || cfg.ControllerURL == "" {
		return client, nil
	}

	switch cfg.ControllerTLSTrust {
	case "", controllertls.TrustSystem:
		return client, nil
	case controllertls.TrustTOFUTailnet:
		transport, err := controllertls.NewTOFUTransport(
			cfg.ControllerURL,
			cfg.FullControllerTLSPinPath(),
		)
		if err != nil {
			return nil, fmt.Errorf("configure tailnet TOFU: %w", err)
		}
		client.Transport = transport
		return client, nil
	default:
		return nil, fmt.Errorf("unsupported controller TLS trust mode %q", cfg.ControllerTLSTrust)
	}
}

func rejectControllerRedirect(_ *http.Request, _ []*http.Request) error {
	return http.ErrUseLastResponse
}

func doControllerRequest(client *http.Client, req *http.Request) (*http.Response, error) {
	if client == nil {
		return nil, errors.New("controller HTTP client is not configured")
	}
	secureClient := *client
	secureClient.CheckRedirect = rejectControllerRedirect
	return secureClient.Do(req)
}

func controllerEndpoint(cfg *config.Config, endpoint string) (string, error) {
	controller, err := url.ParseRequestURI(cfg.ControllerURL)
	if err != nil {
		return "", fmt.Errorf("parse CONTROLLER_URL: %w", err)
	}
	if !strings.EqualFold(controller.Scheme, "https") || controller.Host == "" {
		return "", errors.New("CONTROLLER_URL must use HTTPS")
	}
	if controller.User != nil || controller.RawQuery != "" || controller.Fragment != "" {
		return "", errors.New("CONTROLLER_URL must not contain credentials, a query, or a fragment")
	}
	if cfg.BaseURL != "" && (!strings.HasPrefix(cfg.BaseURL, "/") || strings.ContainsAny(cfg.BaseURL, "?#")) {
		return "", errors.New("BASE_URL must be an absolute path without a query or fragment")
	}
	target := strings.TrimRight(cfg.ControllerURL, "/") + strings.TrimRight(cfg.BaseURL, "/") + endpoint
	parsedTarget, err := url.ParseRequestURI(target)
	if err != nil {
		return "", fmt.Errorf("parse controller endpoint: %w", err)
	}
	if !strings.EqualFold(parsedTarget.Scheme, "https") || parsedTarget.Host != controller.Host {
		return "", errors.New("controller endpoint must remain on the HTTPS controller origin")
	}
	return target, nil
}

func (f *Forwarder) enabled() bool {
	return f.cfg.Mode == config.ModeAgent && f.cfg.ControllerURL != ""
}

// SetDNSRoutesFn sets the callback for applying synced DNS routes (Item 91).
func (f *Forwarder) SetDNSRoutesFn(fn func(routes map[string]string)) {
	f.syncMu.Lock()
	defer f.syncMu.Unlock()
	f.setDNSRoutesFn = fn
}

// SetAliasesFn sets the callback for applying synced client aliases (Item 90).
func (f *Forwarder) SetAliasesFn(fn func(aliases map[string]string)) {
	f.syncMu.Lock()
	defer f.syncMu.Unlock()
	f.setAliasesFn = fn
}

// SetUpstreamHealthFn sets the callback for applying synced upstream health (Item 94).
func (f *Forwarder) SetUpstreamHealthFn(fn func(node string, health map[string]float64)) {
	f.syncMu.Lock()
	defer f.syncMu.Unlock()
	f.setUpstreamHealthFn = fn
}

// SetDNSConfigFn sets the callback that validates and applies a controller snapshot.
func (f *Forwarder) SetDNSConfigFn(fn func(snapshot configsync.Snapshot) error) {
	f.syncMu.Lock()
	defer f.syncMu.Unlock()
	f.setDNSConfigFn = fn
}

// ConfigRevision returns the last successfully applied controller revision.
func (f *Forwarder) ConfigRevision() string {
	f.syncMu.RLock()
	defer f.syncMu.RUnlock()
	return f.configRevision
}

// GetSyncedAliases returns the latest aliases synced from controller (Item 90).
func (f *Forwarder) GetSyncedAliases() map[string]string {
	f.syncMu.RLock()
	defer f.syncMu.RUnlock()
	result := make(map[string]string, len(f.syncedAliases))
	for k, v := range f.syncedAliases {
		result[k] = v
	}
	return result
}

// GetSyncedRoutes returns the latest DNS routes synced from controller (Item 91).
func (f *Forwarder) GetSyncedRoutes() map[string]string {
	f.syncMu.RLock()
	defer f.syncMu.RUnlock()
	result := make(map[string]string, len(f.syncedRoutes))
	for k, v := range f.syncedRoutes {
		result[k] = v
	}
	return result
}

// GetSyncedUpstreamHealth returns the latest upstream health synced from controller (Item 94).
func (f *Forwarder) GetSyncedUpstreamHealth() map[string]map[string]float64 {
	f.syncMu.RLock()
	defer f.syncMu.RUnlock()
	result := make(map[string]map[string]float64, len(f.syncedHealth))
	for node, health := range f.syncedHealth {
		result[node] = make(map[string]float64, len(health))
		for k, v := range health {
			result[node][k] = v
		}
	}
	return result
}

// EnqueueEvent adds a query event to the forwarding queue.
func (f *Forwarder) EnqueueEvent(ev models.QueryEvent) {
	if f.cfg.Mode != config.ModeAgent || f.cfg.ControllerURL == "" {
		return
	}
	if ev.Node == "" {
		ev.Node = f.cfg.NodeName
	}
	item := backlogItem{event: ev, size: eventJSONSize(ev)}
	f.backlogMu.Lock()
	defer f.backlogMu.Unlock()

	// Enforce a maximum backlog size in bytes to prevent OOM (only when limit is configured)
	if f.cfg.MaxBacklogSize > 0 && f.backlogTotalSize+item.size > f.cfg.MaxBacklogSize {
		f.dropped.Add(1)
		return
	}

	f.backlog = append(f.backlog, item)
	f.backlogTotalSize += item.size
	select {
	case f.wakeChan <- struct{}{}:
	default:
	}
}

type responseStatusError struct{ status int }

func (e *responseStatusError) Error() string {
	return fmt.Sprintf("unexpected status code: %d", e.status)
}

func (e *responseStatusError) permanent() bool {
	return e.status >= 400 && e.status < 500 && e.status != http.StatusRequestTimeout && e.status != http.StatusTooManyRequests
}

// eventJSONSize approximates the serialized size of an event for backlog
// byte accounting.
func eventJSONSize(ev models.QueryEvent) int64 {
	data, err := json.Marshal(ev)
	if err != nil {
		return int64(len(ev.Domain) + 64)
	}
	return int64(len(data))
}

// getResourceStats collects current resource usage statistics (Item 93).
func getResourceStats() (memoryMB float64, goroutines int) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	memoryMB = float64(m.Alloc) / 1024 / 1024
	goroutines = runtime.NumGoroutine()
	return memoryMB, goroutines
}

// getDBSizeMB returns the size of the database file in megabytes.
func getDBSizeMB(cfg *config.Config) float64 {
	dbPath := cfg.FullDBPath()
	if info, err := os.Stat(dbPath); err == nil {
		return float64(info.Size()) / 1024 / 1024
	}
	return 0
}

// setVersionHeaders adds version information headers to the request (Item 88).
func setVersionHeaders(req *http.Request) {
	req.Header.Set("X-Node-Version", Version)
	req.Header.Set("X-Go-Version", runtime.Version())
	req.Header.Set("X-Node-Build", fmt.Sprintf("%s/%s", Version, runtime.Version()))
}

// gzipCompress compresses data with gzip. Returns the compressed data and true
// if compression was beneficial (smaller than original), or nil and false if
// compression failed or made the data larger.
func gzipCompress(data []byte) ([]byte, bool) {
	var buf bytes.Buffer
	gzWriter := gzip.NewWriter(&buf)
	if _, err := gzWriter.Write(data); err != nil {
		return nil, false
	}
	if err := gzWriter.Close(); err != nil {
		return nil, false
	}
	compressed := buf.Bytes()
	if len(compressed) >= len(data) {
		// Compression didn't help; send uncompressed
		return nil, false
	}
	return compressed, true
}

// sendBatch sends a batch of query events to the controller with gzip
// compression (Item 85). Events are sent as a top-level JSON array (the new
// ingest format); health-only payloads keep the legacy object shape.
func (f *Forwarder) sendBatch(client *http.Client, events []models.QueryEvent, health map[string]float64) error {
	var data []byte
	var err error
	if len(events) > 0 {
		data, err = json.Marshal(events)
	} else {
		payload := map[string]interface{}{"node": f.cfg.NodeName}
		if len(health) > 0 {
			payload["health"] = health
		}
		data, err = json.Marshal(payload)
	}
	if err != nil {
		return err
	}

	// Item 85: Attempt gzip compression; fall back to uncompressed if not beneficial
	var bodyReader io.Reader = bytes.NewBuffer(data)
	compressed, useGzip := gzipCompress(data)
	if useGzip {
		bodyReader = bytes.NewBuffer(compressed)
	}

	req, err := http.NewRequest("POST", f.cfg.ControllerURL+f.cfg.BaseURL+"/api/ingest", bodyReader)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	// Set Content-Encoding if we compressed
	if useGzip {
		req.Header.Set("Content-Encoding", "gzip")
	}

	// Item 88: Set version headers
	setVersionHeaders(req)

	if f.cfg.IngestSecret != "" {
		req.Header.Set("Authorization", "Bearer "+f.cfg.IngestSecret)
	}

	resp, err := doControllerRequest(client, req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &responseStatusError{status: resp.StatusCode}
	}
	return nil
}

// sendHeartbeat sends a heartbeat to the controller node (Item 92).
func (f *Forwarder) sendHeartbeat(client *http.Client, health map[string]float64) error {
	memoryMB, goroutines := getResourceStats()
	dbSizeMB := getDBSizeMB(f.cfg)

	hb := models.HeartbeatPayload{
		Node:           f.cfg.NodeName,
		Version:        Version,
		GoVersion:      runtime.Version(),
		BuildInfo:      fmt.Sprintf("%s/%s", Version, runtime.Version()),
		MemoryMB:       memoryMB,
		Goroutines:     goroutines,
		DBSizeMB:       dbSizeMB,
		Health:         health,
		ConfigRevision: f.ConfigRevision(),
	}

	data, err := json.Marshal(hb)
	if err != nil {
		return err
	}

	// Item 85: Attempt gzip compression; fall back to uncompressed if not beneficial
	var bodyReader io.Reader = bytes.NewBuffer(data)
	compressed, useGzip := gzipCompress(data)
	if useGzip {
		bodyReader = bytes.NewBuffer(compressed)
	}

	req, err := http.NewRequest("POST", f.cfg.ControllerURL+f.cfg.BaseURL+"/api/heartbeat", bodyReader)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if useGzip {
		req.Header.Set("Content-Encoding", "gzip")
	}

	// Item 88: Set version headers
	setVersionHeaders(req)

	if f.cfg.IngestSecret != "" {
		req.Header.Set("Authorization", "Bearer "+f.cfg.IngestSecret)
	}

	resp, err := doControllerRequest(client, req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("heartbeat unexpected status code: %d", resp.StatusCode)
	}
	return nil
}

// syncFromController fetches configuration data from the controller (Items 90, 91, 94).
func (f *Forwarder) syncFromController(client *http.Client, endpoint string) ([]byte, error) {
	requestURL, err := controllerEndpoint(f.cfg, endpoint)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("GET", requestURL, nil)
	if err != nil {
		return nil, err
	}

	// Item 88: Set version headers
	setVersionHeaders(req)

	if f.cfg.IngestSecret != "" {
		req.Header.Set("Authorization", "Bearer "+f.cfg.IngestSecret)
	}
	req.Header.Set("Accept-Encoding", "gzip")

	resp, err := doControllerRequest(client, req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("sync %s: unexpected status code %d", endpoint, resp.StatusCode)
	}

	var reader io.Reader = resp.Body
	if resp.Header.Get("Content-Encoding") == "gzip" {
		gzReader, err := gzip.NewReader(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("gzip decompress error: %w", err)
		}
		defer func() { _ = gzReader.Close() }()
		reader = gzReader
	}

	maxResponseSize := f.cfg.MaxRequestSize
	if maxResponseSize <= 0 {
		maxResponseSize = config.DefaultMaxRequestSize
	}
	data, err := io.ReadAll(io.LimitReader(reader, maxResponseSize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxResponseSize {
		return nil, fmt.Errorf("sync %s: response exceeds %d bytes", endpoint, maxResponseSize)
	}
	return data, nil
}

// syncAliases fetches and applies client aliases from controller (Item 90).
func (f *Forwarder) syncAliases(client *http.Client) {
	data, err := f.syncFromController(client, "/api/sync/aliases")
	if err != nil {
		log.Printf("[WARN] Failed to sync aliases from controller: %v", err)
		return
	}

	var result map[string]string
	if err := json.Unmarshal(data, &result); err != nil {
		log.Printf("[WARN] Failed to parse aliases sync response: %v", err)
		return
	}

	f.syncMu.Lock()
	f.syncedAliases = result
	fn := f.setAliasesFn
	f.syncMu.Unlock()

	if fn != nil {
		fn(result)
	}

	log.Printf("[INFO] Synced %d client aliases from controller", len(result))
}

// syncDNSRoutes fetches and applies DNS routes from controller (Item 91).
func (f *Forwarder) syncDNSRoutes(client *http.Client) {
	data, err := f.syncFromController(client, "/api/sync/dns-routes")
	if err != nil {
		log.Printf("[WARN] Failed to sync DNS routes from controller: %v", err)
		return
	}

	var result struct {
		Routes map[string]string `json:"routes"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		log.Printf("[WARN] Failed to parse DNS routes sync response: %v", err)
		return
	}

	f.syncMu.Lock()
	f.syncedRoutes = result.Routes
	fn := f.setDNSRoutesFn
	f.syncMu.Unlock()

	if fn != nil {
		fn(result.Routes)
	}

	log.Printf("[INFO] Synced %d DNS routes from controller", len(result.Routes))
}

// syncUpstreamHealth fetches and applies upstream health from controller (Item 94).
func (f *Forwarder) syncUpstreamHealth(client *http.Client) {
	data, err := f.syncFromController(client, "/api/sync/upstream-health")
	if err != nil {
		log.Printf("[WARN] Failed to sync upstream health from controller: %v", err)
		return
	}

	var result map[string]map[string]float64
	if err := json.Unmarshal(data, &result); err != nil {
		log.Printf("[WARN] Failed to parse upstream health sync response: %v", err)
		return
	}

	f.syncMu.Lock()
	f.syncedHealth = result
	fn := f.setUpstreamHealthFn
	f.syncMu.Unlock()

	if fn != nil {
		for node, health := range result {
			fn(node, health)
		}
	}

	totalUpstreams := 0
	for _, health := range result {
		totalUpstreams += len(health)
	}
	log.Printf("[INFO] Synced upstream health for %d nodes (%d upstreams) from controller", len(result), totalUpstreams)
}

func (f *Forwarder) syncDNSConfig(client *http.Client) {
	data, err := f.syncFromController(client, "/api/sync/dns-config")
	if err != nil {
		log.Printf("[WARN] Failed to sync DNS configuration from controller: %v", err)
		return
	}
	var snapshot configsync.Snapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		log.Printf("[WARN] Failed to parse DNS configuration snapshot: %v", err)
		return
	}
	validRevision, err := snapshot.ValidRevision()
	if err != nil {
		log.Printf("[WARN] Failed to validate DNS configuration snapshot revision: %v", err)
		return
	}
	if !validRevision {
		log.Printf("[WARN] Rejected DNS configuration snapshot with invalid revision")
		return
	}
	f.syncMu.RLock()
	currentRevision := f.configRevision
	apply := f.setDNSConfigFn
	f.syncMu.RUnlock()
	if snapshot.Revision == currentRevision {
		return
	}
	if apply == nil {
		log.Printf("[WARN] DNS configuration sync callback is not configured")
		return
	}
	if err := apply(snapshot); err != nil {
		log.Printf("[WARN] Failed to apply DNS configuration revision: %v", err)
		return
	}
	f.syncMu.Lock()
	f.configRevision = snapshot.Revision
	f.syncMu.Unlock()
	log.Printf("[INFO] Applied DNS configuration revision %.12s", snapshot.Revision)
}

// calculateBackoff computes the backoff duration with exponential growth and jitter (Item 86).
// Sequence: initial, 2x, 4x, 8x, 16x, 30s (capped) with 0-500ms random jitter.
// A non-positive initial interval falls back to 1s, preserving the original progression.
func calculateBackoff(attempt int, initial time.Duration) time.Duration {
	if initial <= 0 {
		initial = 1 * time.Second
	}
	if attempt <= 0 {
		return initial
	}
	if attempt > 6 {
		attempt = 6
	}
	backoff := initial * (1 << uint(attempt-1)) // initial * 2^(attempt-1)
	if backoff > 30*time.Second {
		backoff = 30 * time.Second
	}
	// Add jitter: 0-500ms (crypto/rand; falls back to no jitter on error)
	jitter := time.Duration(0)
	if n, err := rand.Int(rand.Reader, big.NewInt(500)); err == nil {
		jitter = time.Duration(n.Int64()) * time.Millisecond
	}
	return backoff + jitter
}

// safeInterval returns the duration if positive, otherwise the fallback.
func safeInterval(d, fallback time.Duration) time.Duration {
	if d > 0 {
		return d
	}
	return fallback
}

// Start begins the forwarding worker loop with heartbeat and sync goroutines.
func (f *Forwarder) Start() error {
	if !f.enabled() {
		return nil
	}
	if f.transportErr != nil {
		return fmt.Errorf("configure controller transport: %w", f.transportErr)
	}
	client := f.httpClient
	backoffAttempt := 0

	var draining bool
	var drainEnd time.Time

	// Item 92: Start heartbeat goroutine
	go f.startHeartbeat(client)

	// Items 90, 91, 94: Start sync goroutines
	go f.startSyncLoops(client)
	f.ensureHealthReporter(client)

	for {
		if !draining {
			select {
			case <-f.stopChan:
				draining = true
				drainEnd = time.Now().Add(5 * time.Second)
			default:
			}
		}

		if draining && time.Now().After(drainEnd) {
			return nil
		}

		f.backlogMu.Lock()
		if len(f.backlog) == 0 {
			f.backlogMu.Unlock()
			if draining {
				return nil
			}
			select {
			case <-f.wakeChan:
			case <-f.stopChan:
				draining = true
				drainEnd = time.Now().Add(5 * time.Second)
			}
			continue
		}
		batchSize := 100
		if len(f.backlog) < batchSize {
			batchSize = len(f.backlog)
		}
		items := append([]backlogItem(nil), f.backlog[:batchSize]...)
		events := make([]models.QueryEvent, len(items))
		for i, item := range items {
			events[i] = item.event
			f.backlogTotalSize -= item.size
		}
		f.backlog = f.backlog[batchSize:]
		f.backlogMu.Unlock()

		err := f.sendBatch(client, events, nil)
		if err == nil {
			log.Printf("Successfully sent batch of %d events to controller", len(events))
			backoffAttempt = 0 // Reset on success (Item 86)
			f.sent.Add(int64(len(events)))
		} else {
			log.Printf("Error sending batch to controller: %v", err)

			var statusErr *responseStatusError
			if errors.As(err, &statusErr) && statusErr.permanent() {
				log.Printf("[WARN] Controller rejected batch permanently with HTTP %d; dropping %d events", statusErr.status, len(events))
				f.dropped.Add(int64(len(events)))
				backoffAttempt = 0
				continue
			}

			// Item 86: Check max retry attempts
			if f.cfg.MaxRetryAttempts > 0 && backoffAttempt >= f.cfg.MaxRetryAttempts {
				log.Printf("[WARN] Max retry attempts (%d) reached, dropping batch of %d events", f.cfg.MaxRetryAttempts, len(events))
				backoffAttempt = 0
				f.dropped.Add(int64(len(events)))
				continue
			}

			f.requeueBatch(items)

			backoffAttempt++
			f.retries.Add(1)
			// Item 80: use the configured initial retry interval (falls back to 1s when unset/invalid)
			waitDur := calculateBackoff(backoffAttempt, safeInterval(f.cfg.ForwarderRetryInterval, time.Second))

			if draining {
				rem := time.Until(drainEnd)
				if rem <= 0 {
					return nil
				}
				if rem < waitDur {
					waitDur = rem
				}
			}

			if draining {
				time.Sleep(waitDur)
			} else {
				select {
				case <-time.After(waitDur):
				case <-f.stopChan:
					draining = true
					drainEnd = time.Now().Add(5 * time.Second)
				}
			}
		}
	}
}

// requeueBatch prepends a failed batch back onto the backlog, honoring the
// configured byte limit (the newest overflow events are dropped).
func (f *Forwarder) requeueBatch(items []backlogItem) {
	f.backlogMu.Lock()
	defer f.backlogMu.Unlock()

	if f.cfg.MaxBacklogSize <= 0 {
		f.backlog = append(items, f.backlog...)
		for _, item := range items {
			f.backlogTotalSize += item.size
		}
		return
	}

	// Re-queue only what fits within the byte limit; drop the oldest overflow
	kept := 0
	for _, item := range items {
		if f.backlogTotalSize+item.size > f.cfg.MaxBacklogSize {
			break
		}
		kept++
		f.backlogTotalSize += item.size
	}
	if kept < len(items) {
		log.Printf("[WARN] Backlog byte limit (%d) reached, dropping %d newest events of failed batch", f.cfg.MaxBacklogSize, len(items)-kept)
	}
	f.dropped.Add(int64(len(items) - kept))
	f.backlog = append(items[:kept:kept], f.backlog...)
}

// startHeartbeat sends periodic heartbeats to the controller (Item 92).
func (f *Forwarder) startHeartbeat(client *http.Client) {
	interval := safeInterval(f.cfg.HeartbeatInterval, config.DefaultHeartbeatInterval)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Send initial heartbeat immediately
	memoryMB, goroutines := getResourceStats()
	dbSizeMB := getDBSizeMB(f.cfg)
	hb := models.HeartbeatPayload{
		Node:           f.cfg.NodeName,
		Version:        Version,
		GoVersion:      runtime.Version(),
		BuildInfo:      fmt.Sprintf("%s/%s", Version, runtime.Version()),
		MemoryMB:       memoryMB,
		Goroutines:     goroutines,
		DBSizeMB:       dbSizeMB,
		ConfigRevision: f.ConfigRevision(),
	}
	if err := f.sendHeartbeat(client, hb.Health); err != nil {
		log.Printf("[WARN] Initial heartbeat failed: %v", err)
	} else {
		log.Printf("[INFO] Initial heartbeat sent to controller")
	}

	for {
		select {
		case <-f.stopChan:
			return
		case <-ticker.C:
			if err := f.sendHeartbeat(client, nil); err != nil {
				log.Printf("[WARN] Heartbeat failed: %v", err)
			}
		}
	}
}

// startSyncLoops runs periodic sync operations for aliases, DNS routes,
// controller-owned DNS configuration, and upstream health.
func (f *Forwarder) startSyncLoops(client *http.Client) {
	// Item 90: Sync client aliases
	aliasesInterval := safeInterval(f.cfg.SyncAliasesInterval, config.DefaultSyncAliasesInterval)
	aliasesTicker := time.NewTicker(aliasesInterval)
	defer aliasesTicker.Stop()

	// Item 91: Sync DNS routes
	routesInterval := safeInterval(f.cfg.SyncDNSRoutesInterval, config.DefaultSyncDNSRoutesInterval)
	routesTicker := time.NewTicker(routesInterval)
	defer routesTicker.Stop()

	// Item 94: Sync upstream health
	healthInterval := safeInterval(f.cfg.SyncUpstreamHealthInterval, config.DefaultSyncUpstreamHealthInterval)
	healthTicker := time.NewTicker(healthInterval)
	defer healthTicker.Stop()

	// Initial sync
	f.syncAliases(client)
	f.syncDNSRoutes(client)
	f.syncUpstreamHealth(client)
	f.syncDNSConfig(client)

	for {
		select {
		case <-f.stopChan:
			return
		case <-aliasesTicker.C:
			f.syncAliases(client)
		case <-routesTicker.C:
			f.syncDNSRoutes(client)
			f.syncDNSConfig(client)
		case <-healthTicker.C:
			f.syncUpstreamHealth(client)
		}
	}
}

// ReportHealth sends a health update to the controller.
func (f *Forwarder) ReportHealth(health map[string]float64) {
	if !f.enabled() || f.transportErr != nil {
		return
	}
	f.ensureHealthReporter(f.httpClient)
	copyHealth := make(map[string]float64, len(health))
	for key, value := range health {
		copyHealth[key] = value
	}
	select {
	case f.healthReports <- copyHealth:
	default:
		select {
		case <-f.healthReports:
		default:
		}
		select {
		case f.healthReports <- copyHealth:
		default:
		}
	}
}

func (f *Forwarder) ensureHealthReporter(client *http.Client) {
	f.healthOnce.Do(func() { go f.startHealthReporter(client) })
}

func (f *Forwarder) startHealthReporter(client *http.Client) {
	for {
		select {
		case <-f.stopChan:
			return
		case health := <-f.healthReports:
			if err := f.sendBatch(client, nil, health); err != nil {
				log.Printf("Error reporting health to controller: %v", err)
			}
		}
	}
}

// Stats returns the current forwarding queue and delivery counters.
func (f *Forwarder) Stats() (backlog int, backlogBytes, retries, dropped, sent int64) {
	f.backlogMu.Lock()
	backlog = len(f.backlog)
	backlogBytes = f.backlogTotalSize
	f.backlogMu.Unlock()
	return backlog, backlogBytes, f.retries.Load(), f.dropped.Load(), f.sent.Load()
}

// Stop cleanly shuts down the forwarder
func (f *Forwarder) Stop() {
	f.stopOnce.Do(func() {
		close(f.stopChan)
		if f.httpClient != nil {
			f.httpClient.CloseIdleConnections()
		}
	})
}

package forwarder

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"runtime"
	"sync"
	"time"

	"tailscale-dnsrewrite/webgui/internal/config"
	"tailscale-dnsrewrite/webgui/internal/models"
)

// Version is set at build time via -ldflags.
var Version = "dev"

// Forwarder handles sending batches of logs from slave to master.
type Forwarder struct {
	cfg              *config.Config
	stopChan         chan struct{}
	stopOnce         sync.Once
	backlogMu        sync.Mutex
	backlog          []string
	backlogTotalSize int64

	// Sync state (Items 90, 91, 94)
	syncedAliases map[string]string
	syncedRoutes  map[string]string
	syncedHealth  map[string]map[string]float64
	syncMu        sync.RWMutex

	// DNSRoutes and ClientAliases setters for applying synced data
	setDNSRoutesFn      func(routes map[string]string)
	setAliasesFn        func(aliases map[string]string)
	setUpstreamHealthFn func(node string, health map[string]float64)
}

// NewForwarder creates a new log forwarder for slave nodes.
func NewForwarder(cfg *config.Config) *Forwarder {
	return &Forwarder{
		stopChan:      make(chan struct{}),
		cfg:           cfg,
		syncedAliases: make(map[string]string),
		syncedRoutes:  make(map[string]string),
		syncedHealth:  make(map[string]map[string]float64),
	}
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

// GetSyncedAliases returns the latest aliases synced from master (Item 90).
func (f *Forwarder) GetSyncedAliases() map[string]string {
	f.syncMu.RLock()
	defer f.syncMu.RUnlock()
	result := make(map[string]string, len(f.syncedAliases))
	for k, v := range f.syncedAliases {
		result[k] = v
	}
	return result
}

// GetSyncedRoutes returns the latest DNS routes synced from master (Item 91).
func (f *Forwarder) GetSyncedRoutes() map[string]string {
	f.syncMu.RLock()
	defer f.syncMu.RUnlock()
	result := make(map[string]string, len(f.syncedRoutes))
	for k, v := range f.syncedRoutes {
		result[k] = v
	}
	return result
}

// GetSyncedUpstreamHealth returns the latest upstream health synced from master (Item 94).
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

// Enqueue adds a log line to the forwarding queue.
func (f *Forwarder) Enqueue(line string) {
	if f.cfg.Mode != "slave" || f.cfg.MasterURL == "" {
		return
	}
	f.backlogMu.Lock()
	defer f.backlogMu.Unlock()

	// Enforce a maximum backlog size to prevent OOM (only when limit is configured)
	if f.cfg.MaxBacklogSize > 0 && f.backlogTotalSize >= f.cfg.MaxBacklogSize {
		return
	}

	f.backlog = append(f.backlog, line)
	f.backlogTotalSize += int64(len(line))
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

// sendBatch sends a batch of log lines to the master with gzip compression (Item 85).
func (f *Forwarder) sendBatch(client *http.Client, lines []string, health map[string]float64) error {
	payload := map[string]interface{}{"node": f.cfg.NodeName}
	if len(lines) > 0 {
		payload["batch"] = lines
	}
	if len(health) > 0 {
		payload["health"] = health
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	// Item 85: Attempt gzip compression; fall back to uncompressed if not beneficial
	var bodyReader io.Reader = bytes.NewBuffer(data)
	compressed, useGzip := gzipCompress(data)
	if useGzip {
		bodyReader = bytes.NewBuffer(compressed)
	}

	req, err := http.NewRequest("POST", f.cfg.MasterURL+f.cfg.BaseURL+"/api/ingest", bodyReader)
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

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
	return nil
}

// sendHeartbeat sends a heartbeat to the master node (Item 92).
func (f *Forwarder) sendHeartbeat(client *http.Client, health map[string]float64) error {
	memoryMB, goroutines := getResourceStats()
	dbSizeMB := getDBSizeMB(f.cfg)

	hb := models.HeartbeatPayload{
		Node:       f.cfg.NodeName,
		Version:    Version,
		GoVersion:  runtime.Version(),
		BuildInfo:  fmt.Sprintf("%s/%s", Version, runtime.Version()),
		MemoryMB:   memoryMB,
		Goroutines: goroutines,
		DBSizeMB:   dbSizeMB,
		Health:     health,
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

	req, err := http.NewRequest("POST", f.cfg.MasterURL+f.cfg.BaseURL+"/api/heartbeat", bodyReader)
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

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("heartbeat unexpected status code: %d", resp.StatusCode)
	}
	return nil
}

// syncFromMaster fetches configuration data from the master (Items 90, 91, 94).
func (f *Forwarder) syncFromMaster(client *http.Client, endpoint string) ([]byte, error) {
	req, err := http.NewRequest("GET", f.cfg.MasterURL+f.cfg.BaseURL+endpoint, nil)
	if err != nil {
		return nil, err
	}

	// Item 88: Set version headers
	setVersionHeaders(req)

	if f.cfg.IngestSecret != "" {
		req.Header.Set("Authorization", "Bearer "+f.cfg.IngestSecret)
	}
	req.Header.Set("Accept-Encoding", "gzip")

	resp, err := client.Do(req)
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

// syncAliases fetches and applies client aliases from master (Item 90).
func (f *Forwarder) syncAliases(client *http.Client) {
	data, err := f.syncFromMaster(client, "/api/sync/aliases")
	if err != nil {
		log.Printf("[WARN] Failed to sync aliases from master: %v", err)
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

	log.Printf("[INFO] Synced %d client aliases from master", len(result))
}

// syncDNSRoutes fetches and applies DNS routes from master (Item 91).
func (f *Forwarder) syncDNSRoutes(client *http.Client) {
	data, err := f.syncFromMaster(client, "/api/sync/dns-routes")
	if err != nil {
		log.Printf("[WARN] Failed to sync DNS routes from master: %v", err)
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

	log.Printf("[INFO] Synced %d DNS routes from master", len(result.Routes))
}

// syncUpstreamHealth fetches and applies upstream health from master (Item 94).
func (f *Forwarder) syncUpstreamHealth(client *http.Client) {
	data, err := f.syncFromMaster(client, "/api/sync/upstream-health")
	if err != nil {
		log.Printf("[WARN] Failed to sync upstream health from master: %v", err)
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
	log.Printf("[INFO] Synced upstream health for %d nodes (%d upstreams) from master", len(result), totalUpstreams)
}

// calculateBackoff computes the backoff duration with exponential growth and jitter (Item 86).
// Sequence: 1s, 2s, 4s, 8s, 16s, 30s (capped) with 0-500ms random jitter.
func calculateBackoff(attempt int) time.Duration {
	if attempt <= 0 {
		return 1 * time.Second
	}
	if attempt > 6 {
		attempt = 6
	}
	seconds := 1 << uint(attempt-1) // 2^(attempt-1)
	if seconds > 30 {
		seconds = 30
	}
	backoff := time.Duration(seconds) * time.Second
	// Add jitter: 0-500ms
	jitter := time.Duration(rand.Intn(500)) * time.Millisecond
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
	if f.cfg.Mode != "slave" || f.cfg.MasterURL == "" {
		return nil
	}
	client := &http.Client{Timeout: 10 * time.Second}
	backoffAttempt := 0

	var draining bool
	var drainEnd time.Time

	// Item 92: Start heartbeat goroutine
	go f.startHeartbeat(client)

	// Items 90, 91, 94: Start sync goroutines
	go f.startSyncLoops(client)

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
			case <-time.After(100 * time.Millisecond):
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
		lines := append([]string(nil), f.backlog[:batchSize]...)

		for i := 0; i < len(lines); i++ {
			f.backlogTotalSize -= int64(len(f.backlog[i]))
		}
		f.backlog = f.backlog[batchSize:]
		f.backlogMu.Unlock()

		err := f.sendBatch(client, lines, nil)
		if err == nil {
			log.Printf("Successfully sent batch of %d lines to master", len(lines))
			backoffAttempt = 0 // Reset on success (Item 86)
		} else {
			log.Printf("Error sending batch to master: %v", err)

			// Item 86: Check max retry attempts
			if f.cfg.MaxRetryAttempts > 0 && backoffAttempt >= f.cfg.MaxRetryAttempts {
				log.Printf("[WARN] Max retry attempts (%d) reached, dropping batch of %d lines", f.cfg.MaxRetryAttempts, len(lines))
				backoffAttempt = 0
				continue
			}

			f.backlogMu.Lock()
			f.backlog = append(lines, f.backlog...)
			for i := 0; i < len(lines); i++ {
				f.backlogTotalSize += int64(len(lines[i]))
			}
			f.backlogMu.Unlock()

			backoffAttempt++
			waitDur := calculateBackoff(backoffAttempt)

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

// startHeartbeat sends periodic heartbeats to the master (Item 92).
func (f *Forwarder) startHeartbeat(client *http.Client) {
	interval := safeInterval(f.cfg.HeartbeatInterval, config.DefaultHeartbeatInterval)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Send initial heartbeat immediately
	memoryMB, goroutines := getResourceStats()
	dbSizeMB := getDBSizeMB(f.cfg)
	hb := models.HeartbeatPayload{
		Node:       f.cfg.NodeName,
		Version:    Version,
		GoVersion:  runtime.Version(),
		BuildInfo:  fmt.Sprintf("%s/%s", Version, runtime.Version()),
		MemoryMB:   memoryMB,
		Goroutines: goroutines,
		DBSizeMB:   dbSizeMB,
	}
	if err := f.sendHeartbeat(client, hb.Health); err != nil {
		log.Printf("[WARN] Initial heartbeat failed: %v", err)
	} else {
		log.Printf("[INFO] Initial heartbeat sent to master")
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

// startSyncLoops runs periodic sync operations for aliases, DNS routes, and upstream health.
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

	for {
		select {
		case <-f.stopChan:
			return
		case <-aliasesTicker.C:
			f.syncAliases(client)
		case <-routesTicker.C:
			f.syncDNSRoutes(client)
		case <-healthTicker.C:
			f.syncUpstreamHealth(client)
		}
	}
}

// ReportHealth sends a health update to the master.
func (f *Forwarder) ReportHealth(health map[string]float64) {
	if f.cfg.Mode != "slave" || f.cfg.MasterURL == "" {
		return
	}
	// Send health reports asynchronously to avoid blocking the health checker
	go func() {
		client := &http.Client{Timeout: 5 * time.Second}
		if err := f.sendBatch(client, nil, health); err != nil {
			log.Printf("Error reporting health to master: %v", err)
		}
	}()
}

// Stop cleanly shuts down the forwarder
func (f *Forwarder) Stop() {
	f.stopOnce.Do(func() {
		close(f.stopChan)
	})
}

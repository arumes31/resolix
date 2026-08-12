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
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/arumes31/resolix/webgui/internal/config"
	"github.com/arumes31/resolix/webgui/internal/configsync"
	"github.com/arumes31/resolix/webgui/internal/models"
)

type responseStatusError struct {
	status     int
	retryAfter time.Duration
}

func (e *responseStatusError) Error() string {
	return fmt.Sprintf("unexpected status code: %d", e.status)
}

func (e *responseStatusError) permanent() bool {
	return e.status >= 400 && e.status < 500 &&
		e.status != http.StatusRequestTimeout &&
		e.status != http.StatusTooManyRequests &&
		e.status != http.StatusRequestEntityTooLarge
}

func parseRetryAfter(value string, now time.Time) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil {
		if seconds <= 0 {
			return 0
		}
		return min(time.Duration(seconds)*time.Second, maxRetryAfter)
	}
	when, err := http.ParseTime(value)
	if err != nil || !when.After(now) {
		return 0
	}
	return min(when.Sub(now), maxRetryAfter)
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

func (f *Forwarder) setNodeHeaders(req *http.Request) {
	setVersionHeaders(req)
	if f.cfg.NodeID != "" {
		req.Header.Set("X-Node-ID", f.cfg.NodeID)
	}
}

func sanitizeDiagnostic(value string, cfg *config.Config) string {
	if cfg != nil {
		for _, privateValue := range []string{
			cfg.IngestSecret, cfg.ControllerURL, cfg.HistoryDir, cfg.ConfigDir, cfg.TLSStateDir,
		} {
			if privateValue != "" {
				value = strings.ReplaceAll(value, privateValue, "<redacted>")
			}
		}
	}
	value = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, value)
	value = strings.Join(strings.Fields(value), " ")
	const maxDiagnosticBytes = 256
	if len(value) > maxDiagnosticBytes {
		value = value[:maxDiagnosticBytes] + "..."
	}
	return value
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
func (f *Forwarder) sendBatch(client *http.Client, events []models.QueryEvent, health map[string]float64) (resultErr error) {
	started := time.Now()
	defer func() { f.recordEndpoint("ingest", started, resultErr) }()
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

	requestURL, err := controllerEndpoint(f.cfg, "/api/ingest")
	if err != nil {
		return err
	}
	req, err := http.NewRequest("POST", requestURL, bodyReader)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	// Set Content-Encoding if we compressed
	if useGzip {
		req.Header.Set("Content-Encoding", "gzip")
	}

	// Item 88: Set version headers
	f.setNodeHeaders(req)

	if f.cfg.IngestSecret != "" {
		req.Header.Set("Authorization", "Bearer "+f.cfg.IngestSecret)
	}

	resp, err := doControllerRequest(client, req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	f.recordControllerDate(resp.Header, time.Now())

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &responseStatusError{
			status:     resp.StatusCode,
			retryAfter: parseRetryAfter(resp.Header.Get("Retry-After"), time.Now()),
		}
	}
	return nil
}

// sendHeartbeat sends a heartbeat to the controller node (Item 92).
func (f *Forwarder) sendHeartbeat(client *http.Client, health map[string]float64) (resultErr error) {
	started := time.Now()
	defer func() { f.recordEndpoint("heartbeat", started, resultErr) }()
	memoryMB, goroutines := getResourceStats()
	dbSizeMB := getDBSizeMB(f.cfg)
	syncStatus := f.SnapshotStatus(started)
	endpointErrors := make(map[string]string)
	for endpoint, status := range syncStatus.Endpoints {
		if status.LastError != "" {
			endpointErrors[endpoint] = status.LastError
		}
	}

	hb := models.HeartbeatPayload{
		NodeID:                  f.cfg.NodeID,
		Node:                    f.cfg.NodeName,
		SentAt:                  started,
		Version:                 Version,
		GoVersion:               runtime.Version(),
		BuildInfo:               fmt.Sprintf("%s/%s", Version, runtime.Version()),
		MemoryMB:                memoryMB,
		Goroutines:              goroutines,
		DBSizeMB:                dbSizeMB,
		Health:                  health,
		ConfigRevision:          syncStatus.AppliedRevision,
		DesiredConfigRevision:   syncStatus.DesiredRevision,
		PreviousConfigRevision:  syncStatus.PreviousRevision,
		ConfigSchemaVersion:     syncStatus.SchemaVersion,
		ConfigSchemaCompatible:  syncStatus.SchemaCompatible,
		ConfigApplyError:        syncStatus.LastApplyError,
		ConfigApplyDurationMS:   syncStatus.LastApplyDuration.Milliseconds(),
		ForwarderBacklogDepth:   syncStatus.BacklogDepth,
		ForwarderBacklogBytes:   syncStatus.BacklogBytes,
		ForwarderBacklogOldestS: syncStatus.BacklogOldestAge.Seconds(),
		ForwarderEndpointErrors: endpointErrors,
		LastIngestError:         endpointErrors["ingest"],
		LastHeartbeatError:      endpointErrors["heartbeat"],
		LastConfigSyncError:     endpointErrors["sync:dns-config"],
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

	requestURL, err := controllerEndpoint(f.cfg, "/api/heartbeat")
	if err != nil {
		return err
	}
	req, err := http.NewRequest("POST", requestURL, bodyReader)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if useGzip {
		req.Header.Set("Content-Encoding", "gzip")
	}

	// Item 88: Set version headers
	f.setNodeHeaders(req)

	if f.cfg.IngestSecret != "" {
		req.Header.Set("Authorization", "Bearer "+f.cfg.IngestSecret)
	}

	resp, err := doControllerRequest(client, req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	f.recordControllerDate(resp.Header, time.Now())
	if generation := resp.Header.Get("X-Config-Sync-Generation"); generation != "" {
		f.syncMu.Lock()
		changed := generation != f.lastSyncGeneration
		f.lastSyncGeneration = generation
		f.syncMu.Unlock()
		if changed {
			f.SyncNow()
		}
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("heartbeat unexpected status code: %d", resp.StatusCode)
	}
	return nil
}

// syncFromController fetches configuration data from the controller (Items 90, 91, 94).
func (f *Forwarder) syncFromController(client *http.Client, endpoint string) (data []byte, resultErr error) {
	started := time.Now()
	endpointName := "sync:" + strings.TrimPrefix(endpoint, "/api/sync/")
	defer func() { f.recordEndpoint(endpointName, started, resultErr) }()
	requestURL, err := controllerEndpoint(f.cfg, endpoint)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("GET", requestURL, nil)
	if err != nil {
		return nil, err
	}

	// Item 88: Set version headers
	f.setNodeHeaders(req)

	if f.cfg.IngestSecret != "" {
		req.Header.Set("Authorization", "Bearer "+f.cfg.IngestSecret)
	}
	req.Header.Set("Accept-Encoding", "gzip")

	resp, err := doControllerRequest(client, req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	f.recordControllerDate(resp.Header, time.Now())

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
	data, err = io.ReadAll(io.LimitReader(reader, maxResponseSize+1))
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
	started := time.Now()
	data, err := f.syncFromController(client, "/api/sync/aliases")
	if err != nil {
		log.Printf("[WARN] Failed to sync aliases from controller: %v", err)
		return
	}

	var result map[string]string
	if err := json.Unmarshal(data, &result); err != nil {
		f.recordEndpoint("sync:aliases", started, err)
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
	f.recordEndpoint("sync:aliases", started, nil)

	log.Printf("[INFO] Synced %d client aliases from controller", len(result))
}

// syncDNSRoutes fetches and applies DNS routes from controller (Item 91).
func (f *Forwarder) syncDNSRoutes(client *http.Client) {
	started := time.Now()
	data, err := f.syncFromController(client, "/api/sync/dns-routes")
	if err != nil {
		log.Printf("[WARN] Failed to sync DNS routes from controller: %v", err)
		return
	}

	var result struct {
		Routes map[string]string `json:"routes"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		f.recordEndpoint("sync:dns-routes", started, err)
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
	f.recordEndpoint("sync:dns-routes", started, nil)

	log.Printf("[INFO] Synced %d DNS routes from controller", len(result.Routes))
}

// syncUpstreamHealth fetches and applies upstream health from controller (Item 94).
func (f *Forwarder) syncUpstreamHealth(client *http.Client) {
	started := time.Now()
	data, err := f.syncFromController(client, "/api/sync/upstream-health")
	if err != nil {
		log.Printf("[WARN] Failed to sync upstream health from controller: %v", err)
		return
	}

	var result map[string]map[string]float64
	if err := json.Unmarshal(data, &result); err != nil {
		f.recordEndpoint("sync:upstream-health", started, err)
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
	f.recordEndpoint("sync:upstream-health", started, nil)

	totalUpstreams := 0
	for _, health := range result {
		totalUpstreams += len(health)
	}
	log.Printf("[INFO] Synced upstream health for %d nodes (%d upstreams) from controller", len(result), totalUpstreams)
}

func (f *Forwarder) syncDNSConfig(client *http.Client) {
	started := time.Now()
	data, err := f.syncFromController(client, "/api/sync/dns-config")
	if err != nil {
		log.Printf("[WARN] Failed to sync DNS configuration from controller: %v", err)
		return
	}
	var snapshot configsync.Snapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		f.recordEndpoint("sync:dns-config", started, err)
		log.Printf("[WARN] Failed to parse DNS configuration snapshot: %v", err)
		return
	}
	f.syncMu.Lock()
	f.desiredRevision = snapshot.Revision
	f.configSchemaVersion = snapshot.Version
	f.configCompatible = snapshot.SchemaCompatible()
	f.syncMu.Unlock()
	if err := snapshot.Validate(); err != nil {
		f.recordConfigApply(snapshot, 0, err)
		f.recordEndpoint("sync:dns-config", started, err)
		log.Printf("[WARN] Rejected DNS configuration snapshot: %v", err)
		return
	}
	f.syncMu.RLock()
	currentRevision := f.configRevision
	apply := f.setDNSConfigFn
	f.syncMu.RUnlock()
	if snapshot.Revision == currentRevision {
		f.recordEndpoint("sync:dns-config", started, nil)
		return
	}
	if apply == nil {
		err := errors.New("DNS configuration sync callback is not configured")
		f.recordConfigApply(snapshot, 0, err)
		f.recordEndpoint("sync:dns-config", started, err)
		log.Printf("[WARN] %v", err)
		return
	}
	applyStarted := time.Now()
	if err := apply(snapshot); err != nil {
		f.recordConfigApply(snapshot, time.Since(applyStarted), err)
		f.recordEndpoint("sync:dns-config", started, err)
		log.Printf("[WARN] Failed to apply DNS configuration revision: %v", err)
		return
	}
	f.syncMu.Lock()
	if f.appliedSnapshot != nil {
		previous := f.appliedSnapshot.Clone()
		f.previousSnapshot = &previous
	}
	applied := snapshot.Clone()
	f.appliedSnapshot = &applied
	f.configRevision = snapshot.Revision
	f.lastConfigApplyErr = ""
	f.lastConfigApplyTime = time.Since(applyStarted)
	f.syncMu.Unlock()
	f.recordEndpoint("sync:dns-config", started, nil)
	log.Printf("[INFO] Applied DNS configuration revision %.12s", snapshot.Revision)
}

func (f *Forwarder) recordConfigApply(snapshot configsync.Snapshot, duration time.Duration, err error) {
	f.syncMu.Lock()
	f.desiredRevision = snapshot.Revision
	f.configSchemaVersion = snapshot.Version
	f.configCompatible = snapshot.SchemaCompatible()
	f.lastConfigApplyTime = duration
	if err == nil {
		f.lastConfigApplyErr = ""
	} else {
		f.lastConfigApplyErr = sanitizeDiagnostic(err.Error(), f.cfg)
	}
	f.syncMu.Unlock()
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

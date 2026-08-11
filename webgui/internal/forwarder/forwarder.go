package forwarder

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
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
	event    models.QueryEvent
	size     int64
	queuedAt time.Time
}

type persistedBacklogItem struct {
	Event    models.QueryEvent `json:"event"`
	QueuedAt time.Time         `json:"queued_at"`
}

type persistedBacklog struct {
	Version int                    `json:"version"`
	Items   []persistedBacklogItem `json:"items"`
}

const (
	initialForwardBatchSize = 100
	minForwardBatchSize     = 10
	maxForwardBatchSize     = 500
	maxRetryAfter           = 10 * time.Minute
	backlogStateFile        = "forwarder-backlog.json"
	backlogStateVersion     = 1
	nodeIdentityFile        = "node-id"
)

// EndpointStatus describes the latest attempt made against one controller
// endpoint without exposing credentials or response bodies.
type EndpointStatus struct {
	LastAttempt time.Time `json:"last_attempt,omitempty"`
	LastSuccess time.Time `json:"last_success,omitempty"`
	LastError   string    `json:"last_error,omitempty"`
}

// Status is a point-in-time view of forwarding and configuration-sync state.
type Status struct {
	BacklogDepth          int                       `json:"backlog_depth"`
	BacklogBytes          int64                     `json:"backlog_bytes"`
	BacklogOldestAge      time.Duration             `json:"backlog_oldest_age"`
	Retries               int64                     `json:"retries"`
	Dropped               int64                     `json:"dropped"`
	Sent                  int64                     `json:"sent"`
	AdaptiveBatchSize     int                       `json:"adaptive_batch_size"`
	DesiredRevision       string                    `json:"desired_revision,omitempty"`
	AppliedRevision       string                    `json:"applied_revision,omitempty"`
	PreviousRevision      string                    `json:"previous_revision,omitempty"`
	SchemaVersion         int                       `json:"schema_version,omitempty"`
	SchemaCompatible      bool                      `json:"schema_compatible"`
	LastApplyError        string                    `json:"last_apply_error,omitempty"`
	LastApplyDuration     time.Duration             `json:"last_apply_duration"`
	ControllerClockSkew   time.Duration             `json:"controller_clock_skew"`
	PersistentBacklogPath string                    `json:"persistent_backlog_path,omitempty"`
	Endpoints             map[string]EndpointStatus `json:"endpoints"`
}

// Forwarder handles sending batches of query events from agent to controller.
type Forwarder struct {
	cfg              *config.Config
	stopChan         chan struct{}
	stopOnce         sync.Once
	healthOnce       sync.Once
	backlogMu        sync.Mutex
	backlog          []backlogItem
	inFlight         []backlogItem
	backlogTotalSize int64
	wakeChan         chan struct{}
	persistWake      chan struct{}
	persistMu        sync.Mutex
	healthReports    chan map[string]float64
	httpClient       *http.Client
	transportErr     error
	retries          atomic.Int64
	dropped          atomic.Int64
	sent             atomic.Int64
	adaptiveBatch    atomic.Int64
	clockSkewNanos   atomic.Int64

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
	desiredRevision     string
	appliedSnapshot     *configsync.Snapshot
	previousSnapshot    *configsync.Snapshot
	configSchemaVersion int
	configCompatible    bool
	lastConfigApplyErr  string
	lastConfigApplyTime time.Duration
	endpointStatus      map[string]EndpointStatus
	lastSyncGeneration  string
	syncNow             chan struct{}
}

// NewForwarder creates a new log forwarder for agent nodes.
func NewForwarder(cfg *config.Config) *Forwarder {
	ensureNodeIdentity(cfg)
	f := &Forwarder{
		stopChan:       make(chan struct{}),
		wakeChan:       make(chan struct{}, 1),
		persistWake:    make(chan struct{}, 1),
		healthReports:  make(chan map[string]float64, 1),
		syncNow:        make(chan struct{}, 1),
		cfg:            cfg,
		syncedAliases:  make(map[string]string),
		syncedRoutes:   make(map[string]string),
		syncedHealth:   make(map[string]map[string]float64),
		endpointStatus: make(map[string]EndpointStatus),
	}
	f.adaptiveBatch.Store(initialForwardBatchSize)
	if cfg.Mode == config.ModeAgent && cfg.ControllerURL != "" {
		_, f.transportErr = controllerEndpoint(cfg, "/api/sync/dns-config")
	}
	if f.transportErr == nil {
		f.httpClient, f.transportErr = newControllerHTTPClient(cfg)
	}
	if f.enabled() {
		f.loadBacklog()
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

// SyncNow asks the running agent to immediately refresh every controller-owned
// configuration endpoint. Repeated requests are coalesced.
func (f *Forwarder) SyncNow() bool {
	if !f.enabled() || f.transportErr != nil {
		return false
	}
	select {
	case f.syncNow <- struct{}{}:
		return true
	default:
		return true
	}
}

// PreviousConfigSnapshot returns the last working snapshot retained before a
// newer revision was applied.
func (f *Forwarder) PreviousConfigSnapshot() (configsync.Snapshot, bool) {
	f.syncMu.RLock()
	defer f.syncMu.RUnlock()
	if f.previousSnapshot == nil {
		return configsync.Snapshot{}, false
	}
	return f.previousSnapshot.Clone(), true
}

// SnapshotStatus returns forwarding and sync diagnostics for status APIs and
// metrics collectors.
func (f *Forwarder) SnapshotStatus(now time.Time) Status {
	f.backlogMu.Lock()
	depth := len(f.backlog) + len(f.inFlight)
	backlogBytes := f.backlogTotalSize
	oldest := time.Time{}
	for _, items := range [][]backlogItem{f.inFlight, f.backlog} {
		for _, item := range items {
			if oldest.IsZero() || item.queuedAt.Before(oldest) {
				oldest = item.queuedAt
			}
		}
	}
	f.backlogMu.Unlock()

	f.syncMu.RLock()
	endpoints := make(map[string]EndpointStatus, len(f.endpointStatus))
	for endpoint, status := range f.endpointStatus {
		endpoints[endpoint] = status
	}
	status := Status{
		BacklogDepth:          depth,
		BacklogBytes:          backlogBytes,
		Retries:               f.retries.Load(),
		Dropped:               f.dropped.Load(),
		Sent:                  f.sent.Load(),
		AdaptiveBatchSize:     int(f.adaptiveBatch.Load()),
		DesiredRevision:       f.desiredRevision,
		AppliedRevision:       f.configRevision,
		SchemaVersion:         f.configSchemaVersion,
		SchemaCompatible:      f.configCompatible,
		LastApplyError:        f.lastConfigApplyErr,
		LastApplyDuration:     f.lastConfigApplyTime,
		ControllerClockSkew:   time.Duration(f.clockSkewNanos.Load()),
		PersistentBacklogPath: f.backlogPath(),
		Endpoints:             endpoints,
	}
	if f.previousSnapshot != nil {
		status.PreviousRevision = f.previousSnapshot.Revision
	}
	f.syncMu.RUnlock()
	if !oldest.IsZero() && now.After(oldest) {
		status.BacklogOldestAge = now.Sub(oldest)
	}
	return status
}

func (f *Forwarder) recordEndpoint(endpoint string, started time.Time, err error) {
	f.syncMu.Lock()
	status := f.endpointStatus[endpoint]
	status.LastAttempt = started
	if err == nil {
		status.LastSuccess = time.Now()
		status.LastError = ""
	} else {
		status.LastError = sanitizeDiagnostic(err.Error(), f.cfg)
	}
	f.endpointStatus[endpoint] = status
	f.syncMu.Unlock()
}

func (f *Forwarder) recordControllerDate(header http.Header, receivedAt time.Time) {
	serverTime, err := http.ParseTime(header.Get("Date"))
	if err != nil {
		return
	}
	f.clockSkewNanos.Store(receivedAt.Sub(serverTime).Nanoseconds())
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

func (f *Forwarder) backlogPath() string {
	if f.cfg == nil || strings.TrimSpace(f.cfg.HistoryDir) == "" {
		return ""
	}
	return filepath.Join(f.cfg.HistoryDir, backlogStateFile)
}

func ensureNodeIdentity(cfg *config.Config) {
	if cfg == nil {
		return
	}
	if identity := strings.TrimSpace(cfg.NodeID); validNodeIdentity(identity) {
		cfg.NodeID = identity
		return
	}
	path := ""
	if strings.TrimSpace(cfg.HistoryDir) != "" {
		path = filepath.Join(cfg.HistoryDir, nodeIdentityFile)
		if data, err := os.ReadFile(path); err == nil { // #nosec G304 -- path is inside the configured state directory
			if identity := strings.TrimSpace(string(data)); validNodeIdentity(identity) {
				cfg.NodeID = identity
				_ = os.Chmod(path, 0o600)
				return
			}
		}
	}
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		log.Printf("[WARN] Generate stable node identity: %v", err)
		return
	}
	identity := "node-" + hex.EncodeToString(buffer)
	cfg.NodeID = identity
	if path == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		log.Printf("[WARN] Persist stable node identity: %v", err)
		return
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".node-id-*.tmp")
	if err != nil {
		log.Printf("[WARN] Persist stable node identity: %v", err)
		return
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
	err = temporary.Chmod(0o600)
	if err == nil {
		_, err = temporary.WriteString(identity + "\n")
	}
	if err == nil {
		err = temporary.Sync()
	}
	if closeErr := temporary.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(temporaryPath, path)
	}
	if err != nil {
		log.Printf("[WARN] Persist stable node identity: %v", err)
	}
}

func validNodeIdentity(identity string) bool {
	if identity == "" || len(identity) > 128 {
		return false
	}
	for _, r := range identity {
		letter := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
		digit := r >= '0' && r <= '9'
		if !letter && !digit && !strings.ContainsRune("._:-", r) {
			return false
		}
	}
	return true
}

func (f *Forwarder) loadBacklog() {
	path := f.backlogPath()
	if path == "" {
		return
	}
	info, err := os.Lstat(path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("[WARN] Inspect persistent forwarder backlog: %v", err)
		}
		return
	}
	if !info.Mode().IsRegular() {
		log.Printf("[WARN] Ignoring non-regular persistent forwarder backlog at %s", path)
		return
	}
	maxBytes := f.cfg.MaxBacklogSize
	if maxBytes <= 0 {
		maxBytes = config.DefaultMaxBacklogSize
	}
	file, err := os.Open(path) // #nosec G304 -- path is inside the trusted history directory
	if err != nil {
		log.Printf("[WARN] Open persistent forwarder backlog: %v", err)
		return
	}
	defer func() { _ = file.Close() }()
	openedInfo, err := file.Stat()
	if err != nil || !os.SameFile(info, openedInfo) || info.Size() != openedInfo.Size() ||
		info.Mode() != openedInfo.Mode() || !info.ModTime().Equal(openedInfo.ModTime()) {
		log.Printf("[WARN] Persistent forwarder backlog changed while opening; ignoring it")
		return
	}
	_ = os.Chmod(path, 0o600)
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1024*1024+1))
	if err != nil {
		log.Printf("[WARN] Read persistent forwarder backlog: %v", err)
		return
	}
	if int64(len(data)) > maxBytes+1024*1024 {
		f.quarantineBacklog(path, "exceeds configured limit")
		return
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return
	}
	persisted, err := decodePersistedBacklog(data)
	if err != nil {
		f.quarantineBacklog(path, "invalid or unsupported data")
		return
	}
	now := time.Now()
	for _, saved := range persisted {
		queuedAt := saved.QueuedAt
		if queuedAt.IsZero() || queuedAt.After(now.Add(time.Minute)) {
			queuedAt = now
		}
		item := backlogItem{event: saved.Event, size: eventJSONSize(saved.Event), queuedAt: queuedAt}
		if f.cfg.MaxBacklogSize > 0 && f.backlogTotalSize+item.size > f.cfg.MaxBacklogSize {
			f.dropped.Add(1)
			continue
		}
		f.backlog = append(f.backlog, item)
		f.backlogTotalSize += item.size
	}
	if len(f.backlog) > 0 {
		log.Printf("[INFO] Restored %d events from the persistent forwarder backlog", len(f.backlog))
		select {
		case f.wakeChan <- struct{}{}:
		default:
		}
	}
}

func decodePersistedBacklog(data []byte) ([]persistedBacklogItem, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		var legacy []persistedBacklogItem
		return legacy, json.Unmarshal(trimmed, &legacy)
	}
	var state persistedBacklog
	if err := json.Unmarshal(trimmed, &state); err != nil {
		return nil, err
	}
	if state.Version != backlogStateVersion {
		return nil, fmt.Errorf("unsupported backlog version %d", state.Version)
	}
	return state.Items, nil
}

func (f *Forwarder) quarantineBacklog(path, reason string) {
	quarantine := fmt.Sprintf("%s.corrupt-%d", path, time.Now().Unix())
	if err := os.Rename(path, quarantine); err != nil {
		log.Printf("[WARN] Ignore persistent forwarder backlog (%s); quarantine failed: %v", reason, err)
		return
	}
	_ = os.Chmod(quarantine, 0o600)
	log.Printf("[WARN] Quarantined persistent forwarder backlog (%s)", reason)
}

func (f *Forwarder) signalBacklogPersistence() {
	if f.backlogPath() == "" {
		return
	}
	select {
	case f.persistWake <- struct{}{}:
	default:
	}
}

func (f *Forwarder) runBacklogPersistence() {
	for {
		select {
		case <-f.stopChan:
			if err := f.flushBacklog(); err != nil {
				log.Printf("[WARN] Persist forwarder backlog during shutdown: %v", err)
			}
			return
		case <-f.persistWake:
			timer := time.NewTimer(250 * time.Millisecond)
			select {
			case <-f.stopChan:
				if !timer.Stop() {
					<-timer.C
				}
			case <-timer.C:
			}
			if err := f.flushBacklog(); err != nil {
				log.Printf("[WARN] Persist forwarder backlog: %v", err)
			}
		}
	}
}

func (f *Forwarder) flushBacklog() error {
	f.persistMu.Lock()
	defer f.persistMu.Unlock()
	path := f.backlogPath()
	if path == "" {
		return nil
	}
	f.backlogMu.Lock()
	defer f.backlogMu.Unlock()
	items := make([]backlogItem, 0, len(f.inFlight)+len(f.backlog))
	items = append(items, f.inFlight...)
	items = append(items, f.backlog...)
	persisted := make([]persistedBacklogItem, len(items))
	for i, item := range items {
		persisted[i] = persistedBacklogItem{Event: item.event, QueuedAt: item.queuedAt}
	}
	data, err := json.Marshal(persistedBacklog{Version: backlogStateVersion, Items: persisted})
	if err != nil {
		return fmt.Errorf("marshal forwarder backlog: %w", err)
	}
	maxBytes := f.cfg.MaxBacklogSize
	if maxBytes <= 0 {
		maxBytes = config.DefaultMaxBacklogSize
	}
	trimmed := 0
	for int64(len(data)) > maxBytes && trimmed < len(f.backlog) {
		trimmed++
		bounded := make([]persistedBacklogItem, 0, len(persisted)-trimmed)
		bounded = append(bounded, persisted[:len(f.inFlight)]...)
		bounded = append(bounded, persisted[len(f.inFlight)+trimmed:]...)
		data, err = json.Marshal(persistedBacklog{Version: backlogStateVersion, Items: bounded})
		if err != nil {
			return fmt.Errorf("marshal bounded forwarder backlog: %w", err)
		}
	}
	if int64(len(data)) > maxBytes {
		return fmt.Errorf("configured backlog limit %d is too small for state metadata", maxBytes)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("create forwarder backlog directory: %w", err)
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".forwarder-backlog-*.tmp")
	if err != nil {
		return fmt.Errorf("create forwarder backlog temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("secure forwarder backlog temporary file: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write forwarder backlog temporary file: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync forwarder backlog temporary file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close forwarder backlog temporary file: %w", err)
	}
	if err := replaceBacklogFile(temporaryPath, path); err != nil {
		return fmt.Errorf("publish forwarder backlog: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("secure published forwarder backlog: %w", err)
	}
	if trimmed > 0 {
		for _, item := range f.backlog[:trimmed] {
			f.backlogTotalSize -= item.size
		}
		f.backlog = f.backlog[trimmed:]
		f.dropped.Add(int64(trimmed))
		log.Printf("[WARN] Dropped %d oldest queued event(s) to keep the persistent forwarder backlog within %d bytes", trimmed, maxBytes)
	}
	return nil
}

// EnqueueEvent adds a query event to the forwarding queue.
func (f *Forwarder) EnqueueEvent(ev models.QueryEvent) {
	if f.cfg.Mode != config.ModeAgent || f.cfg.ControllerURL == "" {
		return
	}
	if ev.Node == "" {
		ev.Node = f.cfg.NodeName
	}
	item := backlogItem{event: ev, size: eventJSONSize(ev), queuedAt: time.Now()}
	f.backlogMu.Lock()

	// Enforce a maximum backlog size in bytes to prevent OOM (only when limit is configured)
	if f.cfg.MaxBacklogSize > 0 && f.backlogTotalSize+item.size > f.cfg.MaxBacklogSize {
		f.dropped.Add(1)
		f.backlogMu.Unlock()
		return
	}

	f.backlog = append(f.backlog, item)
	f.backlogTotalSize += item.size
	f.backlogMu.Unlock()
	f.signalBacklogPersistence()
	select {
	case f.wakeChan <- struct{}{}:
	default:
	}
}

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
		f.recordConfigApply(snapshot, 0, err)
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

// Start begins the forwarding worker loop with heartbeat and sync goroutines.
//
//nolint:gocyclo // Delivery, adaptive retry, graceful drain, and persistence share one state-machine loop.
func (f *Forwarder) Start() error {
	if !f.enabled() {
		return nil
	}
	if f.transportErr != nil {
		return fmt.Errorf("configure controller transport: %w", f.transportErr)
	}
	client := f.httpClient
	backoffAttempt := 0
	go f.runBacklogPersistence()
	defer func() {
		if err := f.flushBacklog(); err != nil {
			log.Printf("[WARN] Persist final forwarder backlog: %v", err)
		}
	}()

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
		batchSize := int(f.adaptiveBatch.Load())
		batchSize = min(max(batchSize, minForwardBatchSize), maxForwardBatchSize)
		if len(f.backlog) < batchSize {
			batchSize = len(f.backlog)
		}
		items := append([]backlogItem(nil), f.backlog[:batchSize]...)
		events := make([]models.QueryEvent, len(items))
		for i, item := range items {
			events[i] = item.event
		}
		f.backlog = f.backlog[batchSize:]
		f.inFlight = items
		f.backlogMu.Unlock()

		err := f.sendBatch(client, events, nil)
		if err == nil {
			log.Printf("Successfully sent batch of %d events to controller", len(events))
			backoffAttempt = 0 // Reset on success (Item 86)
			f.sent.Add(int64(len(events)))
			f.finishInFlight(false)
			if len(events) >= batchSize {
				f.adaptiveBatch.Store(int64(min(maxForwardBatchSize, batchSize+25)))
			}
		} else {
			log.Printf("Error sending batch to controller: %v", err)

			var statusErr *responseStatusError
			if errors.As(err, &statusErr) && statusErr.permanent() {
				log.Printf("[WARN] Controller rejected batch permanently with HTTP %d; dropping %d events", statusErr.status, len(events))
				f.dropped.Add(int64(len(events)))
				f.finishInFlight(false)
				backoffAttempt = 0
				continue
			}

			// Item 86: Check max retry attempts
			if f.cfg.MaxRetryAttempts > 0 && backoffAttempt >= f.cfg.MaxRetryAttempts {
				log.Printf("[WARN] Max retry attempts (%d) reached, dropping batch of %d events", f.cfg.MaxRetryAttempts, len(events))
				backoffAttempt = 0
				f.dropped.Add(int64(len(events)))
				f.finishInFlight(false)
				continue
			}

			f.requeueBatch(items)
			if errors.As(err, &statusErr) &&
				(statusErr.status == http.StatusRequestEntityTooLarge || statusErr.status == http.StatusTooManyRequests) {
				f.adaptiveBatch.Store(int64(max(minForwardBatchSize, batchSize/2)))
			}

			backoffAttempt++
			f.retries.Add(1)
			// Item 80: use the configured initial retry interval (falls back to 1s when unset/invalid)
			waitDur := calculateBackoff(backoffAttempt, safeInterval(f.cfg.ForwarderRetryInterval, time.Second))
			if statusErr != nil && statusErr.retryAfter > waitDur {
				waitDur = statusErr.retryAfter
			}

			if draining {
				rem := time.Until(drainEnd)
				if rem <= 0 {
					return nil
				}
				if rem < waitDur {
					waitDur = rem
				}
			}

			retryTimer := time.NewTimer(waitDur)
			if draining {
				<-retryTimer.C
			} else {
				select {
				case <-retryTimer.C:
				case <-f.stopChan:
					if !retryTimer.Stop() {
						select {
						case <-retryTimer.C:
						default:
						}
					}
					draining = true
					drainEnd = time.Now().Add(5 * time.Second)
				}
			}
		}
	}
}

// requeueBatch prepends a failed in-flight batch. Its bytes remained counted
// while the request was active, so concurrent enqueue operations could not
// overrun the configured limit.
func (f *Forwarder) requeueBatch(items []backlogItem) {
	f.backlogMu.Lock()
	f.inFlight = nil
	f.backlog = append(items, f.backlog...)
	f.backlogMu.Unlock()
	f.signalBacklogPersistence()
}

func (f *Forwarder) finishInFlight(requeue bool) {
	f.backlogMu.Lock()
	items := f.inFlight
	f.inFlight = nil
	if requeue {
		f.backlog = append(items, f.backlog...)
	} else {
		for _, item := range items {
			f.backlogTotalSize -= item.size
		}
	}
	f.backlogMu.Unlock()
	f.signalBacklogPersistence()
}

// startHeartbeat sends periodic heartbeats to the controller (Item 92).
func (f *Forwarder) startHeartbeat(client *http.Client) {
	interval := safeInterval(f.cfg.HeartbeatInterval, config.DefaultHeartbeatInterval)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Send initial heartbeat immediately.
	if err := f.sendHeartbeat(client, nil); err != nil {
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

	// Initial sync.
	f.syncAll(client)

	for {
		select {
		case <-f.stopChan:
			return
		case <-f.syncNow:
			f.syncAll(client)
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

func (f *Forwarder) syncAll(client *http.Client) {
	f.syncAliases(client)
	f.syncDNSRoutes(client)
	f.syncUpstreamHealth(client)
	f.syncDNSConfig(client)
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
	backlog = len(f.backlog) + len(f.inFlight)
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

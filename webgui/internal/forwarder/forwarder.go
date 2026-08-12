package forwarder

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/arumes31/resolix/webgui/internal/config"
	"github.com/arumes31/resolix/webgui/internal/configsync"
	"github.com/arumes31/resolix/webgui/internal/controllertls"
	"github.com/arumes31/resolix/webgui/internal/magicdns"
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
	setMagicDNSFn       func(snapshot magicdns.Snapshot) error
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

// SetMagicDNSFn sets the callback that applies controller-generated MagicDNS records.
func (f *Forwarder) SetMagicDNSFn(fn func(snapshot magicdns.Snapshot) error) {
	f.syncMu.Lock()
	defer f.syncMu.Unlock()
	f.setMagicDNSFn = fn
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

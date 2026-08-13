package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/arumes31/resolix/webgui/internal/config"
	"github.com/arumes31/resolix/webgui/internal/models"
	"github.com/arumes31/resolix/webgui/internal/storage"
)

const dashboardSchemaVersion = 1

type dashboardRangePreset struct {
	key      string
	label    string
	duration time.Duration
	bucket   time.Duration
}

type dashboardRangeMetadata struct {
	Key              string    `json:"key"`
	Label            string    `json:"label"`
	RequestedStart   time.Time `json:"requested_start"`
	Start            time.Time `json:"start"`
	End              time.Time `json:"end"`
	WindowSeconds    int64     `json:"window_seconds"`
	BucketSeconds    int64     `json:"bucket_seconds"`
	AvailableSeconds int64     `json:"available_seconds"`
	RetentionLimited bool      `json:"retention_limited"`
}

type dashboardFilteringStatus struct {
	Configured     bool       `json:"configured"`
	Enabled        bool       `json:"enabled"`
	State          string     `json:"state"`
	SourceCount    int        `json:"source_count"`
	HealthySources int        `json:"healthy_sources"`
	SourceErrors   int        `json:"source_errors"`
	BlockRules     int        `json:"block_rules"`
	AllowRules     int        `json:"allow_rules"`
	BlockedTotal   int64      `json:"blocked_total"`
	AllowedTotal   int64      `json:"allowed_total"`
	LastUpdated    *time.Time `json:"last_updated,omitempty"`
	PausedUntil    *time.Time `json:"paused_until,omitempty"`
}

type dashboardComparison struct {
	Available        bool                      `json:"available"`
	RetentionLimited bool                      `json:"retention_limited"`
	Start            time.Time                 `json:"start"`
	End              time.Time                 `json:"end"`
	Summary          *storage.DashboardSummary `json:"summary,omitempty"`
}

type dashboardRuntime struct {
	Version     string   `json:"version"`
	Role        string   `json:"role"`
	OnlineNodes int      `json:"online_nodes"`
	TotalNodes  int      `json:"total_nodes"`
	VersionSkew bool     `json:"version_skew"`
	SkewedNodes []string `json:"skewed_nodes"`
}

type dashboardBreakdowns struct {
	TopDomains        []models.StatEntry `json:"top_domains"`
	TopClients        []models.StatEntry `json:"top_clients"`
	TopBlockedDomains []models.StatEntry `json:"top_blocked_domains"`
	TypeCounts        map[string]int     `json:"type_counts"`
	NodeTotals        map[string]int     `json:"node_totals"`
	ResponseCodes     map[string]int     `json:"response_codes"`
}

type dashboardV1Response struct {
	SchemaVersion     int                             `json:"schema_version"`
	GeneratedAt       time.Time                       `json:"generated_at"`
	Range             dashboardRangeMetadata          `json:"range"`
	Summary           storage.DashboardSummary        `json:"summary"`
	Comparison        dashboardComparison             `json:"comparison"`
	Runtime           dashboardRuntime                `json:"runtime"`
	Series            []storage.DashboardSeriesPoint  `json:"series"`
	Breakdowns        dashboardBreakdowns             `json:"breakdowns"`
	Filtering         dashboardFilteringStatus        `json:"filtering"`
	UpstreamHealth    map[string]map[string]float64   `json:"upstream_health"`
	UpstreamHistory   map[string]map[string][]float64 `json:"upstream_health_history"`
	UpstreamNodeNames map[string]string               `json:"upstream_node_names"`
	Degraded          bool                            `json:"degraded"`
	Errors            []string                        `json:"errors"`
}

type statsCacheEntry struct {
	body []byte
	at   time.Time
}

var dashboardRangePresets = map[string]dashboardRangePreset{
	"15m": {key: "15m", label: "Last 15 minutes", duration: 15 * time.Minute, bucket: time.Minute},
	"1h":  {key: "1h", label: "Last hour", duration: time.Hour, bucket: 5 * time.Minute},
	"6h":  {key: "6h", label: "Last 6 hours", duration: 6 * time.Hour, bucket: 15 * time.Minute},
	"24h": {key: "24h", label: "Last 24 hours", duration: 24 * time.Hour, bucket: time.Hour},
	"7d":  {key: "7d", label: "Last 7 days", duration: 7 * 24 * time.Hour, bucket: 6 * time.Hour},
	"30d": {key: "30d", label: "Last 30 days", duration: 30 * 24 * time.Hour, bucket: 24 * time.Hour},
}

func (s *Server) handleDashboardV1Stats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	preset, ok := dashboardRangePresets[strings.TrimSpace(r.URL.Query().Get("range"))]
	if r.URL.Query().Get("range") == "" {
		preset = dashboardRangePresets["24h"]
		ok = true
	}
	if !ok {
		http.Error(w, "invalid range; use 15m, 1h, 6h, 24h, 7d, or 30d", http.StatusBadRequest)
		return
	}

	body, err := s.dashboardV1Response(r.Context(), preset, time.Now())
	if err != nil {
		log.Printf("Dashboard v1 response error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(body)
}

func (s *Server) dashboardV1Response(
	ctx context.Context,
	preset dashboardRangePreset,
	now time.Time,
) ([]byte, error) {
	return s.cachedDashboardResponse(ctx, preset.key, now, func(ctx context.Context) ([]byte, error) {
		return s.buildDashboardV1Response(ctx, preset, now)
	})
}

func (s *Server) cachedDashboardResponse(
	ctx context.Context,
	key string,
	now time.Time,
	build func(context.Context) ([]byte, error),
) ([]byte, error) {
	if body, ok := s.cachedDashboardBody(key, now); ok {
		return body, nil
	}

	rangeLock := s.dashboardRangeLock(key)
	rangeLock.Lock()
	defer rangeLock.Unlock()
	if body, ok := s.cachedDashboardBody(key, now); ok {
		return body, nil
	}

	s.dashboardCacheMu.RLock()
	epoch := s.dashboardCacheEpoch
	s.dashboardCacheMu.RUnlock()
	body, err := build(ctx)
	if err != nil {
		return nil, err
	}

	s.dashboardCacheMu.Lock()
	if epoch == s.dashboardCacheEpoch {
		if s.dashboardCache == nil {
			s.dashboardCache = make(map[string]statsCacheEntry)
		}
		s.dashboardCache[key] = statsCacheEntry{body: body, at: now}
	}
	s.dashboardCacheMu.Unlock()
	return body, nil
}

func (s *Server) cachedDashboardBody(key string, now time.Time) ([]byte, bool) {
	s.dashboardCacheMu.RLock()
	defer s.dashboardCacheMu.RUnlock()
	cached, ok := s.dashboardCache[key]
	if !ok {
		return nil, false
	}
	age := now.Sub(cached.at)
	if len(cached.body) == 0 || age < 0 || age >= dashboardResponseTTL {
		return nil, false
	}
	return cached.body, true
}

func (s *Server) dashboardRangeLock(key string) *sync.Mutex {
	s.dashboardCacheMu.Lock()
	defer s.dashboardCacheMu.Unlock()
	if s.dashboardRangeLocks == nil {
		s.dashboardRangeLocks = make(map[string]*sync.Mutex)
	}
	if rangeLock := s.dashboardRangeLocks[key]; rangeLock != nil {
		return rangeLock
	}
	rangeLock := &sync.Mutex{}
	s.dashboardRangeLocks[key] = rangeLock
	return rangeLock
}

func (s *Server) buildDashboardV1Response(
	ctx context.Context,
	preset dashboardRangePreset,
	now time.Time,
) ([]byte, error) {
	if s.store == nil {
		return nil, fmt.Errorf("dashboard store is unavailable")
	}

	requestedStart := now.Add(-preset.duration)
	retention := s.cfg.HistoryRetention
	if retention <= 0 {
		retention = config.DefaultHistoryRetention
	}
	start := requestedStart
	availableStart := now.Add(-retention)
	retentionLimited := requestedStart.Before(availableStart)
	if retentionLimited {
		start = availableStart
	}

	comparisonStart := requestedStart.Add(-preset.duration)
	comparisonAvailable := !comparisonStart.Before(availableStart) && !retentionLimited
	var previousStart *time.Time
	if comparisonAvailable {
		previousStart = &comparisonStart
	}
	stats, err := s.store.GetDashboardStatsWithComparison(ctx, start, now, preset.bucket, previousStart)
	if err != nil {
		return nil, fmt.Errorf("collect dashboard stats: %w", err)
	}
	upstreamHealth, upstreamHistory := s.store.UpstreamHealthSnapshot()
	upstreamNodeNames := make(map[string]string)
	for _, node := range s.store.GetNodeStatuses() {
		identity := strings.TrimSpace(node.ID)
		name := strings.TrimSpace(node.Name)
		if identity != "" && name != "" {
			upstreamNodeNames[identity] = name
		}
	}
	filtering := s.dashboardFilteringStatus()
	errorsList := append([]string{}, stats.Errors...)
	if !filtering.Enabled {
		errorsList = appendUniqueString(errorsList, "filtering_paused")
	}
	if filtering.SourceErrors > 0 {
		errorsList = appendUniqueString(errorsList, "filter_sources")
	}
	sort.Strings(errorsList)

	response := dashboardV1Response{
		SchemaVersion: dashboardSchemaVersion,
		GeneratedAt:   now.UTC(),
		Range: dashboardRangeMetadata{
			Key:              preset.key,
			Label:            preset.label,
			RequestedStart:   requestedStart.UTC(),
			Start:            start.UTC(),
			End:              now.UTC(),
			WindowSeconds:    int64(preset.duration.Seconds()),
			BucketSeconds:    int64(preset.bucket.Seconds()),
			AvailableSeconds: int64(retention.Seconds()),
			RetentionLimited: retentionLimited,
		},
		Summary: stats.Summary,
		Comparison: dashboardComparison{
			Available:        comparisonAvailable && !stats.Degraded,
			RetentionLimited: !comparisonAvailable,
			Start:            comparisonStart.UTC(),
			End:              requestedStart.UTC(),
		},
		Runtime: s.dashboardRuntime(),
		Series:  stats.Series,
		Breakdowns: dashboardBreakdowns{
			TopDomains:        stats.TopDomains,
			TopClients:        stats.TopClients,
			TopBlockedDomains: stats.TopBlockedDomains,
			TypeCounts:        stats.TypeCounts,
			NodeTotals:        stats.NodeTotals,
			ResponseCodes:     stats.ResponseCodes,
		},
		Filtering:         filtering,
		UpstreamHealth:    upstreamHealth,
		UpstreamHistory:   upstreamHistory,
		UpstreamNodeNames: upstreamNodeNames,
		Degraded:          stats.Degraded || !filtering.Enabled || filtering.SourceErrors > 0,
		Errors:            errorsList,
	}
	if response.Comparison.Available {
		response.Comparison.Summary = stats.PreviousSummary
	}
	body, err := json.Marshal(response)
	if err != nil {
		return nil, fmt.Errorf("encode dashboard v1 response: %w", err)
	}
	return body, nil
}

func (s *Server) dashboardRuntime() dashboardRuntime {
	version, _ := s.buildMetadata()
	role := strings.TrimSpace(s.cfg.Mode)
	if role == "" {
		role = config.ModeController
	}
	runtime := dashboardRuntime{
		Version:     version,
		Role:        role,
		SkewedNodes: []string{},
	}
	if s.store == nil {
		return runtime
	}
	for _, node := range s.store.GetNodeStatuses() {
		runtime.TotalNodes++
		if node.Online {
			runtime.OnlineNodes++
		}
		if node.Online && versionsDiffer(version, node.Version) {
			runtime.SkewedNodes = append(runtime.SkewedNodes, node.Name)
		}
	}
	sort.Strings(runtime.SkewedNodes)
	runtime.VersionSkew = len(runtime.SkewedNodes) > 0
	return runtime
}

func versionsDiffer(local, remote string) bool {
	local = strings.TrimPrefix(strings.TrimSpace(local), "v")
	remote = strings.TrimPrefix(strings.TrimSpace(remote), "v")
	return local != "" && remote != "" && local != remote
}

func (s *Server) dashboardFilteringStatus() dashboardFilteringStatus {
	engine := s.getFilter()
	if engine == nil {
		return dashboardFilteringStatus{Enabled: true, State: "unconfigured"}
	}

	sources := engine.Sources()
	status := dashboardFilteringStatus{
		Configured:  true,
		Enabled:     !engine.Paused(),
		State:       "active",
		SourceCount: len(sources),
	}
	for _, source := range sources {
		status.BlockRules += source.RuleCount
		status.AllowRules += source.AllowRuleCount
		if source.LastError == "" {
			status.HealthySources++
		} else {
			status.SourceErrors++
		}
		if !source.LastUpdate.IsZero() && (status.LastUpdated == nil || source.LastUpdate.After(*status.LastUpdated)) {
			lastUpdated := source.LastUpdate.UTC()
			status.LastUpdated = &lastUpdated
		}
	}
	status.BlockedTotal, status.AllowedTotal = engine.Stats()
	if until := engine.PausedUntil(); !until.IsZero() {
		pausedUntil := until.UTC()
		status.PausedUntil = &pausedUntil
		status.State = "paused"
	} else if status.SourceErrors > 0 {
		status.State = "degraded"
	}
	return status
}

func appendUniqueString(values []string, target string) []string {
	for _, value := range values {
		if value == target {
			return values
		}
	}
	return append(values, target)
}

func (s *Server) invalidateDashboardStatsCache() {
	s.dashboardCacheMu.Lock()
	s.dashboardCache = make(map[string]statsCacheEntry)
	s.dashboardCacheEpoch++
	s.dashboardCacheMu.Unlock()

	s.statsCacheMu.Lock()
	s.statsCacheBody = nil
	s.statsCacheAt = time.Time{}
	s.statsCacheMu.Unlock()
}

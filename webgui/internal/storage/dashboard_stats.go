package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/arumes31/resolix/webgui/internal/models"
)

// DashboardStats is the ranged analytics snapshot consumed by the dashboard API.
type DashboardStats struct {
	Summary           DashboardSummary       `json:"summary"`
	Series            []DashboardSeriesPoint `json:"series"`
	TopDomains        []models.StatEntry     `json:"top_domains"`
	TopClients        []models.StatEntry     `json:"top_clients"`
	TopBlockedDomains []models.StatEntry     `json:"top_blocked_domains"`
	TypeCounts        map[string]int         `json:"type_counts"`
	NodeTotals        map[string]int         `json:"node_totals"`
	ResponseCodes     map[string]int         `json:"response_codes"`
	Degraded          bool                   `json:"degraded"`
	Errors            []string               `json:"errors"`
}

// DashboardSummary contains the headline values for a selected time range.
type DashboardSummary struct {
	Queries          int     `json:"queries"`
	QueriesPerMinute float64 `json:"queries_per_minute"`
	Blocked          int     `json:"blocked"`
	BlockedRatio     float64 `json:"blocked_ratio"`
	Errors           int     `json:"errors"`
	ErrorRatio       float64 `json:"error_ratio"`
	CacheHits        int     `json:"cache_hits"`
	CacheHitRatio    float64 `json:"cache_hit_ratio"`
	BandwidthSaved   int64   `json:"bandwidth_saved_bytes"`
}

// DashboardSeriesPoint is one server-generated bucket in the dashboard timeline.
type DashboardSeriesPoint struct {
	Start     int64          `json:"start"`
	Queries   int            `json:"queries"`
	Blocked   int            `json:"blocked"`
	Cached    int            `json:"cached"`
	Errors    int            `json:"errors"`
	Forwarded int            `json:"forwarded"`
	Nodes     map[string]int `json:"nodes"`
}

type dashboardAccumulator struct {
	start          int64
	end            int64
	bucketSeconds  int64
	stats          DashboardStats
	domainCounts   map[string]int
	clientCounts   map[string]int
	blockedDomains map[string]int
	pointIndexes   map[int64]int
	replies        int
}

// GetDashboardStats returns a bounded, server-generated dashboard time series.
func (s *Store) GetDashboardStats(
	ctx context.Context,
	start time.Time,
	end time.Time,
	bucket time.Duration,
) (DashboardStats, error) {
	if ctx == nil {
		return DashboardStats{}, fmt.Errorf("dashboard stats: nil context")
	}
	if !start.Before(end) || bucket <= 0 {
		return DashboardStats{}, fmt.Errorf("invalid dashboard time range")
	}

	accumulator := newDashboardAccumulator(start.Unix(), end.Unix(), int64(bucket.Seconds()))

	s.archiveMu.Lock()
	defer s.archiveMu.Unlock()

	s.batchMu.Lock()
	pending := append([]models.QueryEvent{}, s.pendingBatchLocked()...)
	s.batchMu.Unlock()

	s.dbMu.RLock()
	if s.db != nil {
		err := accumulator.mergeStoredEvents(ctx, s.db)
		if err != nil {
			s.dbMu.RUnlock()
			return DashboardStats{}, err
		}
	}
	s.dbMu.RUnlock()

	for _, event := range pending {
		accumulator.mergeEvent(event)
	}

	return accumulator.finish(s), nil
}

// UpstreamHealthSnapshot returns a defensive copy of current per-node health data.
func (s *Store) UpstreamHealthSnapshot() (
	map[string]map[string]float64,
	map[string]map[string][]float64,
) {
	s.healthMu.RLock()
	defer s.healthMu.RUnlock()

	health := make(map[string]map[string]float64, len(s.nodeUpstreamHealth))
	history := make(map[string]map[string][]float64, len(s.nodeUpstreamHealthHistory))
	for node, upstreams := range s.nodeUpstreamHealth {
		health[node] = make(map[string]float64, len(upstreams))
		for upstream, latency := range upstreams {
			health[node][upstream] = latency
		}
	}
	for node, upstreams := range s.nodeUpstreamHealthHistory {
		history[node] = make(map[string][]float64, len(upstreams))
		for upstream, samples := range upstreams {
			history[node][upstream] = append([]float64{}, samples...)
		}
	}
	return health, history
}

func newDashboardAccumulator(start, end, bucketSeconds int64) *dashboardAccumulator {
	firstBucket := start - start%bucketSeconds
	series := make([]DashboardSeriesPoint, 0, int((end-firstBucket)/bucketSeconds)+1)
	pointIndexes := make(map[int64]int)
	for bucketStart := firstBucket; bucketStart <= end; bucketStart += bucketSeconds {
		pointIndexes[bucketStart] = len(series)
		series = append(series, DashboardSeriesPoint{
			Start: bucketStart,
			Nodes: make(map[string]int),
		})
	}

	return &dashboardAccumulator{
		start:         start,
		end:           end,
		bucketSeconds: bucketSeconds,
		stats: DashboardStats{
			Series:        series,
			TypeCounts:    make(map[string]int),
			NodeTotals:    make(map[string]int),
			ResponseCodes: make(map[string]int),
			Errors:        []string{},
		},
		domainCounts:   make(map[string]int),
		clientCounts:   make(map[string]int),
		blockedDomains: make(map[string]int),
		pointIndexes:   pointIndexes,
	}
}

func (a *dashboardAccumulator) mergeStoredEvents(ctx context.Context, database *sql.DB) error {
	rows, err := database.QueryContext(
		ctx,
		`SELECT unix_time, node, domain, client_ip, type, upstream, response_code,
			blocked, cache_status
		 FROM queries
		 WHERE unix_time >= ? AND unix_time <= ?
		 ORDER BY unix_time`,
		a.start,
		a.end,
	)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return fmt.Errorf("query dashboard events: %w", err)
		}
		a.markDegraded("events")
		return nil
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var event models.QueryEvent
		var node, upstream, responseCode, cacheStatus sql.NullString
		if err := rows.Scan(
			&event.UnixTime,
			&node,
			&event.Domain,
			&event.ClientIP,
			&event.Type,
			&upstream,
			&responseCode,
			&event.Blocked,
			&cacheStatus,
		); err != nil {
			a.markDegraded("events")
			continue
		}
		event.Node = node.String
		event.Upstream = upstream.String
		event.ResponseCode = responseCode.String
		event.CacheStatus = cacheStatus.String
		a.mergeEvent(event)
	}
	if err := rows.Err(); err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return fmt.Errorf("iterate dashboard events: %w", err)
		}
		a.markDegraded("events")
	}
	return nil
}

func (a *dashboardAccumulator) mergeEvent(event models.QueryEvent) {
	if event.UnixTime < a.start || event.UnixTime > a.end {
		return
	}

	node := strings.TrimSpace(event.Node)
	if node == "" {
		node = "local"
	}
	responseCode := strings.ToUpper(strings.TrimSpace(event.ResponseCode))
	isError := !event.Blocked && dashboardResponseIsError(responseCode)
	isCached := isCacheHit(event)

	a.stats.Summary.Queries++
	a.domainCounts[event.Domain]++
	a.clientCounts[event.ClientIP]++
	a.stats.TypeCounts[event.Type]++
	a.stats.NodeTotals[node]++
	if responseCode != "" {
		a.stats.ResponseCodes[responseCode]++
	}
	if event.Upstream != "" {
		a.replies++
	}
	if event.Blocked {
		a.stats.Summary.Blocked++
		a.blockedDomains[event.Domain]++
	}
	if isError {
		a.stats.Summary.Errors++
	}
	if isCached {
		a.stats.Summary.CacheHits++
	}

	bucketStart := event.UnixTime - event.UnixTime%a.bucketSeconds
	pointIndex, ok := a.pointIndexes[bucketStart]
	if !ok {
		return
	}
	point := &a.stats.Series[pointIndex]
	point.Queries++
	point.Nodes[node]++
	switch {
	case event.Blocked:
		point.Blocked++
	case isError:
		point.Errors++
	case isCached:
		point.Cached++
	default:
		point.Forwarded++
	}
}

func (a *dashboardAccumulator) finish(store *Store) DashboardStats {
	windowMinutes := float64(a.end-a.start) / 60
	if windowMinutes > 0 {
		a.stats.Summary.QueriesPerMinute = float64(a.stats.Summary.Queries) / windowMinutes
	}
	if a.stats.Summary.Queries > 0 {
		a.stats.Summary.BlockedRatio = float64(a.stats.Summary.Blocked) / float64(a.stats.Summary.Queries) * 100
		a.stats.Summary.ErrorRatio = float64(a.stats.Summary.Errors) / float64(a.stats.Summary.Queries) * 100
	}
	if a.replies > 0 {
		a.stats.Summary.CacheHitRatio = float64(a.stats.Summary.CacheHits) / float64(a.replies) * 100
	}
	a.stats.Summary.BandwidthSaved = int64(a.stats.Summary.CacheHits) * 100
	a.stats.TopDomains = store.toStats(a.domainCounts, "domains")
	a.stats.TopClients = store.toStats(a.clientCounts, "clients")
	a.stats.TopBlockedDomains = topDashboardEntries(a.blockedDomains, 10)
	return a.stats
}

func (a *dashboardAccumulator) markDegraded(name string) {
	a.stats.Degraded = true
	if !containsString(a.stats.Errors, name) {
		a.stats.Errors = append(a.stats.Errors, name)
	}
}

func dashboardResponseIsError(responseCode string) bool {
	switch responseCode {
	case "NXDOMAIN", "SERVFAIL", "REFUSED", "FORMERR", "NOTIMP", "TIMEOUT":
		return true
	default:
		return false
	}
}

func topDashboardEntries(counts map[string]int, limit int) []models.StatEntry {
	entries := make([]models.StatEntry, 0, len(counts))
	for key, count := range counts {
		if key == "" {
			continue
		}
		entries = append(entries, models.StatEntry{Key: key, Count: count})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Count == entries[j].Count {
			return entries[i].Key < entries[j].Key
		}
		return entries[i].Count > entries[j].Count
	})
	if len(entries) > limit {
		entries = entries[:limit]
	}
	return entries
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

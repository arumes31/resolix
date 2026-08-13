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
	PreviousSummary   *DashboardSummary      `json:"previous_summary,omitempty"`
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
	Queries            int     `json:"queries"`
	QueriesPerMinute   float64 `json:"queries_per_minute"`
	Blocked            int     `json:"blocked"`
	BlockedRatio       float64 `json:"blocked_ratio"`
	Errors             int     `json:"errors"`
	ErrorRatio         float64 `json:"error_ratio"`
	CacheHits          int     `json:"cache_hits"`
	CacheHitRatio      float64 `json:"cache_hit_ratio"`
	RewriteHits        int     `json:"rewrite_hits"`
	LocalResponses     int     `json:"local_responses"`
	LocalResponseRatio float64 `json:"local_response_ratio"`
	BandwidthSaved     int64   `json:"bandwidth_saved_bytes"`
}

// DashboardSeriesPoint is one server-generated bucket in the dashboard timeline.
type DashboardSeriesPoint struct {
	Start     int64          `json:"start"`
	Queries   int            `json:"queries"`
	Blocked   int            `json:"blocked"`
	Cached    int            `json:"cached"`
	Rewritten int            `json:"rewritten"`
	Errors    int            `json:"errors"`
	Forwarded int            `json:"forwarded"`
	Nodes     map[string]int `json:"nodes"`
}

type dashboardAccumulator struct {
	start           int64
	end             int64
	previousStart   int64
	previous        *DashboardSummary
	previousReplies int
	bucketSeconds   int64
	stats           DashboardStats
	domainCounts    map[string]int
	clientCounts    map[string]int
	blockedDomains  map[string]int
	pointIndexes    map[int64]int
	replies         int
}

// GetDashboardStats returns a bounded, server-generated dashboard time series.
func (s *Store) GetDashboardStats(
	ctx context.Context,
	start time.Time,
	end time.Time,
	bucket time.Duration,
) (DashboardStats, error) {
	return s.GetDashboardStatsWithComparison(ctx, start, end, bucket, nil)
}

// GetDashboardStatsWithComparison returns the current dashboard snapshot and,
// when previousStart is provided, a headline summary for the immediately
// preceding non-overlapping window. Both windows share one pending-event
// snapshot and one database scan.
func (s *Store) GetDashboardStatsWithComparison(
	ctx context.Context,
	start time.Time,
	end time.Time,
	bucket time.Duration,
	previousStart *time.Time,
) (DashboardStats, error) {
	if ctx == nil {
		return DashboardStats{}, fmt.Errorf("dashboard stats: nil context")
	}
	if !start.Before(end) || bucket <= 0 {
		return DashboardStats{}, fmt.Errorf("invalid dashboard time range")
	}
	if previousStart != nil && !previousStart.Before(start) {
		return DashboardStats{}, fmt.Errorf("invalid dashboard comparison range")
	}

	accumulator := newDashboardAccumulator(start.Unix(), end.Unix(), int64(bucket.Seconds()), previousStart)

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

func newDashboardAccumulator(start, end, bucketSeconds int64, previousStart *time.Time) *dashboardAccumulator {
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

	accumulator := &dashboardAccumulator{
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
	if previousStart != nil {
		accumulator.previousStart = previousStart.Unix()
		accumulator.previous = &DashboardSummary{}
	}
	return accumulator
}

func (a *dashboardAccumulator) mergeStoredEvents(ctx context.Context, database *sql.DB) error {
	rows, err := database.QueryContext(
		ctx,
		`SELECT unix_time, node, domain, client_ip, type, upstream, response_code,
			blocked, cache_status
		 FROM queries
		 WHERE unix_time >= ? AND unix_time <= ?
		 ORDER BY unix_time`,
		a.queryStart(),
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
	if a.previous != nil && event.UnixTime >= a.previousStart && event.UnixTime < a.start {
		mergeDashboardSummary(a.previous, &a.previousReplies, event)
		return
	}
	if event.UnixTime < a.start || event.UnixTime > a.end {
		return
	}

	node := strings.TrimSpace(event.Node)
	if node == "" {
		node = "local"
	}
	responseCode := strings.ToUpper(strings.TrimSpace(event.ResponseCode))
	isRewritten := !event.Blocked && isRewriteAnswer(event)
	isError := !event.Blocked && !isRewritten && dashboardResponseIsError(responseCode)
	isCached := isCacheHit(event)

	mergeDashboardSummary(&a.stats.Summary, &a.replies, event)
	a.domainCounts[event.Domain]++
	a.clientCounts[event.ClientIP]++
	a.stats.TypeCounts[event.Type]++
	a.stats.NodeTotals[node]++
	if responseCode != "" {
		a.stats.ResponseCodes[responseCode]++
	}
	if event.Blocked {
		a.blockedDomains[event.Domain]++
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
	case isRewritten:
		point.Rewritten++
	case isError:
		point.Errors++
	case isCached:
		point.Cached++
	default:
		point.Forwarded++
	}
}

func (a *dashboardAccumulator) finish(store *Store) DashboardStats {
	finishDashboardSummary(&a.stats.Summary, a.replies, a.end-a.start)
	if a.previous != nil {
		finishDashboardSummary(a.previous, a.previousReplies, a.start-a.previousStart)
		a.stats.PreviousSummary = a.previous
	}
	a.stats.TopDomains = store.toStats(a.domainCounts, "domains")
	a.stats.TopClients = store.toStats(a.clientCounts, "clients")
	a.stats.TopBlockedDomains = topDashboardEntries(a.blockedDomains, 10)
	return a.stats
}

func (a *dashboardAccumulator) queryStart() int64 {
	if a.previous != nil {
		return a.previousStart
	}
	return a.start
}

func mergeDashboardSummary(summary *DashboardSummary, replies *int, event models.QueryEvent) {
	responseCode := strings.ToUpper(strings.TrimSpace(event.ResponseCode))
	isRewritten := !event.Blocked && isRewriteAnswer(event)
	isCached := !isRewritten && isCacheHit(event)
	summary.Queries++
	if event.Upstream != "" {
		(*replies)++
	}
	if event.Blocked {
		summary.Blocked++
	}
	if !event.Blocked && !isRewritten && dashboardResponseIsError(responseCode) {
		summary.Errors++
	}
	if isCached {
		summary.CacheHits++
	}
	if isRewritten {
		summary.RewriteHits++
	}
}

func finishDashboardSummary(summary *DashboardSummary, replies int, windowSeconds int64) {
	windowMinutes := float64(windowSeconds) / 60
	if windowMinutes > 0 {
		summary.QueriesPerMinute = float64(summary.Queries) / windowMinutes
	}
	if summary.Queries > 0 {
		summary.BlockedRatio = float64(summary.Blocked) / float64(summary.Queries) * 100
		summary.ErrorRatio = float64(summary.Errors) / float64(summary.Queries) * 100
	}
	if replies > 0 {
		summary.CacheHitRatio = float64(summary.CacheHits) / float64(replies) * 100
		summary.LocalResponseRatio = float64(summary.CacheHits+summary.RewriteHits) / float64(replies) * 100
	}
	summary.LocalResponses = summary.CacheHits + summary.RewriteHits
	summary.BandwidthSaved = int64(summary.CacheHits) * 100
}

func isRewriteAnswer(event models.QueryEvent) bool {
	upstream := strings.TrimSpace(event.Upstream)
	return strings.EqualFold(upstream, "Rewrite") || strings.EqualFold(upstream, "Local Override")
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

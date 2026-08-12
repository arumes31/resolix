package api

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Metrics holds Prometheus-format counters and gauges for the application.
// All fields use atomic operations for thread-safe access.
type Metrics struct {
	QueriesTotal      atomic.Int64
	QueriesBlocked    atomic.Int64
	CacheHits         atomic.Int64
	CacheMisses       atomic.Int64
	StartTime         time.Time
	queriesByType     sync.Map // map[string]*atomic.Int64
	upstreamLatencies sync.Map // map[string]*latencyBucket
	httpRequests      sync.Map // map["method status"]*atomic.Int64
	httpDurationNanos atomic.Int64
}

// latencyBucket tracks upstream latency samples for histogram emulation.
type latencyBucket struct {
	mu      sync.Mutex
	count   int64
	sum     float64
	buckets [5]int64 // <10ms, <50ms, <100ms, <500ms, >=500ms
}

// addSample records a latency measurement in milliseconds.
func (lb *latencyBucket) addSample(ms float64) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	lb.count++
	lb.sum += ms
	switch {
	case ms < 10:
		lb.buckets[0]++
	case ms < 50:
		lb.buckets[1]++
	case ms < 100:
		lb.buckets[2]++
	case ms < 500:
		lb.buckets[3]++
	default:
		lb.buckets[4]++
	}
}

// IncQueriesByType increments the counter for a specific DNS query type.
func (m *Metrics) IncQueriesByType(qtype string) {
	if v, ok := m.queriesByType.Load(qtype); ok {
		v.(*atomic.Int64).Add(1)
		return
	}
	newV := &atomic.Int64{}
	newV.Add(1)
	if actual, loaded := m.queriesByType.LoadOrStore(qtype, newV); loaded {
		actual.(*atomic.Int64).Add(1)
	}
}

// RecordUpstreamLatency records a latency measurement for an upstream server.
func (m *Metrics) RecordUpstreamLatency(upstreamName string, latencyMs float64) {
	if v, ok := m.upstreamLatencies.Load(upstreamName); ok {
		v.(*latencyBucket).addSample(latencyMs)
		return
	}
	newV := &latencyBucket{}
	newV.addSample(latencyMs)
	if actual, loaded := m.upstreamLatencies.LoadOrStore(upstreamName, newV); loaded {
		actual.(*latencyBucket).addSample(latencyMs)
	}
}

type statusResponseWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusResponseWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusResponseWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (w *statusResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func metricMethod(method string) string {
	switch method {
	case http.MethodConnect,
		http.MethodDelete,
		http.MethodGet,
		http.MethodHead,
		http.MethodOptions,
		http.MethodPatch,
		http.MethodPost,
		http.MethodPut,
		http.MethodTrace:
		return method
	default:
		return "OTHER"
	}
}

func (s *Server) requestMetricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		requestIDBytes := make([]byte, 12)
		if _, err := rand.Read(requestIDBytes); err == nil {
			w.Header().Set("X-Request-ID", base64.RawURLEncoding.EncodeToString(requestIDBytes))
		}
		rw := &statusResponseWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rw, r)
		key := metricMethod(r.Method) + " " + strconv.Itoa(rw.status)
		counter := &atomic.Int64{}
		actual, _ := s.metrics.httpRequests.LoadOrStore(key, counter)
		actual.(*atomic.Int64).Add(1)
		s.metrics.httpDurationNanos.Add(time.Since(started).Nanoseconds())
	})
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	var buf bytes.Buffer
	m := s.metrics

	// dns_queries_total
	fmt.Fprintf(&buf, "# HELP dns_queries_total Total DNS queries processed\n")
	fmt.Fprintf(&buf, "# TYPE dns_queries_total counter\n")
	fmt.Fprintf(&buf, "dns_queries_total %d\n", m.QueriesTotal.Load())

	// dns_queries_blocked_total
	fmt.Fprintf(&buf, "# HELP dns_queries_blocked_total Total blocked queries\n")
	fmt.Fprintf(&buf, "# TYPE dns_queries_blocked_total counter\n")
	fmt.Fprintf(&buf, "dns_queries_blocked_total %d\n", m.QueriesBlocked.Load())

	// dns_queries_by_type
	fmt.Fprintf(&buf, "# HELP dns_queries_by_type Queries by DNS record type\n")
	fmt.Fprintf(&buf, "# TYPE dns_queries_by_type counter\n")
	m.queriesByType.Range(func(key, value interface{}) bool {
		fmt.Fprintf(&buf, "dns_queries_by_type{type=\"%s\"} %d\n", escapePrometheusLabel(fmt.Sprint(key)), value.(*atomic.Int64).Load())
		return true
	})

	// dns_upstream_latency_seconds
	fmt.Fprintf(&buf, "# HELP dns_upstream_latency_seconds Upstream latency in seconds\n")
	fmt.Fprintf(&buf, "# TYPE dns_upstream_latency_seconds summary\n")
	m.upstreamLatencies.Range(func(key, value interface{}) bool {
		lb := value.(*latencyBucket)
		lb.mu.Lock()
		defer lb.mu.Unlock()
		if lb.count > 0 {
			label := escapePrometheusLabel(fmt.Sprint(key))
			fmt.Fprintf(&buf, "dns_upstream_latency_seconds_count{upstream=\"%s\"} %d\n", label, lb.count)
			fmt.Fprintf(&buf, "dns_upstream_latency_seconds_sum{upstream=\"%s\"} %f\n", label, lb.sum/1000.0)
		}
		return true
	})

	// dns_cache_hits_total
	fmt.Fprintf(&buf, "# HELP dns_cache_hits_total Cache hit count\n")
	fmt.Fprintf(&buf, "# TYPE dns_cache_hits_total counter\n")
	fmt.Fprintf(&buf, "dns_cache_hits_total %d\n", m.CacheHits.Load())

	// dns_cache_misses_total
	fmt.Fprintf(&buf, "# HELP dns_cache_misses_total Cache miss count\n")
	fmt.Fprintf(&buf, "# TYPE dns_cache_misses_total counter\n")
	fmt.Fprintf(&buf, "dns_cache_misses_total %d\n", m.CacheMisses.Load())

	// go_goroutines
	fmt.Fprintf(&buf, "# HELP go_goroutines Current goroutine count\n")
	fmt.Fprintf(&buf, "# TYPE go_goroutines gauge\n")
	fmt.Fprintf(&buf, "go_goroutines %d\n", runtime.NumGoroutine())

	// process_uptime_seconds
	uptime := time.Since(m.StartTime).Seconds()
	fmt.Fprintf(&buf, "# HELP process_uptime_seconds Application uptime in seconds\n")
	fmt.Fprintf(&buf, "# TYPE process_uptime_seconds gauge\n")
	fmt.Fprintf(&buf, "process_uptime_seconds %f\n", uptime)
	fmt.Fprintf(&buf, "# HELP sse_subscriber_drops_total Events dropped for slow SSE subscribers\n")
	fmt.Fprintf(&buf, "# TYPE sse_subscriber_drops_total counter\n")
	fmt.Fprintf(&buf, "sse_subscriber_drops_total %d\n", s.subDropCnt.Load())
	if s.store != nil {
		databaseMetrics := s.store.DBMetrics(r.Context())
		archiveMetrics := databaseMetrics.Archive
		fmt.Fprintf(&buf, "# HELP sqlite_archive_pending_events Events waiting to be archived to SQLite\n")
		fmt.Fprintf(&buf, "# TYPE sqlite_archive_pending_events gauge\n")
		fmt.Fprintf(&buf, "sqlite_archive_pending_events %d\n", archiveMetrics.Pending)
		fmt.Fprintf(&buf, "# HELP sqlite_archive_queue_capacity Maximum events held while waiting for SQLite\n")
		fmt.Fprintf(&buf, "# TYPE sqlite_archive_queue_capacity gauge\n")
		fmt.Fprintf(&buf, "sqlite_archive_queue_capacity %d\n", archiveMetrics.Capacity)
		fmt.Fprintf(&buf, "# HELP sqlite_archive_trigger_events Pending events that trigger an archive pass\n")
		fmt.Fprintf(&buf, "# TYPE sqlite_archive_trigger_events gauge\n")
		fmt.Fprintf(&buf, "sqlite_archive_trigger_events %d\n", archiveMetrics.Trigger)
		fmt.Fprintf(&buf, "# HELP sqlite_archive_write_batch_events Maximum events written per SQLite transaction\n")
		fmt.Fprintf(&buf, "# TYPE sqlite_archive_write_batch_events gauge\n")
		fmt.Fprintf(&buf, "sqlite_archive_write_batch_events %d\n", archiveMetrics.WriteBatch)
		fmt.Fprintf(&buf, "# HELP sqlite_archive_dropped_events_total Events dropped after the SQLite archive queue reached its hard limit\n")
		fmt.Fprintf(&buf, "# TYPE sqlite_archive_dropped_events_total counter\n")
		fmt.Fprintf(&buf, "sqlite_archive_dropped_events_total %d\n", archiveMetrics.Dropped)
		fmt.Fprintf(&buf, "# HELP sqlite_archive_pending_bytes Approximate bytes waiting for SQLite archival\n")
		fmt.Fprintf(&buf, "# TYPE sqlite_archive_pending_bytes gauge\n")
		fmt.Fprintf(&buf, "sqlite_archive_pending_bytes %d\n", archiveMetrics.PendingBytes)
		fmt.Fprintf(&buf, "# HELP sqlite_database_bytes Main SQLite database file size\n")
		fmt.Fprintf(&buf, "# TYPE sqlite_database_bytes gauge\n")
		fmt.Fprintf(&buf, "sqlite_database_bytes %d\n", databaseMetrics.DatabaseBytes)
		fmt.Fprintf(&buf, "# HELP sqlite_wal_bytes SQLite write-ahead log file size\n")
		fmt.Fprintf(&buf, "# TYPE sqlite_wal_bytes gauge\n")
		fmt.Fprintf(&buf, "sqlite_wal_bytes %d\n", databaseMetrics.WALBytes)
		fmt.Fprintf(&buf, "# HELP sqlite_busy_errors_total SQLite operations that failed with BUSY or LOCKED\n")
		fmt.Fprintf(&buf, "# TYPE sqlite_busy_errors_total counter\n")
		fmt.Fprintf(&buf, "sqlite_busy_errors_total %d\n", databaseMetrics.BusyErrors)
		fmt.Fprintf(&buf, "# HELP sqlite_freelist_pages Currently unused SQLite pages\n")
		fmt.Fprintf(&buf, "# TYPE sqlite_freelist_pages gauge\n")
		fmt.Fprintf(&buf, "sqlite_freelist_pages %d\n", databaseMetrics.FreeListPages)
		fmt.Fprintf(&buf, "# HELP sqlite_checkpoint_age_seconds Seconds since the last scheduled WAL checkpoint; -1 before the first checkpoint\n")
		fmt.Fprintf(&buf, "# TYPE sqlite_checkpoint_age_seconds gauge\n")
		fmt.Fprintf(&buf, "sqlite_checkpoint_age_seconds %.3f\n", databaseMetrics.CheckpointAgeSeconds)
		fmt.Fprintf(&buf, "# HELP sqlite_checkpoint_busy Whether the last WAL checkpoint was blocked by another connection\n")
		fmt.Fprintf(&buf, "# TYPE sqlite_checkpoint_busy gauge\n")
		fmt.Fprintf(&buf, "sqlite_checkpoint_busy %d\n", databaseMetrics.LastCheckpointBusy)
		fmt.Fprintf(&buf, "# HELP sqlite_checkpoint_log_frames WAL frames observed by the last checkpoint\n")
		fmt.Fprintf(&buf, "# TYPE sqlite_checkpoint_log_frames gauge\n")
		fmt.Fprintf(&buf, "sqlite_checkpoint_log_frames %d\n", databaseMetrics.LastCheckpointLogFrames)
		fmt.Fprintf(&buf, "# HELP sqlite_checkpointed_frames WAL frames checkpointed by the last checkpoint\n")
		fmt.Fprintf(&buf, "# TYPE sqlite_checkpointed_frames gauge\n")
		fmt.Fprintf(&buf, "sqlite_checkpointed_frames %d\n", databaseMetrics.LastCheckpointedFrames)
		vacuumRecommended := 0
		if databaseMetrics.VacuumRecommended {
			vacuumRecommended = 1
		}
		fmt.Fprintf(&buf, "# HELP sqlite_vacuum_recommended Whether a maintenance-window migration to incremental vacuum is recommended\n")
		fmt.Fprintf(&buf, "# TYPE sqlite_vacuum_recommended gauge\n")
		fmt.Fprintf(&buf, "sqlite_vacuum_recommended %d\n", vacuumRecommended)
	}

	fmt.Fprintf(&buf, "# HELP http_requests_total HTTP requests by method and status\n")
	fmt.Fprintf(&buf, "# TYPE http_requests_total counter\n")
	var requestCount int64
	m.httpRequests.Range(func(key, value interface{}) bool {
		parts := strings.SplitN(fmt.Sprint(key), " ", 2)
		if len(parts) == 2 {
			count := value.(*atomic.Int64).Load()
			requestCount += count
			fmt.Fprintf(&buf, "http_requests_total{method=\"%s\",status=\"%s\"} %d\n", escapePrometheusLabel(parts[0]), escapePrometheusLabel(parts[1]), count)
		}
		return true
	})
	fmt.Fprintf(&buf, "# HELP http_request_duration_seconds_sum Total HTTP request duration\n")
	fmt.Fprintf(&buf, "# TYPE http_request_duration_seconds_sum counter\n")
	fmt.Fprintf(&buf, "http_request_duration_seconds_sum %f\n", float64(m.httpDurationNanos.Load())/float64(time.Second))
	fmt.Fprintf(&buf, "# HELP http_request_duration_seconds_count Total timed HTTP requests\n")
	fmt.Fprintf(&buf, "# TYPE http_request_duration_seconds_count counter\n")
	fmt.Fprintf(&buf, "http_request_duration_seconds_count %d\n", requestCount)

	// Filter engine metrics
	if eng := s.getFilter(); eng != nil {
		blocked, allowed := eng.Stats()
		fmt.Fprintf(&buf, "# HELP filter_blocked_total Queries blocked by the filter engine\n")
		fmt.Fprintf(&buf, "# TYPE filter_blocked_total counter\n")
		fmt.Fprintf(&buf, "filter_blocked_total %d\n", blocked)
		fmt.Fprintf(&buf, "# HELP filter_allowed_total Queries allowed by filter exception rules\n")
		fmt.Fprintf(&buf, "# TYPE filter_allowed_total counter\n")
		fmt.Fprintf(&buf, "filter_allowed_total %d\n", allowed)
		fmt.Fprintf(&buf, "# HELP filter_rules_total Loaded filter rules per source\n")
		fmt.Fprintf(&buf, "# TYPE filter_rules_total gauge\n")
		for _, src := range eng.Sources() {
			label := escapePrometheusLabel(src.Name)
			kind := escapePrometheusLabel(src.Kind)
			fmt.Fprintf(&buf, "filter_rules_total{source=\"%s\",kind=\"%s\",type=\"block\"} %d\n", label, kind, src.RuleCount)
			fmt.Fprintf(&buf, "filter_rules_total{source=\"%s\",kind=\"%s\",type=\"allow\"} %d\n", label, kind, src.AllowRuleCount)
		}
		fmt.Fprintf(&buf, "# HELP filter_paused Whether filtering is currently paused (1) or active (0)\n")
		fmt.Fprintf(&buf, "# TYPE filter_paused gauge\n")
		paused := 0
		if eng.Paused() {
			paused = 1
		}
		fmt.Fprintf(&buf, "filter_paused %d\n", paused)
	}

	// DNS pipeline counters (rewrites / safe-search / bogus-NXDOMAIN)
	if dnsSrv := s.getDNSServer(); dnsSrv != nil {
		rewriteHits, safeSearchHits, bogusNXHits := dnsSrv.Stats()
		fmt.Fprintf(&buf, "# HELP rewrites_hits_total Queries answered by typed rewrites\n")
		fmt.Fprintf(&buf, "# TYPE rewrites_hits_total counter\n")
		fmt.Fprintf(&buf, "rewrites_hits_total %d\n", rewriteHits)
		fmt.Fprintf(&buf, "# HELP safesearch_hits_total Queries rewritten by safe search\n")
		fmt.Fprintf(&buf, "# TYPE safesearch_hits_total counter\n")
		fmt.Fprintf(&buf, "safesearch_hits_total %d\n", safeSearchHits)
		fmt.Fprintf(&buf, "# HELP bogus_nxdomain_total Upstream answers converted to NXDOMAIN (bogus ranges)\n")
		fmt.Fprintf(&buf, "# TYPE bogus_nxdomain_total counter\n")
		fmt.Fprintf(&buf, "bogus_nxdomain_total %d\n", bogusNXHits)

		fmt.Fprintf(&buf, "# HELP dns_ratelimit_dropped_total Queries silently dropped by the per-client-IP rate limiter\n")
		fmt.Fprintf(&buf, "# TYPE dns_ratelimit_dropped_total counter\n")
		fmt.Fprintf(&buf, "dns_ratelimit_dropped_total %d\n", dnsSrv.RateLimitDropped())
		aclDropped, allowlistDropped, rateBuckets := dnsSrv.ACLStats()
		fmt.Fprintf(&buf, "# HELP dns_acl_dropped_total Queries silently dropped by the DNS deny ACL\n")
		fmt.Fprintf(&buf, "# TYPE dns_acl_dropped_total counter\n")
		fmt.Fprintf(&buf, "dns_acl_dropped_total %d\n", aclDropped)
		fmt.Fprintf(&buf, "# HELP dns_acl_allowlist_dropped_total Queries silently dropped outside the DNS allow ACL\n")
		fmt.Fprintf(&buf, "# TYPE dns_acl_allowlist_dropped_total counter\n")
		fmt.Fprintf(&buf, "dns_acl_allowlist_dropped_total %d\n", allowlistDropped)
		fmt.Fprintf(&buf, "# HELP dns_acl_refused_total Deprecated; unauthorized DNS queries are now silently dropped\n")
		fmt.Fprintf(&buf, "# TYPE dns_acl_refused_total counter\n")
		fmt.Fprintf(&buf, "dns_acl_refused_total 0\n")
		fmt.Fprintf(&buf, "# HELP dns_ratelimit_buckets Active per-client-IP rate-limit buckets\n")
		fmt.Fprintf(&buf, "# TYPE dns_ratelimit_buckets gauge\n")
		fmt.Fprintf(&buf, "dns_ratelimit_buckets %d\n", rateBuckets)

		cacheStats := dnsSrv.CacheStats()
		fmt.Fprintf(&buf, "# HELP dns_cache_entries Current cache entries\n# TYPE dns_cache_entries gauge\ndns_cache_entries %d\n", cacheStats.Entries)
		fmt.Fprintf(&buf, "# HELP dns_cache_capacity Maximum cache entries\n# TYPE dns_cache_capacity gauge\ndns_cache_capacity %d\n", cacheStats.Capacity)
		fmt.Fprintf(&buf, "# HELP dns_cache_utilization Cache capacity utilization ratio\n# TYPE dns_cache_utilization gauge\ndns_cache_utilization %f\n", cacheStats.Utilization)
		fmt.Fprintf(&buf, "# HELP dns_cache_negative_entries Current negative cache entries\n# TYPE dns_cache_negative_entries gauge\ndns_cache_negative_entries %d\n", cacheStats.NegativeEntries)
		fmt.Fprintf(&buf, "# HELP dns_cache_in_flight Current coalesced upstream cache misses\n# TYPE dns_cache_in_flight gauge\ndns_cache_in_flight %d\n", cacheStats.InFlight)
		fmt.Fprintf(&buf, "# HELP dns_cache_fresh_hits_total Fresh positive cache responses served\n# TYPE dns_cache_fresh_hits_total counter\ndns_cache_fresh_hits_total %d\n", cacheStats.FreshHits)
		fmt.Fprintf(&buf, "# HELP dns_cache_negative_hits_total Negative cache responses served\n# TYPE dns_cache_negative_hits_total counter\ndns_cache_negative_hits_total %d\n", cacheStats.NegativeHits)
		fmt.Fprintf(&buf, "# HELP dns_cache_prefetched_hits_total Prefetched cache responses served\n# TYPE dns_cache_prefetched_hits_total counter\ndns_cache_prefetched_hits_total %d\n", cacheStats.PrefetchedHits)
		fmt.Fprintf(&buf, "# HELP dns_cache_servfail_hits_total SERVFAIL micro-cache responses served\n# TYPE dns_cache_servfail_hits_total counter\ndns_cache_servfail_hits_total %d\n", cacheStats.SERVFAILHits)
		fmt.Fprintf(&buf, "# HELP dns_cache_stale_hits_total Optimistic stale responses served\n# TYPE dns_cache_stale_hits_total counter\ndns_cache_stale_hits_total %d\n", cacheStats.StaleHits)
		fmt.Fprintf(&buf, "# HELP dns_cache_evictions_total LRU cache evictions\n# TYPE dns_cache_evictions_total counter\ndns_cache_evictions_total %d\n", cacheStats.Evictions)
		fmt.Fprintf(&buf, "# HELP dns_cache_expirations_total Expired cache entries removed\n# TYPE dns_cache_expirations_total counter\ndns_cache_expirations_total %d\n", cacheStats.Expirations)
		fmt.Fprintf(&buf, "# HELP dns_cache_cleared_entries_total Entries removed by cache clears\n# TYPE dns_cache_cleared_entries_total counter\ndns_cache_cleared_entries_total %d\n", cacheStats.Cleared)
		fmt.Fprintf(&buf, "# HELP dns_cache_invalidated_entries_total Entries removed by targeted invalidation\n# TYPE dns_cache_invalidated_entries_total counter\ndns_cache_invalidated_entries_total %d\n", cacheStats.Invalidated)
		fmt.Fprintf(&buf, "# HELP dns_cache_refreshes_total Successful optimistic cache refreshes\n# TYPE dns_cache_refreshes_total counter\ndns_cache_refreshes_total %d\n", cacheStats.Refreshes)
		fmt.Fprintf(&buf, "# HELP dns_cache_prefetches_total Successful proactive cache refreshes\n# TYPE dns_cache_prefetches_total counter\ndns_cache_prefetches_total %d\n", cacheStats.Prefetches)
		fmt.Fprintf(&buf, "# HELP dns_cache_coalesced_total Cache misses joined to an in-flight request\n# TYPE dns_cache_coalesced_total counter\ndns_cache_coalesced_total %d\n", cacheStats.Coalesced)
		fmt.Fprintf(&buf, "# HELP dns_cache_qtype_hits_total Cache hits by DNS record type\n# TYPE dns_cache_qtype_hits_total counter\n")
		fmt.Fprintf(&buf, "# HELP dns_cache_qtype_misses_total Cache misses by DNS record type\n# TYPE dns_cache_qtype_misses_total counter\n")
		fmt.Fprintf(&buf, "# HELP dns_cache_qtype_evictions_total Cache evictions by DNS record type\n# TYPE dns_cache_qtype_evictions_total counter\n")
		fmt.Fprintf(&buf, "# HELP dns_cache_qtype_expirations_total Cache expirations by DNS record type\n# TYPE dns_cache_qtype_expirations_total counter\n")
		qtypes := make([]string, 0, len(cacheStats.ByQType))
		for qtype := range cacheStats.ByQType {
			qtypes = append(qtypes, qtype)
		}
		sort.Strings(qtypes)
		for _, qtype := range qtypes {
			stats := cacheStats.ByQType[qtype]
			label := escapePrometheusLabel(qtype)
			fmt.Fprintf(&buf, "dns_cache_qtype_hits_total{qtype=\"%s\"} %d\n", label, stats.Hits)
			fmt.Fprintf(&buf, "dns_cache_qtype_misses_total{qtype=\"%s\"} %d\n", label, stats.Misses)
			fmt.Fprintf(&buf, "dns_cache_qtype_evictions_total{qtype=\"%s\"} %d\n", label, stats.Evictions)
			fmt.Fprintf(&buf, "dns_cache_qtype_expirations_total{qtype=\"%s\"} %d\n", label, stats.Expirations)
		}

	}

	s.fieldsMu.RLock()
	pool := s.upstreamPool
	fwd := s.forwarder
	s.fieldsMu.RUnlock()
	if pool != nil {
		fmt.Fprintf(&buf, "# HELP dns_upstream_requests_total Upstream requests by result\n# TYPE dns_upstream_requests_total counter\n")
		fmt.Fprintf(&buf, "# HELP dns_upstream_ewma_seconds Upstream latency EWMA\n# TYPE dns_upstream_ewma_seconds gauge\n")
		fmt.Fprintf(&buf, "# HELP dns_upstream_healthy Upstream health state\n# TYPE dns_upstream_healthy gauge\n")
		for _, stat := range pool.StatsSnapshot() {
			label := escapePrometheusLabel(stat.Spec)
			fmt.Fprintf(&buf, "dns_upstream_requests_total{upstream=\"%s\",result=\"success\"} %d\n", label, stat.Successes)
			fmt.Fprintf(&buf, "dns_upstream_requests_total{upstream=\"%s\",result=\"failure\"} %d\n", label, stat.Failures)
			fmt.Fprintf(&buf, "dns_upstream_ewma_seconds{upstream=\"%s\"} %f\n", label, stat.EWMAms/1000)
			healthy := 0
			if stat.Healthy {
				healthy = 1
			}
			fmt.Fprintf(&buf, "dns_upstream_healthy{upstream=\"%s\"} %d\n", label, healthy)
		}
	}
	if fwd != nil {
		backlog, backlogBytes, retries, dropped, sent := fwd.Stats()
		fmt.Fprintf(&buf, "# HELP forwarder_backlog_events Events waiting for controller delivery\n# TYPE forwarder_backlog_events gauge\nforwarder_backlog_events %d\n", backlog)
		fmt.Fprintf(&buf, "# HELP forwarder_backlog_bytes Bytes waiting for controller delivery\n# TYPE forwarder_backlog_bytes gauge\nforwarder_backlog_bytes %d\n", backlogBytes)
		fmt.Fprintf(&buf, "# HELP forwarder_retries_total Controller delivery retries\n# TYPE forwarder_retries_total counter\nforwarder_retries_total %d\n", retries)
		fmt.Fprintf(&buf, "# HELP forwarder_dropped_events_total Events dropped by forwarding limits or permanent errors\n# TYPE forwarder_dropped_events_total counter\nforwarder_dropped_events_total %d\n", dropped)
		fmt.Fprintf(&buf, "# HELP forwarder_sent_events_total Events delivered to the controller\n# TYPE forwarder_sent_events_total counter\nforwarder_sent_events_total %d\n", sent)
	}

	_, _ = buf.WriteTo(w)
}

func escapePrometheusLabel(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, "\n", `\n`)
	return strings.ReplaceAll(value, `"`, `\"`)
}

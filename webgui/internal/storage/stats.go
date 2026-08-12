package storage

import (
	"context"
	"database/sql"
	"log"
	"sort"
	"time"

	"github.com/arumes31/resolix/webgui/internal/models"
)

// GetStats returns aggregated traffic statistics using SQLite.
func (s *Store) GetStats() map[string]interface{} {
	return s.getStatsAt(time.Now())
}

// getStatsAt is the deterministic implementation behind GetStats. Complete
// UTC hours use incremental aggregates; the partial cutoff hour is read from
// SQLite exactly so the rolling 24-hour window never includes older rows.
//
//nolint:gocyclo
func (s *Store) getStatsAt(nowTime time.Time) map[string]interface{} {
	s.archiveMu.Lock()
	defer s.archiveMu.Unlock()
	s.batchMu.Lock()
	pending := append([]models.QueryEvent(nil), s.pendingBatchLocked()...)
	s.batchMu.Unlock()
	s.dbMu.RLock()
	defer s.dbMu.RUnlock()

	now := nowTime.Unix()
	cutoff24h := now - 86400
	cutoffHour := (cutoff24h / 3600) * 3600
	completeHourStart := cutoffHour + 3600

	rpm := 0
	rph := 0

	s.statsMu.RLock()
	for i := 0; i < 60; i++ {
		if now-s.rpmTimes[i] < 60 {
			rpm += s.rpmBuckets[i]
		}
		if now-s.rphTimes[i] < 3600 {
			rph += s.rphBuckets[i]
		}
	}

	nodeList := make(map[string]interface{})
	for node, buckets := range s.nodeRPHBuckets {
		nRPM := 0
		nRPH := 0
		rpmTs := s.nodeRPMTimes[node]
		rphTs := s.nodeRPHTimes[node]
		rpmB := s.nodeRPMBuckets[node]
		for i := 0; i < 60; i++ {
			if now-rpmTs[i] < 60 {
				nRPM += rpmB[i]
			}
			if now-rphTs[i] < 3600 {
				nRPH += buckets[i]
			}
		}
		if nRPH > 0 {
			nodeList[node] = map[string]int{
				"rpm": nRPM,
				"rph": nRPH,
			}
		}
	}

	typeCounts := make(map[string]int)
	s.statsMu.RUnlock()

	// Query SQLite for long-term aggregates
	var totalEvents int64
	var rpd int
	var cacheHits, totalReplies int64
	var queryErrors []string
	domainCounts := make(map[string]int)
	clientCounts := make(map[string]int)
	heatmap := make(map[string]int)
	mergeWindowEvent := func(event models.QueryEvent) {
		rpd++
		if event.Upstream != "" {
			totalReplies++
		}
		if isCacheHit(event) {
			cacheHits++
		}
		typeCounts[event.Type]++
		domainCounts[event.Domain]++
		clientCounts[event.ClientIP]++
		hour := time.Unix(event.UnixTime, 0).UTC().Format("15:00")
		heatmap[hour]++
	}
	if s.db != nil {
		if err := s.db.QueryRow("SELECT COALESCE(SUM(total), 0) FROM query_hourly_totals").Scan(&totalEvents); err != nil && err != sql.ErrNoRows {
			log.Printf("Error getting totalEvents: %v", err)
			s.recordDBError(err)
			queryErrors = append(queryErrors, "total")
		}
		err := s.db.QueryRow(`SELECT COALESCE(SUM(total), 0),
			COALESCE(SUM(cache_hits), 0), COALESCE(SUM(replies), 0)
			FROM query_hourly_totals WHERE hour >= ?`, completeHourStart).Scan(&rpd, &cacheHits, &totalReplies)
		if err != nil && err != sql.ErrNoRows {
			log.Printf("Error getting daily aggregates: %v", err)
			s.recordDBError(err)
			queryErrors = append(queryErrors, "rpd", "cache_hits", "total_replies")
		}
		rows, err := s.db.Query("SELECT type, SUM(count) FROM query_hourly_types WHERE hour >= ? GROUP BY type", completeHourStart)
		if err != nil {
			s.recordDBError(err)
			queryErrors = append(queryErrors, "type_counts")
		} else {
			for rows.Next() {
				var queryType string
				var count int
				if err := rows.Scan(&queryType, &count); err == nil {
					typeCounts[queryType] = count
				}
			}
			if err := rows.Err(); err != nil {
				s.recordDBError(err)
				queryErrors = append(queryErrors, "type_counts")
			}
			_ = rows.Close()
		}

		rows, err = s.db.Query(`SELECT unix_time, domain, client_ip, type, upstream, cache_status
			FROM queries WHERE unix_time >= ? AND unix_time < ?`, cutoff24h, completeHourStart)
		if err != nil {
			s.recordDBError(err)
			queryErrors = append(queryErrors, "cutoff_hour")
		} else {
			for rows.Next() {
				var event models.QueryEvent
				var upstream, cacheStatus sql.NullString
				if err := rows.Scan(
					&event.UnixTime, &event.Domain, &event.ClientIP, &event.Type,
					&upstream, &cacheStatus,
				); err != nil {
					s.recordDBError(err)
					queryErrors = append(queryErrors, "cutoff_hour")
					continue
				}
				event.Upstream = upstream.String
				event.CacheStatus = cacheStatus.String
				mergeWindowEvent(event)
			}
			if err := rows.Err(); err != nil {
				s.recordDBError(err)
				queryErrors = append(queryErrors, "cutoff_hour")
			}
			_ = rows.Close()
		}
	}

	totalEvents += int64(len(pending))
	for _, event := range pending {
		if event.UnixTime < cutoff24h {
			continue
		}
		mergeWindowEvent(event)
	}

	cacheHitRatio := 0.0
	if totalReplies > 0 {
		cacheHitRatio = float64(cacheHits) / float64(totalReplies) * 100
	}

	// Item 67: Bandwidth savings estimate (100 bytes per cached query)
	bandwidthSaved := cacheHits * 100

	if s.db != nil {
		// Domain candidates (the Top 10 are selected after pending counts are merged).
		if s.stmtGetTopDomains != nil {
			rowsDomains, err := s.stmtGetTopDomains.Query(completeHourStart)
			if err == nil {
				for rowsDomains.Next() {
					var d string
					var c int
					if rowsDomains.Scan(&d, &c) == nil {
						domainCounts[d] += c
					}
				}
				if err := rowsDomains.Err(); err != nil {
					log.Printf("Error iterating domain rows: %v", err)
				}
				_ = rowsDomains.Close()
			}
		}

		// Client candidates (the Top 10 are selected after pending counts are merged).
		if s.stmtGetTopClients != nil {
			rowsClients, err := s.stmtGetTopClients.Query(completeHourStart)
			if err == nil {
				for rowsClients.Next() {
					var ip string
					var c int
					if rowsClients.Scan(&ip, &c) == nil {
						clientCounts[ip] += c
					}
				}
				if err := rowsClients.Err(); err != nil {
					log.Printf("Error iterating client rows: %v", err)
				}
				_ = rowsClients.Close()
			}
		}

		// Hourly heatmap
		currentHour := now / 3600
		rowsHeatmap, err := s.db.Query("SELECT hour, total FROM query_hourly_totals WHERE hour >= ?", completeHourStart)
		if err == nil {
			for rowsHeatmap.Next() {
				var hr int64
				var c int
				if rowsHeatmap.Scan(&hr, &c) == nil {
					t := time.Unix(hr, 0).UTC()
					heatmap[t.Format("15:00")] += c
				}
			}
			if err := rowsHeatmap.Err(); err != nil {
				log.Printf("Error iterating heatmap rows: %v", err)
			}
			_ = rowsHeatmap.Close()
		}

		// Fill missing hours in heatmap
		for h := currentHour - 23; h <= currentHour; h++ {
			t := time.Unix(h*3600, 0).UTC()
			k := t.Format("15:00")
			if _, exists := heatmap[k]; !exists {
				heatmap[k] = 0
			}
		}
	}

	s.healthMu.RLock()
	nodeHealth := make(map[string]map[string]float64)
	nodeHealthHist := make(map[string]map[string][]float64)
	for node, upstreams := range s.nodeUpstreamHealth {
		nodeHealth[node] = make(map[string]float64)
		nodeHealthHist[node] = make(map[string][]float64)
		for up, lat := range upstreams {
			nodeHealth[node][up] = lat
			if hist, ok := s.nodeUpstreamHealthHistory[node][up]; ok {
				nodeHealthHist[node][up] = append([]float64(nil), hist...)
			}
		}
	}
	s.healthMu.RUnlock()

	return map[string]interface{}{
		"top_domains":      s.toStats(domainCounts, "domains"),
		"top_clients":      s.toStats(clientCounts, "clients"),
		"rpm":              rpm,
		"rph":              rph,
		"rpd":              rpd,
		"total":            totalEvents,
		"nodes":            nodeList,
		"cache_hit_ratio":  cacheHitRatio,
		"node_health":      nodeHealth,
		"node_health_hist": nodeHealthHist,
		"heatmap":          heatmap,
		"type_counts":      typeCounts,
		"bandwidth_saved":  bandwidthSaved,
		"degraded":         len(queryErrors) > 0,
		"errors":           queryErrors,
	}
}

func (s *Store) toStats(m map[string]int, category string) []models.StatEntry {
	st := make([]models.StatEntry, 0, len(m))
	for k, v := range m {
		entry := models.StatEntry{Key: k, Count: v}
		if category == "clients" {
			entry.Alias = s.cfg.GetClientAlias(k)
		}
		s.statsMu.RLock()
		if last, ok := s.lastTopStats[category]; ok {
			for _, le := range last {
				if le.Key == k {
					switch {
					case v > le.Count:
						entry.Trend = "up"
					case v < le.Count:
						entry.Trend = "down"
					default:
						entry.Trend = "stable"
					}
					break
				}
			}
		}
		s.statsMu.RUnlock()
		st = append(st, entry)
	}

	sort.Slice(st, func(i, j int) bool {
		return st[i].Count > st[j].Count
	})

	if len(st) > 10 {
		st = st[:10]
	}
	return st
}

// GetClientStats returns the RPM/RPH stats for a specific client.
func (s *Store) GetClientStats(ip string) map[string]interface{} {
	s.statsMu.RLock()
	defer s.statsMu.RUnlock()

	now := time.Now().Unix()
	rpm := 0
	rph := 0
	rpmHistory := make([]int, 60)

	rpmBuckets := s.clientRPMBuckets[ip]
	rpmTimes := s.clientRPMTimes[ip]
	rphBuckets := s.clientRPHBuckets[ip]
	rphTimes := s.clientRPHTimes[ip]

	if rpmBuckets != nil && rpmTimes != nil {
		for i := 0; i < 60; i++ {
			if now-rpmTimes[i] < 60 {
				rpm += rpmBuckets[i]
			}
		}
		for i := 0; i < 60; i++ {
			idx := (now - 59 + int64(i)) % 60
			if now-rpmTimes[idx] < 60 {
				rpmHistory[i] = rpmBuckets[idx]
			}
		}
	}
	if rphBuckets != nil && rphTimes != nil {
		for i := 0; i < 60; i++ {
			if now-rphTimes[i] < 3600 {
				rph += rphBuckets[i]
			}
		}
	}

	return map[string]interface{}{
		"ip":          ip,
		"alias":       s.cfg.GetClientAlias(ip),
		"rpm":         rpm,
		"rph":         rph,
		"rpm_history": rpmHistory,
	}
}

// StartStatsTrends begins periodic snapshots of top lists for trend analysis.
func (s *Store) StartStatsTrends(ctx context.Context) {
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Minute):
				s.updateTrends()
			}
		}
	}()
}

func (s *Store) updateTrends() {
	stats := s.GetStats()
	s.statsMu.Lock()
	if td, ok := stats["top_domains"].([]models.StatEntry); ok {
		s.lastTopStats["domains"] = td
	}
	if tc, ok := stats["top_clients"].([]models.StatEntry); ok {
		s.lastTopStats["clients"] = tc
	}
	s.statsMu.Unlock()
}

// startVacuum runs bounded incremental vacuum work when the database supports
// it. Existing databases that require a blocking one-time VACUUM migration are
// reported through DBMetrics and never migrated automatically.

package storage

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/arumes31/resolix/webgui/internal/config"
	"github.com/arumes31/resolix/webgui/internal/models"
)

// RunArchiver persists queued events when the queue reaches its high-water mark
// or the periodic interval expires. Failed writes retry with bounded backoff.
func (s *Store) RunArchiver(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = config.DefaultArchiveInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-s.archiveReady:
		}

		retryDelay := archiveRetryInitialDelay
		for {
			_, err := s.archiveStep(ctx, time.Now())
			if err == nil {
				break
			}
			if ctx.Err() != nil {
				return
			}
			metrics := s.ArchiveMetrics()
			log.Printf("SQLite archive failed; retaining %d events and retrying in %s: %v", metrics.Pending, retryDelay, err)

			retryTimer := time.NewTimer(retryDelay)
			select {
			case <-ctx.Done():
				if !retryTimer.Stop() {
					<-retryTimer.C
				}
				return
			case <-retryTimer.C:
			}
			retryDelay = min(retryDelay*2, archiveRetryMaxDelay)
		}
	}
}

// ArchiveStep performs a batch insert of recent queries into SQLite and deletes old ones.
func (s *Store) ArchiveStep(now time.Time) int {
	archived, err := s.archiveStep(context.Background(), now)
	if err != nil {
		metrics := s.ArchiveMetrics()
		log.Printf("SQLite archive failed; retaining %d events: %v", metrics.Pending, err)
	}
	return archived
}

func (s *Store) archiveStep(ctx context.Context, now time.Time) (int, error) {
	s.archiveMu.Lock()
	defer s.archiveMu.Unlock()
	s.dbMu.RLock()
	defer s.dbMu.RUnlock()
	if s.closed || s.db == nil {
		return 0, nil
	}

	archived := 0
	for {
		toInsert := s.claimArchiveBatch()
		if len(toInsert) == 0 {
			break
		}

		insert := s.insertArchiveBatch
		if s.archiveInsert != nil {
			insert = s.archiveInsert
		}
		if err := insert(ctx, toInsert); err != nil {
			s.restoreArchiveBatch(toInsert)
			return archived, err
		}
		s.batchInFlight.Add(-int64(len(toInsert)))
		s.batchFlightBytes.Add(-eventsApproxBytes(toInsert))
		archived += len(toInsert)
	}

	s.pruneOldEvents(ctx, now)
	s.flushArchiveDropWarning()
	return archived, nil
}

func (s *Store) claimArchiveBatch() []models.QueryEvent {
	s.batchMu.Lock()
	defer s.batchMu.Unlock()

	pending := s.pendingBatchLocked()
	chunkSize := min(len(pending), s.archiveBatch)
	if chunkSize == 0 {
		return nil
	}
	claimed := append([]models.QueryEvent(nil), pending[:chunkSize]...)
	claimedBytes := eventsApproxBytes(claimed)
	clear(s.batch[s.batchStart : s.batchStart+chunkSize])
	s.batchStart += chunkSize
	s.batchBytes -= claimedBytes
	s.batchInFlight.Add(int64(chunkSize))
	s.batchFlightBytes.Add(claimedBytes)
	if s.pendingBatchLenLocked() == 0 || s.batchStart >= max(1, s.archiveLimit/4) {
		s.compactBatchLocked()
	}
	return claimed
}

func (s *Store) restoreArchiveBatch(claimed []models.QueryEvent) {
	s.batchMu.Lock()
	pending := append([]models.QueryEvent(nil), s.pendingBatchLocked()...)
	combined := make([]models.QueryEvent, 0, len(claimed)+len(pending))
	combined = append(combined, claimed...)
	combined = append(combined, pending...)

	dropped := max(0, len(combined)-s.archiveLimit)
	clear(s.batch)
	s.batch = append(s.batch[:0], combined[dropped:]...)
	s.batchStart = 0
	s.batchBytes = eventsApproxBytes(s.batch)
	s.batchInFlight.Add(-int64(len(claimed)))
	s.batchFlightBytes.Add(-eventsApproxBytes(claimed))
	if dropped > 0 {
		s.batchDropped.Add(int64(dropped))
		s.batchDropUnreported += int64(dropped)
	}
	s.batchMu.Unlock()

	if dropped > 0 {
		log.Printf("[WARN] SQLite archive retry queue full; dropped %d oldest uncommitted event(s) (%d total)", dropped, s.batchDropped.Load())
	}
}

func (s *Store) insertArchiveBatch(ctx context.Context, events []models.QueryEvent) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction for %d events: %w", len(events), err)
	}

	const insertPrefix = "INSERT INTO queries (unix_time, node, client_ip, domain, type, upstream, latency, dnssec, response_code, client_hostname, blocked, latency_alert, matched_rule, block_reason, cache_status, cache_ttl, negative_soa) VALUES "
	const rowPlaceholders = "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
	for start := 0; start < len(events); start += archiveInsertRows {
		end := min(start+archiveInsertRows, len(events))
		var query strings.Builder
		query.Grow(len(insertPrefix) + (end-start)*(len(rowPlaceholders)+1))
		query.WriteString(insertPrefix)
		args := make([]any, 0, (end-start)*17)
		for index, event := range events[start:end] {
			if index > 0 {
				query.WriteByte(',')
			}
			query.WriteString(rowPlaceholders)
			blocked := 0
			if event.Blocked {
				blocked = 1
			}
			latencyAlert := 0
			if event.LatencyAlert {
				latencyAlert = 1
			}
			args = append(args, event.UnixTime, event.Node, event.ClientIP, event.Domain, event.Type, event.Upstream, event.Latency, event.DNSSEC, event.ResponseCode, event.ClientHostname, blocked, latencyAlert, event.MatchedRule, event.BlockReason, event.CacheStatus, event.CacheTTL, event.NegativeSOA)
		}
		if _, err = tx.ExecContext(ctx, query.String(), args...); err != nil {
			_ = tx.Rollback()
			s.recordDBError(err)
			return fmt.Errorf("insert batch of %d events: %w", len(events), err)
		}
	}
	if err := upsertHourlyAggregates(ctx, tx, events); err != nil {
		_ = tx.Rollback()
		s.recordDBError(err)
		return fmt.Errorf("update hourly aggregates for %d events: %w", len(events), err)
	}
	if err := tx.Commit(); err != nil {
		s.recordDBError(err)
		return fmt.Errorf("commit batch of %d events: %w", len(events), err)
	}
	return nil
}

// ArchiveMetrics returns current queue pressure, configured limits, and the
// lifetime number of events dropped at the hard limit.
func (s *Store) ArchiveMetrics() ArchiveQueueMetrics {
	s.batchMu.Lock()
	pending := s.pendingBatchLenLocked() + int(s.batchInFlight.Load())
	pendingBytes := s.batchBytes + s.batchFlightBytes.Load()
	s.batchMu.Unlock()
	return ArchiveQueueMetrics{
		Pending:      pending,
		PendingBytes: pendingBytes,
		Dropped:      s.batchDropped.Load(),
		Capacity:     s.archiveLimit,
		Trigger:      s.archiveMark,
		WriteBatch:   s.archiveBatch,
	}
}

func (s *Store) flushArchiveDropWarning() {
	s.batchMu.Lock()
	unreported := s.batchDropUnreported
	s.batchDropUnreported = 0
	if unreported > 0 {
		s.batchDropLogAt = time.Now()
	}
	pending := s.pendingBatchLenLocked()
	s.batchMu.Unlock()
	if unreported > 0 {
		log.Printf("[WARN] SQLite archive recovered after dropping %d additional event(s) (%d total); %d event(s) remain pending", unreported, s.batchDropped.Load(), pending)
	}
}

func (s *Store) pruneOldEvents(ctx context.Context, now time.Time) {
	cutoff := now.Add(-s.cfg.HistoryRetention).Unix()
	deleted, err := pruneRetentionBatch(ctx, s.db, cutoff)
	if err != nil {
		s.recordDBError(err)
		log.Printf("Failed to prune old SQLite data: %v", err)
	} else if deleted == retentionDeleteBatch {
		log.Printf("SQLite retention deleted a bounded batch of %d rows; remaining expired rows will be pruned on a later archive pass", deleted)
	}
}

func (s *Store) startVacuum(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(s.vacuumInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.dbMu.RLock()
				if s.closed || s.db == nil {
					s.dbMu.RUnlock()
					return
				}
				start := time.Now()
				var mode int
				err := s.db.QueryRowContext(ctx, "PRAGMA auto_vacuum").Scan(&mode)
				pagesRequested := 0
				if err == nil && mode == 2 {
					pagesRequested = incrementalVacuumPages
					_, err = s.db.ExecContext(ctx, "PRAGMA incremental_vacuum(200)")
				}
				duration := time.Since(start)
				s.maintenanceMu.Lock()
				s.vacuumState = vacuumState{
					At: start, Duration: duration, PagesRequested: pagesRequested,
				}
				if err != nil {
					s.vacuumState.Error = err.Error()
				}
				s.maintenanceMu.Unlock()
				switch {
				case err != nil:
					s.recordDBError(err)
					log.Printf("Incremental database vacuum failed: %v", err)
				case mode == 2:
					log.Printf("Incremental database vacuum completed in %s", duration.Round(time.Millisecond))
				default:
					log.Printf("Database auto_vacuum is not incremental; skipping blocking VACUUM and exposing a maintenance recommendation")
				}
				s.dbMu.RUnlock()
			}
		}
	}()
	log.Printf("Periodic incremental vacuum check started (interval: %s)", s.vacuumInterval)
}

// startWALCheckpoint runs a background goroutine that periodically executes
// PRAGMA wal_checkpoint(TRUNCATE) to prevent the WAL file from growing too large.
// Default interval: 5 minutes.
func (s *Store) startWALCheckpoint(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(s.checkpointInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.dbMu.RLock()
				if s.closed || s.db == nil {
					s.dbMu.RUnlock()
					return
				}
				var busy, logFrames, checkpointed int
				started := time.Now()
				row := s.db.QueryRowContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE);")
				err := row.Scan(&busy, &logFrames, &checkpointed)
				duration := time.Since(started)
				s.maintenanceMu.Lock()
				s.checkpointState = checkpointState{
					At: started, Duration: duration, Busy: busy,
					LogFrames: logFrames, Checkpointed: checkpointed,
				}
				if err != nil {
					s.checkpointState.Error = err.Error()
				}
				s.maintenanceMu.Unlock()
				if err != nil {
					s.recordDBError(err)
					log.Printf("WAL checkpoint failed: %v", err)
				} else {
					log.Printf("WAL checkpoint completed: busy=%d, logFrames=%d, checkpointed=%d", busy, logFrames, checkpointed)
				}
				s.dbMu.RUnlock()
			}
		}
	}()
	log.Printf("Periodic WAL checkpoint started (interval: %s)", s.checkpointInterval)
}

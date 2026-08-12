package forwarder

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/arumes31/resolix/webgui/internal/config"
	"github.com/arumes31/resolix/webgui/internal/models"
)

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

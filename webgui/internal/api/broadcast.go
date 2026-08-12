package api

import (
	"log"

	"github.com/arumes31/resolix/webgui/internal/models"
)

// Subscribe registers a channel to receive broadcast events.
// Returns the channel that the caller should read from.
func (s *Server) Subscribe() chan models.QueryEvent {
	ch := make(chan models.QueryEvent, 100)
	s.subMu.Lock()
	s.subscribers[ch] = 0
	s.subMu.Unlock()
	return ch
}

// Unsubscribe removes a subscriber channel. BroadcastEvent owns channel
// closure so removal cannot race with a concurrent send.
func (s *Server) Unsubscribe(ch chan models.QueryEvent) {
	s.subMu.Lock()
	delete(s.subscribers, ch)
	s.subMu.Unlock()
}

// BroadcastEvent safely sends an event to all SSE subscribers.
// Slow subscribers are handled with non-blocking sends; if a subscriber's
// channel is full, the event is dropped and the drop counter is incremented.
// Subscribers that exceed 10 consecutive drops are removed.
func (s *Server) BroadcastEvent(e models.QueryEvent) {
	if e.ID == "" && s.store != nil {
		e = s.store.AssignEventID(e)
	}

	// Item 59: Enrich with reverse DNS hostname
	s.fieldsMu.RLock()
	res := s.resolver
	bl := s.blocklist
	s.fieldsMu.RUnlock()

	if res != nil && e.ClientIP != "" {
		if hostname := res.GetHostname(e.ClientIP); hostname != "" {
			e.ClientHostname = hostname
		}
	}

	// Item 61: Check blocklist — fallback for legacy-ingested events only;
	// the DNS pipeline (filter engine) is the source of truth for Blocked.
	if !e.Blocked && bl != nil && e.Domain != "" {
		if bl.IsBlocked(e.Domain) {
			e.Blocked = true
		}
	}

	// Update Prometheus metrics
	s.metrics.QueriesTotal.Add(1)
	s.metrics.IncQueriesByType(e.Type)
	if e.Blocked {
		s.metrics.QueriesBlocked.Add(1)
	}
	if e.Upstream == "System Cache" {
		s.metrics.CacheHits.Add(1)
	} else if e.Upstream != "" {
		s.metrics.CacheMisses.Add(1)
	}
	if e.Latency.Valid && e.Upstream != "" && e.Upstream != "System Cache" && e.Upstream != "Local Override" {
		s.metrics.RecordUpstreamLatency(e.Upstream, e.Latency.Float64)
	}

	s.subMu.Lock()
	defer s.subMu.Unlock()
	for ch, drops := range s.subscribers {
		select {
		case ch <- e:
			if drops > 0 {
				s.subscribers[ch] = 0
			}
		default:
			s.subDropCnt.Add(1)
			s.subscribers[ch] = drops + 1
			if s.subscribers[ch] > 10 {
				log.Printf("Dropping slow subscriber")
				delete(s.subscribers, ch)
				close(ch)
			}
		}
	}
}

// Broadcast is a convenience method that calls BroadcastEvent.
// It enriches the event with hostname and blocklist data before broadcasting.
func (s *Server) Broadcast(e models.QueryEvent) {
	s.BroadcastEvent(e)
}

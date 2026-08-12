package storage

import (
	"time"

	"github.com/arumes31/resolix/webgui/internal/config"
)

// CleanupPending removes stale entries from the pending query map.
func (s *Store) CleanupPending(now time.Time) {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	cutoff := now.Add(-30 * time.Second)
	for node, domains := range s.pendingQueries {
		for domain, infos := range domains {
			newInfos := make([]pendingInfo, 0)
			for _, info := range infos {
				if info.startTime.After(cutoff) {
					newInfos = append(newInfos, info)
				}
			}
			if len(newInfos) == 0 {
				delete(domains, domain)
			} else {
				domains[domain] = newInfos
			}
		}
		if len(domains) == 0 {
			delete(s.pendingQueries, node)
		}
	}

	s.statsMu.Lock()
	clientCutoff := now.Add(-time.Hour).Unix()
	for client, lastSeen := range s.clientLastSeen {
		if lastSeen >= clientCutoff {
			continue
		}
		delete(s.clientLastSeen, client)
		delete(s.clientRPMBuckets, client)
		delete(s.clientRPMTimes, client)
		delete(s.clientRPHBuckets, client)
		delete(s.clientRPHTimes, client)
	}
	s.statsMu.Unlock()
}

// SetPending records the start time of a DNS query.
func (s *Store) SetPending(node, domain string, t time.Time) {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	if s.pendingQueries[node] == nil {
		s.pendingQueries[node] = make(map[string][]pendingInfo)
	}
	s.pendingQueries[node][domain] = append(s.pendingQueries[node][domain], pendingInfo{startTime: t})
}

// GetPending retrieves and removes the oldest pending DNS query for a domain.
func (s *Store) GetPending(node, domain string) (time.Time, string, bool) {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()

	if s.pendingQueries[node] == nil {
		return time.Time{}, "", false
	}
	infos := s.pendingQueries[node][domain]
	if len(infos) == 0 {
		return time.Time{}, "", false
	}

	info := infos[0]
	if len(infos) == 1 {
		delete(s.pendingQueries[node], domain)
	} else {
		s.pendingQueries[node][domain] = infos[1:]
	}
	return info.startTime, info.upstream, true
}

// SetUpstream records the upstream server used for the latest query of a domain.
func (s *Store) SetUpstream(node, domain, upstream string) {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	if s.pendingQueries[node] == nil {
		return
	}
	infos := s.pendingQueries[node][domain]
	if len(infos) == 0 {
		return
	}
	infos[len(infos)-1].upstream = upstream
}

// SetDNSSEC updates the DNSSEC validation status for the most recent query of a domain on a node.
func (s *Store) SetDNSSEC(node, domain, result string) {
	s.eventsMu.Lock()
	defer s.eventsMu.Unlock()

	scanLimit := s.count
	if scanLimit > config.DefaultScanLimit {
		scanLimit = config.DefaultScanLimit
	}
	for i := 0; i < scanLimit; i++ {
		idx := (s.head - 1 - i + s.cfg.MaxEvents) % s.cfg.MaxEvents
		if s.events[idx].Domain == domain && s.events[idx].Node == node {
			s.events[idx].DNSSEC = result
			// Also update in the pending batch
			s.batchMu.Lock()
			for b := len(s.batch) - 1; b >= s.batchStart; b-- {
				if s.batch[b].Domain == domain && s.batch[b].Node == node {
					beforeBytes := eventApproxBytes(s.batch[b])
					s.batch[b].DNSSEC = result
					s.batchBytes += eventApproxBytes(s.batch[b]) - beforeBytes
					break
				}
			}
			s.batchMu.Unlock()
			return
		}
	}
}

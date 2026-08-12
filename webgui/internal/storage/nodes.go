package storage

import (
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/arumes31/resolix/webgui/internal/models"
)

// SetUpstreamHealth updates the upstream DNS latency history for a node.
func (s *Store) SetUpstreamHealth(node string, health map[string]float64) {
	if node == "" {
		node = "local"
	}
	s.nodeStatusMu.RLock()
	if _, tombstoned := s.nodeTombstones[node]; tombstoned {
		s.nodeStatusMu.RUnlock()
		return
	}
	defer s.nodeStatusMu.RUnlock()
	s.healthMu.Lock()
	defer s.healthMu.Unlock()

	if s.nodeUpstreamHealth[node] == nil {
		s.nodeUpstreamHealth[node] = make(map[string]float64)
		s.nodeUpstreamHealthHistory[node] = make(map[string][]float64)
	}

	s.nodeUpstreamHealth[node] = health
	for ip, lat := range health {
		hist := s.nodeUpstreamHealthHistory[node][ip]
		hist = append(hist, lat)
		if len(hist) > 20 {
			hist = hist[1:]
		}
		s.nodeUpstreamHealthHistory[node][ip] = hist
	}
}

// GetUpstreamHealth returns a deep copy of the current upstream health data (node -> upstream -> latency).
// This is the exported accessor for the unexported nodeUpstreamHealth map.
func (s *Store) GetUpstreamHealth() map[string]map[string]float64 {
	s.healthMu.RLock()
	defer s.healthMu.RUnlock()

	result := make(map[string]map[string]float64, len(s.nodeUpstreamHealth))
	for node, upstreams := range s.nodeUpstreamHealth {
		result[node] = make(map[string]float64, len(upstreams))
		for up, lat := range upstreams {
			result[node][up] = lat
		}
	}
	return result
}

// SetNodeStatus updates a legacy name-addressed status. New cluster traffic
// should use SetNodeStatusIdentity so equal display names cannot overwrite one
// another.
func (s *Store) SetNodeStatus(name string, status models.NodeStatus) {
	_ = s.SetNodeStatusIdentity(status.ID, name, status)
}

// SetNodeStatusIdentity updates a node keyed by its stable identity. It returns
// false for a tombstoned identity, requiring an explicit restore before a
// decommissioned node can silently rejoin.
func (s *Store) SetNodeStatusIdentity(identity, name string, status models.NodeStatus) bool {
	if name == "" {
		name = "unknown"
	}
	identity = strings.TrimSpace(identity)
	if identity == "" {
		identity = name
	}
	s.nodeStatusMu.Lock()
	defer s.nodeStatusMu.Unlock()
	if _, tombstoned := s.nodeTombstones[identity]; tombstoned {
		return false
	}

	status.ID = identity
	status.Name = name
	status.Online = true
	status.LastSeen = time.Now()
	status.UpstreamHealth = cloneFloatMap(status.UpstreamHealth)
	status.ForwarderEndpointErrors = cloneStringMap(status.ForwarderEndpointErrors)
	s.nodeStatuses[identity] = &status
	s.refreshDuplicateNameWarningsLocked(name)
	return true
}

// GetNodeStatus returns the status of a single node by name.
func (s *Store) GetNodeStatus(name string) *models.NodeStatus {
	s.nodeStatusMu.RLock()
	defer s.nodeStatusMu.RUnlock()

	if ns, ok := s.nodeStatuses[name]; ok {
		return s.cloneNodeStatus(ns)
	}
	for _, ns := range s.nodeStatuses {
		if ns.Name == name {
			return s.cloneNodeStatus(ns)
		}
	}
	return nil
}

// GetNodeStatusByID returns a node only when its stable identity matches.
func (s *Store) GetNodeStatusByID(identity string) *models.NodeStatus {
	s.nodeStatusMu.RLock()
	defer s.nodeStatusMu.RUnlock()
	status := s.nodeStatuses[strings.TrimSpace(identity)]
	if status == nil {
		return nil
	}
	return s.cloneNodeStatus(status)
}

// GetNodeStatuses returns a copy of all node statuses with online state computed.
func (s *Store) GetNodeStatuses() []models.NodeStatus {
	s.nodeStatusMu.RLock()
	defer s.nodeStatusMu.RUnlock()

	result := make([]models.NodeStatus, 0, len(s.nodeStatuses))
	for _, ns := range s.nodeStatuses {
		result = append(result, *s.cloneNodeStatus(ns))
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Name == result[j].Name {
			return result[i].ID < result[j].ID
		}
		return result[i].Name < result[j].Name
	})
	return result
}

// DecommissionNode tombstones a stable identity and removes volatile status
// and health without deleting archived query history.
func (s *Store) DecommissionNode(identity string) (bool, error) {
	identity = strings.TrimSpace(identity)
	s.nodeStatusMu.Lock()
	status := s.nodeStatuses[identity]
	if status == nil {
		s.nodeStatusMu.Unlock()
		return false, nil
	}
	decommissionedAt := time.Now()
	s.dbMu.RLock()
	if s.closed || s.db == nil {
		s.dbMu.RUnlock()
		s.nodeStatusMu.Unlock()
		return false, errors.New("persist node tombstone: database is not available")
	}
	_, err := s.db.Exec(`INSERT INTO node_tombstones(node_id, node_name, decommissioned_at)
		VALUES (?, ?, ?) ON CONFLICT(node_id) DO UPDATE SET
		node_name = excluded.node_name, decommissioned_at = excluded.decommissioned_at`,
		identity, status.Name, decommissionedAt.Unix())
	s.dbMu.RUnlock()
	if err != nil {
		s.recordDBError(err)
		s.nodeStatusMu.Unlock()
		return false, fmt.Errorf("persist node tombstone: %w", err)
	}
	delete(s.nodeStatuses, identity)
	s.nodeTombstones[identity] = decommissionedAt
	s.refreshDuplicateNameWarningsLocked(status.Name)
	s.nodeStatusMu.Unlock()

	s.healthMu.Lock()
	delete(s.nodeUpstreamHealth, identity)
	delete(s.nodeUpstreamHealthHistory, identity)
	s.healthMu.Unlock()
	return true, nil
}

// RestoreNode removes a stable tombstone. The node remains absent until its
// next authenticated heartbeat.
func (s *Store) RestoreNode(identity string) (bool, error) {
	identity = strings.TrimSpace(identity)
	s.nodeStatusMu.Lock()
	_, existed := s.nodeTombstones[identity]
	if !existed {
		s.nodeStatusMu.Unlock()
		return false, nil
	}
	s.dbMu.RLock()
	if s.closed || s.db == nil {
		s.dbMu.RUnlock()
		s.nodeStatusMu.Unlock()
		return false, errors.New("remove node tombstone: database is not available")
	}
	_, err := s.db.Exec("DELETE FROM node_tombstones WHERE node_id = ?", identity)
	s.dbMu.RUnlock()
	if err != nil {
		s.recordDBError(err)
		s.nodeStatusMu.Unlock()
		return false, fmt.Errorf("remove node tombstone: %w", err)
	}
	delete(s.nodeTombstones, identity)
	s.nodeStatusMu.Unlock()
	return true, nil
}

// IsNodeTombstoned reports whether an identity requires explicit restoration.
func (s *Store) IsNodeTombstoned(identity string) bool {
	s.nodeStatusMu.RLock()
	_, ok := s.nodeTombstones[strings.TrimSpace(identity)]
	s.nodeStatusMu.RUnlock()
	return ok
}

func (s *Store) loadNodeTombstones() {
	rows, err := s.db.Query("SELECT node_id, decommissioned_at FROM node_tombstones")
	if err != nil {
		log.Printf("[WARN] Load node tombstones: %v", err)
		return
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var identity string
		var unixTime int64
		if err := rows.Scan(&identity, &unixTime); err != nil {
			log.Printf("[WARN] Read node tombstone: %v", err)
			continue
		}
		s.nodeTombstones[identity] = time.Unix(unixTime, 0)
	}
}

func (s *Store) refreshDuplicateNameWarningsLocked(name string) {
	count := 0
	for _, status := range s.nodeStatuses {
		if status.Name == name {
			count++
		}
	}
	for _, status := range s.nodeStatuses {
		if status.Name == name {
			status.DuplicateNameWarning = count > 1
		}
	}
}

func (s *Store) cloneNodeStatus(status *models.NodeStatus) *models.NodeStatus {
	result := *status
	result.Online = status.IsOnline(s.cfg.NodeOfflineThreshold)
	result.UpstreamHealth = cloneFloatMap(status.UpstreamHealth)
	result.ForwarderEndpointErrors = cloneStringMap(status.ForwarderEndpointErrors)
	return &result
}

func cloneFloatMap(source map[string]float64) map[string]float64 {
	if source == nil {
		return nil
	}
	cloned := make(map[string]float64, len(source))
	for key, value := range source {
		cloned[key] = value
	}
	return cloned
}

func cloneStringMap(source map[string]string) map[string]string {
	if source == nil {
		return nil
	}
	cloned := make(map[string]string, len(source))
	for key, value := range source {
		cloned[key] = value
	}
	return cloned
}

// GetAlias returns the friendly name for a client IP if configured.
func (s *Store) GetAlias(ip string) string {
	return s.cfg.GetClientAlias(ip)
}

package api

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/arumes31/resolix/webgui/internal/models"
)

func sanitizeLogValue(s string) string {
	return strings.NewReplacer("\r", "", "\n", "").Replace(s)
}

func requestNodeIdentity(r *http.Request, fallbackName string) string {
	return normalizeNodeIdentity(r.Header.Get("X-Node-ID"), fallbackName)
}

const maxNodeIdentityLength = 128

func normalizeNodeIdentity(value, fallbackName string) string {
	fallbackName = strings.TrimSpace(fallbackName)
	if len(fallbackName) > maxNodeIdentityLength {
		fallbackName = ""
	}
	identity := strings.TrimSpace(value)
	if identity == "" || len(identity) > maxNodeIdentityLength {
		return fallbackName
	}
	for _, char := range identity {
		if !isAllowedNodeIdentityRune(char) {
			return fallbackName
		}
	}
	return identity
}

func (s *Server) establishIngestNodeStatus(w http.ResponseWriter, r *http.Request, identity, node string) bool {
	if node == "" {
		return true
	}
	if identity == "" {
		http.Error(w, "invalid node identity", http.StatusBadRequest)
		return false
	}
	status := models.NodeStatus{ID: identity, Name: node}
	if existing := s.store.GetNodeStatus(identity); existing != nil {
		status = *existing
	}
	if v := r.Header.Get("X-Node-Version"); v != "" {
		status.Version = v
	}
	if v := r.Header.Get("X-Go-Version"); v != "" {
		status.GoVersion = v
	}
	if v := r.Header.Get("X-Node-Build"); v != "" {
		status.BuildInfo = v
	}
	if !s.store.SetNodeStatusIdentity(identity, node, status) {
		http.Error(w, "node is decommissioned", http.StatusGone)
		return false
	}
	return true
}

func isAllowedNodeIdentityRune(char rune) bool {
	return char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' ||
		char >= '0' && char <= '9' || strings.ContainsRune("._:-", char)
}

// clientIP extracts the client IP from the request. Forwarded headers are
// honored only when the immediate peer is explicitly trusted; the
// X-Forwarded-For list is then walked right-to-left and the first address
// that is not itself a trusted proxy is returned.
func (s *Server) clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" && s.isTrustedProxy(r) {
		parts := strings.Split(xff, ",")
		for i := len(parts) - 1; i >= 0; i-- {
			ip := strings.TrimSpace(parts[i])
			if ip != "" && !s.isTrustedProxyIP(ip) {
				return ip
			}
		}
	}
	if forwarded := r.Header.Get("Forwarded"); forwarded != "" && s.isTrustedProxy(r) {
		entries := strings.Split(forwarded, ",")
		for i := len(entries) - 1; i >= 0; i-- {
			for _, parameter := range strings.Split(entries[i], ";") {
				key, value, ok := strings.Cut(strings.TrimSpace(parameter), "=")
				if !ok || !strings.EqualFold(key, "for") {
					continue
				}
				ip := strings.Trim(strings.TrimSpace(value), `"`)
				if host, _, err := net.SplitHostPort(ip); err == nil {
					ip = host
				}
				ip = strings.Trim(ip, "[]")
				if net.ParseIP(ip) != nil && !s.isTrustedProxyIP(ip) {
					return ip
				}
			}
		}
	}
	return remoteIP(r)
}

func (s *Server) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Authenticate with IngestSecret (same as ingest endpoint)
	if s.cfg.IngestSecret != "" {
		auth := r.Header.Get("Authorization")
		expected := "Bearer " + s.cfg.IngestSecret
		if subtle.ConstantTimeCompare([]byte(auth), []byte(expected)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}

	body, err := readRequestBody(w, r, s.cfg.MaxRequestSize)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
		} else {
			http.Error(w, "invalid payload", http.StatusBadRequest)
		}
		return
	}
	var hb models.HeartbeatPayload
	if err := json.Unmarshal(body, &hb); err != nil {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}

	if hb.Node == "" {
		http.Error(w, "missing node name", http.StatusBadRequest)
		return
	}
	identity := normalizeNodeIdentity(hb.NodeID, hb.Node)
	if identity == "" {
		http.Error(w, "invalid node identity", http.StatusBadRequest)
		return
	}
	if headerIdentity := strings.TrimSpace(r.Header.Get("X-Node-ID")); headerIdentity != "" {
		normalizedHeader := normalizeNodeIdentity(headerIdentity, "")
		if normalizedHeader == "" || (hb.NodeID != "" && normalizedHeader != identity) {
			http.Error(w, "node identity mismatch", http.StatusBadRequest)
			return
		}
		identity = normalizedHeader
	}
	if s.store.IsNodeTombstoned(identity) {
		http.Error(w, "node is decommissioned", http.StatusGone)
		return
	}

	// Extract version info from headers (Item 88)
	nodeVersion := r.Header.Get("X-Node-Version")
	goVersion := r.Header.Get("X-Go-Version")
	buildInfo := r.Header.Get("X-Node-Build")

	// Use header values if payload fields are empty
	if hb.Version == "" && nodeVersion != "" {
		hb.Version = nodeVersion
	}
	if hb.GoVersion == "" && goVersion != "" {
		hb.GoVersion = goVersion
	}
	if hb.BuildInfo == "" && buildInfo != "" {
		hb.BuildInfo = buildInfo
	}

	clockSkewMS := int64(0)
	if !hb.SentAt.IsZero() {
		clockSkewMS = time.Since(hb.SentAt).Milliseconds()
	}
	sourceAddress := r.RemoteAddr
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		sourceAddress = host
	}

	// Update node status in storage.
	status := models.NodeStatus{
		ID:                      identity,
		Name:                    hb.Node,
		Version:                 hb.Version,
		GoVersion:               hb.GoVersion,
		BuildInfo:               hb.BuildInfo,
		MemoryMB:                hb.MemoryMB,
		Goroutines:              hb.Goroutines,
		DBSizeMB:                hb.DBSizeMB,
		UpstreamHealth:          hb.Health,
		ConfigRevision:          hb.ConfigRevision,
		DesiredConfigRevision:   hb.DesiredConfigRevision,
		PreviousConfigRevision:  hb.PreviousConfigRevision,
		ConfigSchemaVersion:     hb.ConfigSchemaVersion,
		ConfigSchemaCompatible:  hb.ConfigSchemaCompatible,
		ConfigApplyError:        hb.ConfigApplyError,
		ConfigApplyDurationMS:   hb.ConfigApplyDurationMS,
		ClockSkewMS:             clockSkewMS,
		ForwarderBacklogDepth:   hb.ForwarderBacklogDepth,
		ForwarderBacklogBytes:   hb.ForwarderBacklogBytes,
		ForwarderBacklogOldestS: hb.ForwarderBacklogOldestS,
		ForwarderEndpointErrors: hb.ForwarderEndpointErrors,
		LastIngestError:         hb.LastIngestError,
		LastHeartbeatError:      hb.LastHeartbeatError,
		LastConfigSyncError:     hb.LastConfigSyncError,
		SourceAddress:           sourceAddress,
	}
	if !s.store.SetNodeStatusIdentity(identity, hb.Node, status) {
		http.Error(w, "node is decommissioned", http.StatusGone)
		return
	}

	// Also store upstream health if provided
	if len(hb.Health) > 0 {
		s.store.SetUpstreamHealth(identity, hb.Health)
	}

	log.Printf("[INFO] Heartbeat received from node %s (v%s, %d goroutines, %.1fMB mem)", // #nosec G706 -- CR/LF stripped by sanitizeLogValue; gosec taint analysis cannot see through the helper
		sanitizeLogValue(hb.Node), sanitizeLogValue(hb.Version), hb.Goroutines, hb.MemoryMB)

	w.Header().Set("X-Config-Sync-Generation", s.syncGenerationFor(identity))
	w.WriteHeader(http.StatusNoContent)
}

// ===== Item 90: Sync Client Aliases Endpoint =====
// handleSyncAliases returns the current client aliases configuration.
// Agents call this to sync their aliases with the controller.
func (s *Server) handleSyncAliases(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Authenticate with IngestSecret
	if s.cfg.IngestSecret != "" {
		auth := r.Header.Get("Authorization")
		expected := "Bearer " + s.cfg.IngestSecret
		if subtle.ConstantTimeCompare([]byte(auth), []byte(expected)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}

	aliases := s.cfg.GetAllClientAliases()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(aliases)
}

// ===== Item 91: Sync DNS Routes Endpoint =====
// handleSyncDNSRoutes returns the current DNS routes configuration.
// Agents call this to sync their DNS routes with the controller.
func (s *Server) handleSyncDNSRoutes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Authenticate with IngestSecret
	if s.cfg.IngestSecret != "" {
		auth := r.Header.Get("Authorization")
		expected := "Bearer " + s.cfg.IngestSecret
		if subtle.ConstantTimeCompare([]byte(auth), []byte(expected)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}

	routes := make(map[string]string)
	s.fieldsMu.RLock()
	dr := s.dnsRoutes
	s.fieldsMu.RUnlock()
	if dr != nil {
		routes = dr.GetRoutesMap()
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"routes": routes,
	})
}

// ===== Item 94: Sync Upstream Health Endpoint =====
// handleSyncUpstreamHealth returns the upstream health data for all nodes.
// Agents call this to sync their upstream health view with the controller.
func (s *Server) handleSyncUpstreamHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Authenticate with IngestSecret
	if s.cfg.IngestSecret != "" {
		auth := r.Header.Get("Authorization")
		expected := "Bearer " + s.cfg.IngestSecret
		if subtle.ConstantTimeCompare([]byte(auth), []byte(expected)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}

	healthData := s.store.GetUpstreamHealth()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(healthData)
}

// ===== Item 89: Node Discovery and Status Endpoint =====
// handleNodes returns node status or safely decommissions an offline node.
func (s *Server) handleNodes(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		nodes := s.store.GetNodeStatuses()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"nodes": nodes})
	case http.MethodDelete:
		if !s.requireController(w) || !s.checkCSRF(w, r) {
			return
		}
		identifier := strings.TrimSpace(r.URL.Query().Get("id"))
		if identifier == "" || len(identifier) > maxNodeIdentityLength {
			http.Error(w, "A stable node id is required", http.StatusBadRequest)
			return
		}
		status := s.store.GetNodeStatusByID(identifier)
		if status == nil {
			http.Error(w, "Node not found", http.StatusNotFound)
			return
		}
		if status.Online && r.URL.Query().Get("force") != "true" {
			http.Error(w, "Node is online; retry with force=true only after stopping it", http.StatusConflict)
			return
		}
		decommissioned, err := s.store.DecommissionNode(status.ID)
		if err != nil {
			http.Error(w, "Failed to persist node decommission", http.StatusInternalServerError)
			return
		}
		if !decommissioned {
			http.Error(w, "Node not found", http.StatusNotFound)
			return
		}
		s.syncRequestMu.Lock()
		delete(s.nodeSyncGenerations, status.ID)
		s.syncRequestMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status": "decommissioned", "node": status.Name, "id": status.ID,
		})
	case http.MethodPost:
		if !s.requireController(w) || !s.checkCSRF(w, r) {
			return
		}
		if r.URL.Query().Get("action") != "restore" {
			http.Error(w, "Unsupported node action", http.StatusBadRequest)
			return
		}
		identity := strings.TrimSpace(r.URL.Query().Get("id"))
		if identity == "" || len(identity) > maxNodeIdentityLength {
			http.Error(w, "A stable node identity is required", http.StatusBadRequest)
			return
		}
		restored, err := s.store.RestoreNode(identity)
		if err != nil {
			http.Error(w, "Failed to persist node restoration", http.StatusInternalServerError)
			return
		}
		if !restored {
			http.Error(w, "Node tombstone not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "restored", "id": identity})
	default:
		w.Header().Set("Allow", "GET, POST, DELETE")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

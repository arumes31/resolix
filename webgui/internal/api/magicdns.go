package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/arumes31/resolix/webgui/internal/config"
	"github.com/arumes31/resolix/webgui/internal/magicdns"
)

func (s *Server) magicDNSStatus() map[string]interface{} {
	s.fieldsMu.RLock()
	store := s.magicDNSStore
	syncer := s.magicDNSSync
	s.fieldsMu.RUnlock()
	snapshot := magicdns.Snapshot{Version: magicdns.SnapshotVersion, Records: make([]magicdns.Record, 0)}
	if store != nil {
		snapshot = store.Snapshot()
	}
	status := magicdns.Status{RecordCount: len(snapshot.Records)}
	deviceIDs := make(map[string]struct{})
	for _, record := range snapshot.Records {
		deviceIDs[record.NodeID] = struct{}{}
	}
	status.DeviceCount = len(deviceIDs)
	if syncer != nil {
		syncStatus := syncer.Status()
		if syncStatus.LastSuccess.IsZero() {
			syncStatus.DeviceCount = status.DeviceCount
			syncStatus.RecordCount = status.RecordCount
		}
		status = syncStatus
	}
	preview := snapshot.Records
	const previewLimit = 200
	if len(preview) > previewLimit {
		preview = preview[:previewLimit]
	}
	return map[string]interface{}{
		"mode":                   s.cfg.Mode,
		"enabled":                s.cfg.MagicDNSEnabled,
		"editable":               s.isController(),
		"tailnet":                snapshotTailnet(snapshot, s.cfg.MagicDNSTailnet),
		"credentials_configured": strings.TrimSpace(s.cfg.MagicDNSClientID) != "" && strings.TrimSpace(s.cfg.MagicDNSClientSecret) != "",
		"sync_interval":          s.cfg.MagicDNSSyncInterval.String(),
		"ttl":                    s.cfg.MagicDNSTTL,
		"generation":             snapshot.Generation,
		"synced_at":              snapshot.SyncedAt,
		"records":                preview,
		"records_truncated":      len(snapshot.Records) > len(preview),
		"status":                 status,
	}
}

func snapshotTailnet(snapshot magicdns.Snapshot, configured string) string {
	if strings.TrimSpace(snapshot.Tailnet) != "" {
		return snapshot.Tailnet
	}
	return strings.TrimSpace(configured)
}

func (s *Server) handleMagicDNSStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.magicDNSStatus())
}

func (s *Server) handleMagicDNSSync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.cfg.Mode != config.ModeController {
		http.Error(w, "MagicDNS synchronization is controller-owned", http.StatusForbidden)
		return
	}
	s.fieldsMu.RLock()
	syncer := s.magicDNSSync
	s.fieldsMu.RUnlock()
	if syncer == nil || !s.cfg.MagicDNSEnabled {
		http.Error(w, "MagicDNS synchronization is not enabled", http.StatusConflict)
		return
	}
	if err := syncer.Sync(r.Context()); err != nil {
		http.Error(w, "MagicDNS synchronization failed", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.magicDNSStatus())
}

func (s *Server) handleSyncMagicDNS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.fieldsMu.RLock()
	store := s.magicDNSStore
	s.fieldsMu.RUnlock()
	if store == nil {
		http.Error(w, "MagicDNS store is unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(store.Snapshot())
}

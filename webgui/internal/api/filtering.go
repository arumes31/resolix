package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/arumes31/resolix/webgui/internal/clients"
)

func (s *Server) handleBlocklistStatus(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	s.fieldsMu.RLock()
	bl := s.blocklist
	s.fieldsMu.RUnlock()
	if bl == nil {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"count": 0,
			"file":  "",
		})
		return
	}
	_ = json.NewEncoder(w).Encode(bl.Status())
}

// ===== Filter Engine Endpoints =====

// handleFilteringStatus reports the filter engine state: enabled/paused,
// per-source rule counts, and last update times.
func (s *Server) handleFilteringStatus(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	eng := s.getFilter()
	if eng == nil {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"enabled": true,
			"sources": []interface{}{},
		})
		return
	}
	blocked, allowed := eng.Stats()
	resp := map[string]interface{}{
		"enabled":                 !eng.Paused(),
		"sources":                 eng.Sources(),
		"update_interval_seconds": int64(s.cfg.FilterUpdateInterval.Seconds()),
		"allowlist_overrides":     eng.AllowlistOverrides(100),
		"filter_blocked_total":    blocked,
		"filter_allowed_total":    allowed,
	}
	if until := eng.PausedUntil(); !until.IsZero() {
		resp["paused_until"] = until.Format(time.RFC3339)
	}
	_ = json.NewEncoder(w).Encode(resp)
}

// handleFilteringPause pauses protection for N minutes (POST {"minutes": n});
// minutes <= 0 resumes immediately.
func (s *Server) handleFilteringPause(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireController(w) {
		return
	}
	if !s.checkCSRF(w, r) {
		return
	}
	eng := s.getFilter()
	if eng == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "filter engine is not configured",
		})
		return
	}

	var req struct {
		Minutes int `json:"minutes"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	eng.Pause(req.Minutes)
	s.invalidateDashboardStatsCache()

	resp := map[string]interface{}{"status": "ok", "enabled": !eng.Paused()}
	if until := eng.PausedUntil(); !until.IsZero() {
		resp["paused_until"] = until.Format(time.RFC3339)
	}
	_ = json.NewEncoder(w).Encode(resp)
}

// ===== Typed Rewrites CRUD =====

// handleRewrites dispatches GET (list), POST (add), PUT (update by ?id=), and
// DELETE (?id=) for typed DNS rewrites. Changes take effect live in the DNS
// pipeline.
func (s *Server) handleRewrites(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet && !s.requireController(w) {
		return
	}
	s.fieldsMu.RLock()
	store := s.rewritesStore
	s.fieldsMu.RUnlock()
	if store == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "rewrites store is not configured",
		})
		return
	}

	switch r.Method {
	case http.MethodGet:
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":   "ok",
			"rewrites": store.List(),
		})
	case http.MethodPost:
		if !s.checkCSRF(w, r) {
			return
		}
		var req struct {
			Domain      string   `json:"domain"`
			Type        string   `json:"type"`
			Value       string   `json:"value"`
			SourceCIDRs []string `json:"source_cidrs"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		rw, err := store.Add(req.Domain, req.Type, req.Value, req.SourceCIDRs...)
		if err != nil {
			http.Error(w, fmt.Sprintf("Invalid rewrite: %v", err), http.StatusBadRequest)
			return
		}
		s.clearDNSCache()
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok", "rewrite": rw})
	case http.MethodPut:
		if !s.checkCSRF(w, r) {
			return
		}
		id := r.URL.Query().Get("id")
		if id == "" {
			http.Error(w, "Missing id parameter", http.StatusBadRequest)
			return
		}
		var req struct {
			Domain      string   `json:"domain"`
			Type        string   `json:"type"`
			Value       string   `json:"value"`
			SourceCIDRs []string `json:"source_cidrs"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		rw, found, err := store.Update(id, req.Domain, req.Type, req.Value, req.SourceCIDRs...)
		if err != nil {
			http.Error(w, fmt.Sprintf("Invalid rewrite: %v", err), http.StatusBadRequest)
			return
		}
		if !found {
			http.Error(w, "Rewrite not found", http.StatusNotFound)
			return
		}
		s.clearDNSCache()
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok", "rewrite": rw})
	case http.MethodDelete:
		if !s.checkCSRF(w, r) {
			return
		}
		id := r.URL.Query().Get("id")
		if id == "" {
			http.Error(w, "Missing id parameter", http.StatusBadRequest)
			return
		}
		found, err := store.Delete(id)
		if err != nil {
			http.Error(w, "Failed to delete rewrite", http.StatusInternalServerError)
			return
		}
		if !found {
			http.Error(w, "Rewrite not found", http.StatusNotFound)
			return
		}
		s.clearDNSCache()
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok"})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// ===== Per-Client Registry CRUD =====

// handleClients dispatches GET (list), POST (add), PUT (update), and
// DELETE (?name=) for the per-client registry. Changes take effect live.
func (s *Server) handleClients(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet && !s.requireController(w) {
		return
	}
	s.fieldsMu.RLock()
	reg := s.clientsRegistry
	s.fieldsMu.RUnlock()
	if reg == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "clients registry is not configured",
		})
		return
	}

	switch r.Method {
	case http.MethodGet:
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "ok",
			"clients": reg.List(),
		})
	case http.MethodPost, http.MethodPut:
		if !s.checkCSRF(w, r) {
			return
		}
		var c clients.Client
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256*1024)).Decode(&c); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		if strings.TrimSpace(c.Name) == "" || len(c.IDs) == 0 {
			http.Error(w, "Client requires a name and at least one ID (IP or CIDR)", http.StatusBadRequest)
			return
		}
		var err error
		if r.Method == http.MethodPost {
			err = reg.Add(c)
		} else {
			err = reg.Update(c)
		}
		if err != nil {
			http.Error(w, fmt.Sprintf("Invalid client: %v", err), http.StatusBadRequest)
			return
		}
		s.clearDNSCache()
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok"})
	case http.MethodDelete:
		if !s.checkCSRF(w, r) {
			return
		}
		name := r.URL.Query().Get("name")
		if name == "" {
			http.Error(w, "Missing name parameter", http.StatusBadRequest)
			return
		}
		if !reg.Delete(name) {
			http.Error(w, "Client not found", http.StatusNotFound)
			return
		}
		s.clearDNSCache()
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok"})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// ===== Query-Log Block/Unblock Actions =====

// userRulesPath returns the filter user-rules file managed by the
// query-log actions (a plain file source of the filter engine).
func (s *Server) userRulesPath() string {
	return s.cfg.FullUserRulesPath()
}

// handleQuerylogAction adds a block rule (block=true) or removes it / adds
// an exception (block=false) for a domain, then reloads the user-rules
// source so the change takes effect immediately.
func (s *Server) handleQuerylogAction(w http.ResponseWriter, r *http.Request, block bool) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireController(w) {
		return
	}
	if !s.checkCSRF(w, r) {
		return
	}
	eng := s.getFilter()
	if eng == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "filter engine is not configured",
		})
		return
	}

	var req struct {
		Domain string `json:"domain"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	domain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(req.Domain), "."))
	_, validDomain := dns.IsDomainName(domain)
	invalidCharacter := strings.IndexFunc(domain, func(r rune) bool {
		letter := r >= 'a' && r <= 'z'
		digit := r >= '0' && r <= '9'
		return !letter && !digit && r != '-' && r != '.'
	}) >= 0
	if domain == "" || !strings.Contains(domain, ".") || !validDomain || invalidCharacter {
		http.Error(w, "Invalid domain", http.StatusBadRequest)
		return
	}

	path := s.userRulesPath()
	blockRule := "||" + domain + "^"
	exceptRule := "@@||" + domain + "^"

	userRulesMu.Lock()
	defer userRulesMu.Unlock()

	var action, rule string
	if block {
		// Blocking: drop any stale exception and add the block rule.
		if _, err := modifyUserRuleLocked(path, exceptRule, true); err != nil {
			http.Error(w, "Failed to update user rules: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if _, err := modifyUserRuleLocked(path, blockRule, false); err != nil {
			http.Error(w, "Failed to update user rules: "+err.Error(), http.StatusInternalServerError)
			return
		}
		action, rule = "blocked", blockRule
	} else {
		// Unblocking: remove the user block rule when it came from this
		// file; otherwise add an exception rule.
		removed, err := modifyUserRuleLocked(path, blockRule, true)
		if err != nil {
			http.Error(w, "Failed to update user rules: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if removed {
			action, rule = "unblocked", blockRule
		} else {
			if _, err := modifyUserRuleLocked(path, exceptRule, false); err != nil {
				http.Error(w, "Failed to update user rules: "+err.Error(), http.StatusInternalServerError)
				return
			}
			action, rule = "exception_added", exceptRule
		}
	}
	eng.ReloadSource(path)
	s.clearDNSCache()

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "ok",
		"action": action,
		"rule":   rule,
	})
}

// modifyUserRule adds or removes an exact rule line in the user rules file.
// It returns whether the file changed.
func modifyUserRule(path, ruleLine string, remove bool) (bool, error) {
	userRulesMu.Lock()
	defer userRulesMu.Unlock()
	return modifyUserRuleLocked(path, ruleLine, remove)
}

func modifyUserRuleLocked(path, ruleLine string, remove bool) (bool, error) {
	data, err := os.ReadFile(path) // #nosec G304 G703 -- path derived from trusted ConfigDir plus a constant filename, not request input
	if err != nil && !os.IsNotExist(err) {
		return false, err
	}

	var out []string
	found := false
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == ruleLine {
			found = true
			if remove {
				continue
			}
		}
		if trimmed == "" && len(out) == 0 {
			continue // skip leading empties
		}
		out = append(out, line)
	}

	changed := false
	switch {
	case remove && found:
		changed = true
	case !remove && !found:
		out = append(out, ruleLine)
		changed = true
	}
	if !changed {
		return false, nil
	}
	content := strings.Join(out, "\n")
	if !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	if err := writeFileAtomic(path, []byte(content), 0o600); err != nil {
		return false, err
	}
	return true, nil
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) (err error) {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".api-*.tmp") // #nosec G304 -- directory is trusted application configuration
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = tmp.Close()
		if err != nil {
			_ = os.Remove(tmpPath)
		}
	}()
	if err = tmp.Chmod(mode); err != nil {
		return err
	}
	if _, err = tmp.Write(data); err != nil {
		return err
	}
	if err = tmp.Sync(); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

// ===== Item 62: Upstream Configuration Editor =====

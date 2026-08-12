package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"

	"github.com/arumes31/resolix/webgui/internal/filter"
)

func (s *Server) handleUserRules(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodGet:
		data, err := os.ReadFile(s.userRulesPath()) // #nosec G304 -- path is derived from trusted ConfigDir configuration
		if err != nil && !os.IsNotExist(err) {
			http.Error(w, "Failed to read user rules", http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"rules": string(data)})
	case http.MethodPut:
		if !s.requireController(w) || !s.checkCSRF(w, r) {
			return
		}
		var request struct {
			Rules string `json:"rules"`
		}
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxUserRulesBytes+4096))
		if err := decoder.Decode(&request); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		if len(request.Rules) > maxUserRulesBytes {
			http.Error(w, "User rules exceed 1 MiB", http.StatusRequestEntityTooLarge)
			return
		}
		_, diagnostics := filter.ValidateRuleText(request.Rules)
		for _, diagnostic := range diagnostics {
			if diagnostic.Severity != "error" {
				continue
			}
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"message": "Custom rules contain invalid syntax", "diagnostics": diagnostics,
			})
			return
		}
		if err := s.replaceUserRules(request.Rules); err != nil {
			http.Error(w, "Failed to save user rules", http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	default:
		w.Header().Set("Allow", "GET, PUT")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) replaceUserRules(rules string) error {
	if len(rules) > maxUserRulesBytes {
		return errors.New("user rules exceed 1 MiB")
	}
	rules = strings.ReplaceAll(rules, "\r\n", "\n")
	if rules != "" && !strings.HasSuffix(rules, "\n") {
		rules += "\n"
	}
	userRulesMu.Lock()
	err := writeFileAtomic(s.userRulesPath(), []byte(rules), 0o600)
	userRulesMu.Unlock()
	if err != nil {
		return err
	}
	if engine := s.getFilter(); engine != nil {
		engine.ReloadSource(s.userRulesPath())
	}
	s.clearDNSCache()
	return nil
}

package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/arumes31/resolix/webgui/internal/storage"
)

func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	filter := storage.HistoryFilter{
		Domain:   r.URL.Query().Get("domain"),
		ClientIP: r.URL.Query().Get("client"),
		Type:     r.URL.Query().Get("type"),
		Status:   r.URL.Query().Get("status"),
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("cursor")); raw != "" {
		cursor, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || cursor < 1 {
			http.Error(w, "cursor must be a positive SQLite row ID", http.StatusBadRequest)
			return
		}
		filter.Cursor = cursor
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil || limit < 1 || limit > storage.MaxHistoryPageSize {
			http.Error(
				w,
				fmt.Sprintf("limit must be between 1 and %d", storage.MaxHistoryPageSize),
				http.StatusBadRequest,
			)
			return
		}
		filter.Limit = limit
	}
	page, err := s.store.QueryHistory(r.Context(), filter)
	if err != nil {
		if errors.Is(err, storage.ErrInvalidHistoryFilter) {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		http.Error(w, "Failed to query persisted history", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(page)
}

func (s *Server) handleStorageStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.store.DBMetrics(r.Context()))
}

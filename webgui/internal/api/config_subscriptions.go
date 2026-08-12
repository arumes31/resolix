package api

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"

	"github.com/arumes31/resolix/webgui/internal/filter"
)

func (s *Server) handleFilterSubscriptions(w http.ResponseWriter, r *http.Request) {
	s.fieldsMu.RLock()
	store := s.subscriptionStore
	engine := s.filterEngine
	s.fieldsMu.RUnlock()
	if store == nil || engine == nil {
		http.Error(w, "Filter subscriptions are not configured", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodGet:
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"subscriptions": store.List()})
	case http.MethodPut:
		if !s.requireController(w) || !s.checkCSRF(w, r) {
			return
		}
		var request struct {
			Subscriptions []filter.Subscription `json:"subscriptions"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256*1024)).Decode(&request); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		if err := store.Replace(request.Subscriptions); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		engine.ReplaceURLSources(store.List())
		s.clearDNSCache()
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok", "subscriptions": store.List()})
	default:
		w.Header().Set("Allow", "GET, PUT")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) filterStores(w http.ResponseWriter) (*filter.SubscriptionStore, *filter.Engine, bool) {
	s.fieldsMu.RLock()
	store := s.subscriptionStore
	engine := s.filterEngine
	s.fieldsMu.RUnlock()
	if store == nil || engine == nil {
		http.Error(w, "Filter subscriptions are not configured", http.StatusServiceUnavailable)
		return nil, nil, false
	}
	return store, engine, true
}

func (s *Server) handleFilterSubscriptionsExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	store, _, ok := s.filterStores(w)
	if !ok {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="resolix-subscriptions.json"`)
	_ = json.NewEncoder(w).Encode(filter.NewSubscriptionDocument(store.List()))
}

func (s *Server) handleFilterSubscriptionsImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireController(w) || !s.checkCSRF(w, r) {
		return
	}
	store, engine, ok := s.filterStores(w)
	if !ok {
		return
	}
	var document filter.SubscriptionDocument
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256*1024))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		http.Error(w, "Invalid subscription document", http.StatusBadRequest)
		return
	}
	if err := document.Validate(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := store.Replace(document.Subscriptions); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	engine.ReplaceURLSources(store.List())
	s.clearDNSCache()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok", "subscriptions": store.List()})
}

func (s *Server) handleFilterSubscriptionsBulk(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireController(w) || !s.checkCSRF(w, r) {
		return
	}
	store, engine, ok := s.filterStores(w)
	if !ok {
		return
	}
	var request struct {
		Action string   `json:"action"`
		IDs    []string `json:"ids"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	request.Action = strings.ToLower(strings.TrimSpace(request.Action))
	if err := store.Bulk(request.Action, request.IDs); err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, filter.ErrSubscriptionNotFound) {
			status = http.StatusNotFound
		}
		http.Error(w, err.Error(), status)
		return
	}
	engine.ReplaceURLSources(store.List())
	if request.Action != "refresh" {
		s.clearDNSCache()
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok", "subscriptions": store.List()})
}

func (s *Server) handleFilteringUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireController(w) || !s.checkCSRF(w, r) {
		return
	}
	s.fieldsMu.RLock()
	engine := s.filterEngine
	store := s.subscriptionStore
	s.fieldsMu.RUnlock()
	if engine == nil || store == nil {
		http.Error(w, "Filter subscriptions are not configured", http.StatusServiceUnavailable)
		return
	}
	id := strings.TrimSpace(r.URL.Query().Get("id"))
	var err error
	if id == "" {
		err = store.RequestRefresh()
	} else {
		err = store.RequestSourceRefresh(id)
	}
	if err != nil {
		log.Printf("[ERROR] persist filter subscription refresh request: %v", err)
		if id != "" && errors.Is(err, filter.ErrSubscriptionNotFound) {
			http.Error(w, "Filter subscription not found", http.StatusNotFound)
		} else {
			http.Error(w, "Failed to schedule filter subscription update", http.StatusInternalServerError)
		}
		return
	}
	engine.ReplaceURLSources(store.List())
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "scheduled"})
}

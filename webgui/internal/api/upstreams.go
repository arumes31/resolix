package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/miekg/dns"

	"github.com/arumes31/resolix/webgui/internal/dnsroutes"
	"github.com/arumes31/resolix/webgui/internal/dnsserver"
	"github.com/arumes31/resolix/webgui/internal/upstream"
)

func (s *Server) handleUpstreams(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleGetUpstreams(w, r)
	case http.MethodPost:
		s.handlePostUpstreams(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleGetUpstreams(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.configuredUpstreams())
}

func (s *Server) handleUpstreamSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		upstreams := s.configuredUpstreams()
		details := make([]map[string]interface{}, 0, len(upstreams))
		for _, raw := range upstreams {
			spec, err := upstream.Parse(raw)
			if err != nil {
				continue
			}
			details = append(details, map[string]interface{}{
				"spec": raw, "normalized_spec": spec.NormalizedKey(), "scheme": spec.Scheme,
				"host": spec.Host, "port": spec.Port, "path": spec.Path,
				"timeout_ms": float64(spec.TimeoutDuration().Microseconds()) / 1000,
				"weight":     spec.SelectionWeight(),
			})
		}
		s.fieldsMu.RLock()
		pool := s.upstreamPool
		s.fieldsMu.RUnlock()
		var upstreamRuntime []upstream.StatSnapshot
		var bootstrapStatus []upstream.BootstrapStatus
		if pool != nil {
			upstreamRuntime = pool.StatsSnapshot()
			bootstrapStatus = pool.BootstrapStatus()
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"upstreams":         upstreams,
			"bootstrap_servers": s.configuredBootstrapServers(),
			"details":           details,
			"runtime":           upstreamRuntime,
			"bootstrap_status":  bootstrapStatus,
		})
	case http.MethodPost:
		if !s.requireController(w) || !s.checkCSRF(w, r) {
			return
		}
		var request struct {
			Upstreams        []string `json:"upstreams"`
			BootstrapServers []string `json:"bootstrap_servers"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&request); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}
		upstreams := compactStrings(request.Upstreams)
		bootstrapServers := compactStrings(request.BootstrapServers)
		if err := validateResolverSettings(upstreams, bootstrapServers); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := s.saveUpstreamSettings(upstreams, bootstrapServers); err != nil {
			http.Error(w, "Failed to save upstream settings", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":            "ok",
			"upstreams":         upstreams,
			"bootstrap_servers": bootstrapServers,
		})
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleUpstreamTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.checkCSRF(w, r) {
		return
	}
	var request struct {
		Spec             string   `json:"spec"`
		Domain           string   `json:"domain"`
		BootstrapServers []string `json:"bootstrap_servers"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&request); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	request.Spec = strings.TrimSpace(request.Spec)
	request.Domain = strings.TrimSuffix(strings.TrimSpace(request.Domain), ".")
	if request.Domain == "" {
		request.Domain = s.cfg.HealthDomain
	}
	if _, ok := dns.IsDomainName(request.Domain); !ok {
		http.Error(w, "A valid test domain is required", http.StatusBadRequest)
		return
	}
	if len(request.BootstrapServers) == 0 {
		request.BootstrapServers = s.configuredBootstrapServers()
	}
	if err := upstream.ValidateBootstrapServers(request.BootstrapServers); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	report, err := upstream.ProbeDetailed(r.Context(), request.Spec, request.Domain, request.BootstrapServers)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(report)
}

func compactStrings(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			result = append(result, value)
		}
	}
	return result
}

func (s *Server) saveUpstreamSettings(upstreams, bootstrapServers []string) error {
	path := s.cfg.FullUpstreamsPath()
	if path == "" {
		return errors.New("upstreams file not configured")
	}
	if err := dnsroutes.SaveUpstreamSettings(path, dnsroutes.UpstreamSettings{
		Upstreams:           upstreams,
		BootstrapServers:    bootstrapServers,
		BootstrapConfigured: true,
	}); err != nil {
		return err
	}
	s.fieldsMu.RLock()
	reload := s.upstreamReloadFn
	s.fieldsMu.RUnlock()
	if reload != nil {
		reload()
	}
	s.clearDNSCache()
	return nil
}

func (s *Server) handlePostUpstreams(w http.ResponseWriter, r *http.Request) {
	if !s.requireController(w) {
		return
	}
	if !s.checkCSRF(w, r) {
		return
	}
	var req []struct {
		Address string `json:"address"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Validate each address
	upstreams := make([]string, 0, len(req))
	for _, item := range req {
		addr := strings.TrimSpace(item.Address)
		if addr == "" {
			continue
		}
		if _, err := upstream.Parse(addr); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"error": "Invalid upstream specification",
				"input": addr,
			})
			return
		}
		upstreams = append(upstreams, addr)
	}
	if len(upstreams) == 0 {
		http.Error(w, "At least one upstream resolver is required", http.StatusBadRequest)
		return
	}

	// Save to file
	upstreamsPath := s.cfg.FullUpstreamsPath()
	if upstreamsPath == "" {
		http.Error(w, "Upstreams file not configured", http.StatusInternalServerError)
		return
	}

	if err := dnsroutes.SaveUpstreams(upstreamsPath, upstreams); err != nil {
		http.Error(w, "Failed to save upstreams file", http.StatusInternalServerError)
		return
	}

	// Reload the upstream pool so changes take effect immediately.
	s.fieldsMu.RLock()
	reload := s.upstreamReloadFn
	s.fieldsMu.RUnlock()
	if reload != nil {
		reload()
	}
	s.clearDNSCache()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "ok",
		"upstreams": upstreams,
	})
}

// ===== Item 63: Cache Clear Endpoint =====
func (s *Server) handleCacheClear(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.checkCSRF(w, r) {
		return
	}
	dnsSrv := s.getDNSServer()
	if dnsSrv == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "DNS server is not configured",
		})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "ok",
		"cleared": dnsSrv.ClearCache(),
	})
}

func (s *Server) handleCacheStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	dnsSrv := s.getDNSServer()
	if dnsSrv == nil {
		http.Error(w, "DNS server is not configured", http.StatusServiceUnavailable)
		return
	}

	mode := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("entries")))
	if mode != "" && mode != "negative" && mode != "all" {
		http.Error(w, "entries must be negative or all", http.StatusBadRequest)
		return
	}
	limit := 100
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 1000 {
			http.Error(w, "limit must be between 1 and 1000", http.StatusBadRequest)
			return
		}
		limit = parsed
	}

	response := struct {
		Stats     dnsserver.CacheStats         `json:"stats"`
		Entries   []dnsserver.CacheEntryStatus `json:"entries,omitempty"`
		Truncated bool                         `json:"truncated,omitempty"`
	}{Stats: dnsSrv.CacheStats()}
	if mode != "" {
		for _, entry := range dnsSrv.CacheEntries() {
			if mode == "negative" && !entry.Negative {
				continue
			}
			if len(response.Entries) == limit {
				response.Truncated = true
				break
			}
			response.Entries = append(response.Entries, entry)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

// ===== Item 65: DNS Loop Detection Endpoint =====
func (s *Server) handleDNSLoopStatus(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	s.dnsLoopMu.Lock()
	detected := s.dnsLoopDetected
	details := s.dnsLoopDetails
	s.dnsLoopMu.Unlock()

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"loop_detected": detected,
		"details":       details,
	})
}

// ===== Item 66: Domain-Specific Routing Rules Endpoints =====
func (s *Server) handleDNSRoutes(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleGetDNSRoutes(w, r)
	case http.MethodPost:
		s.handlePostDNSRoutes(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleGetDNSRoutes(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	s.fieldsMu.RLock()
	dr := s.dnsRoutes
	s.fieldsMu.RUnlock()
	if dr == nil {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"routes": map[string]string{},
			"count":  0,
		})
		return
	}

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"routes": dr.GetRoutesMap(),
		"count":  dr.Count(),
	})
}

func (s *Server) handleDNSRouteTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	domain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(r.URL.Query().Get("domain")), "."))
	if _, ok := dns.IsDomainName(domain); !ok || domain == "" {
		http.Error(w, "A valid domain is required", http.StatusBadRequest)
		return
	}
	s.fieldsMu.RLock()
	dr := s.dnsRoutes
	s.fieldsMu.RUnlock()
	routes := map[string]string{}
	if dr != nil {
		routes = dr.GetRoutesMap()
	}
	type candidate struct {
		Pattern        string `json:"pattern"`
		Upstream       string `json:"upstream"`
		NormalizedSpec string `json:"normalized_spec"`
		Exact          bool   `json:"exact"`
	}
	candidates := make([]candidate, 0)
	for pattern, raw := range routes {
		pattern = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(pattern), "."))
		exact := pattern == domain
		matches := exact
		if strings.HasPrefix(pattern, "*.") {
			suffix := strings.TrimPrefix(pattern, "*.")
			matches = domain == suffix || strings.HasSuffix(domain, "."+suffix)
		}
		if !matches {
			continue
		}
		normalized, _ := upstream.Normalize(raw)
		candidates = append(candidates, candidate{Pattern: pattern, Upstream: raw, NormalizedSpec: normalized, Exact: exact})
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].Exact != candidates[j].Exact {
			return candidates[i].Exact
		}
		if len(candidates[i].Pattern) != len(candidates[j].Pattern) {
			return len(candidates[i].Pattern) > len(candidates[j].Pattern)
		}
		return candidates[i].Pattern < candidates[j].Pattern
	})
	var selected interface{}
	if len(candidates) > 0 {
		selected = candidates[0]
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"domain": domain, "matched": len(candidates) > 0, "selected": selected, "precedence": candidates,
	})
}

func (s *Server) handlePostDNSRoutes(w http.ResponseWriter, r *http.Request) {
	if !s.requireController(w) {
		return
	}
	if !s.checkCSRF(w, r) {
		return
	}
	var routesMap map[string]string
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&routesMap); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	for pattern, raw := range routesMap {
		if strings.TrimSpace(pattern) == "" {
			http.Error(w, "DNS route pattern may not be empty", http.StatusBadRequest)
			return
		}
		if _, err := upstream.Parse(raw); err != nil {
			http.Error(w, "DNS route contains an invalid upstream", http.StatusBadRequest)
			return
		}
	}

	s.fieldsMu.RLock()
	dr := s.dnsRoutes
	s.fieldsMu.RUnlock()
	if dr == nil {
		http.Error(w, "DNS routes not configured", http.StatusInternalServerError)
		return
	}

	if err := dr.SetRoutes(routesMap); err != nil {
		http.Error(w, fmt.Sprintf("Failed to save routes: %v", err), http.StatusInternalServerError)
		return
	}
	s.clearDNSCache()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "ok",
		"count":  dr.Count(),
	})
}

// ===== Item 68: Upstream Latency Alerts Endpoint =====
func (s *Server) handleUpstreamLatency(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	threshold := s.cfg.UpstreamLatencyThreshold

	// Get slow upstreams from health data using exported accessor
	healthData := s.store.GetUpstreamHealth()
	slowUpstreams := make([]map[string]interface{}, 0)
	for node, upstreams := range healthData {
		for ip, lat := range upstreams {
			if lat > float64(threshold) {
				slowUpstreams = append(slowUpstreams, map[string]interface{}{
					"node":      node,
					"upstream":  ip,
					"latency":   lat,
					"threshold": threshold,
				})
			}
		}
	}

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"threshold":      threshold,
		"slow_upstreams": slowUpstreams,
	})
}

// ===== Item 92: Heartbeat Endpoint =====
// handleHeartbeat processes heartbeat messages from agent nodes.
// It updates the node status in storage and is protected by IngestSecret.

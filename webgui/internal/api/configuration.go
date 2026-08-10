package api

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/arumes31/resolix/webgui/internal/clients"
	"github.com/arumes31/resolix/webgui/internal/configsync"
	"github.com/arumes31/resolix/webgui/internal/dnsroutes"
	"github.com/arumes31/resolix/webgui/internal/filter"
	"github.com/arumes31/resolix/webgui/internal/rewrites"
	"github.com/arumes31/resolix/webgui/internal/upstream"
)

const maxUserRulesBytes = 1 << 20

func (s *Server) isMaster() bool {
	return s.cfg.Mode == "" || s.cfg.Mode == "master"
}

func validateSnapshotRevision(snapshot configsync.Snapshot) error {
	valid, err := snapshot.ValidRevision()
	if err != nil {
		return fmt.Errorf("validate configuration snapshot revision: %w", err)
	}
	if !valid {
		return errors.New("configuration snapshot revision is invalid")
	}
	return nil
}

func logConfigApplyFailure(failed string, applied []string) {
	completed := "none"
	if len(applied) > 0 {
		completed = strings.Join(applied, ", ")
	}
	log.Printf("[WARN] DNS configuration apply failed at %s; stores already applied: %s", failed, completed)
}

func (s *Server) requireMaster(w http.ResponseWriter) bool {
	if s.isMaster() {
		return true
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":  "error",
		"message": "configuration is read-only on resolver nodes; edit the master node",
	})
	return false
}

func (s *Server) templateData(r *http.Request) map[string]interface{} {
	nonce := ""
	if s.nonceFromCtx != nil {
		nonce = s.nonceFromCtx(r.Context())
	}
	csrfToken := ""
	if cookie, err := r.Cookie(csrfCookieName); err == nil {
		csrfToken = cookie.Value
	}
	return map[string]interface{}{
		"Nonce":     nonce,
		"BaseURL":   s.cfg.BaseURL,
		"Mode":      s.cfg.Mode,
		"CSRFToken": csrfToken,
	}
}

func (s *Server) handleConfigPage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/config" || r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	var buf bytes.Buffer
	if err := s.tmpl.ExecuteTemplate(&buf, "config.html", s.templateData(r)); err != nil {
		log.Printf("Template execution error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = buf.WriteTo(w)
}

func (s *Server) configuredUpstreams() []string {
	if path := s.cfg.FullUpstreamsPath(); path != "" {
		if configured := dnsroutes.LoadUpstreams(path); len(configured) > 0 {
			return configured
		}
	}
	return strings.Fields(s.cfg.UpstreamDNS)
}

func (s *Server) currentConfigSnapshot() (configsync.Snapshot, error) {
	rules, err := os.ReadFile(s.userRulesPath()) // #nosec G304 -- path is derived from trusted HistoryDir configuration
	if err != nil && !os.IsNotExist(err) {
		return configsync.Snapshot{}, fmt.Errorf("read user rules: %w", err)
	}
	s.fieldsMu.RLock()
	subscriptions := s.subscriptionStore
	rewriteStore := s.rewritesStore
	clientRegistry := s.clientsRegistry
	dnsRoutes := s.dnsRoutes
	s.fieldsMu.RUnlock()
	var subscriptionItems []filter.Subscription
	if subscriptions != nil {
		subscriptionItems = subscriptions.List()
	}
	rewritesList := make([]rewrites.Rewrite, 0)
	if rewriteStore != nil {
		rewritesList = rewriteStore.List()
	}
	clientsList := make([]clients.Client, 0)
	if clientRegistry != nil {
		clientsList = clientRegistry.List()
	}
	routes := make(map[string]string)
	if dnsRoutes != nil {
		routes = dnsRoutes.GetRoutesMap()
	}
	return configsync.NewSnapshot(
		s.configuredUpstreams(), routes, subscriptionItems, string(rules), rewritesList, clientsList,
	)
}

func (s *Server) handleConfigStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	snapshot, err := s.currentConfigSnapshot()
	if err != nil {
		http.Error(w, "Failed to read configuration", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"mode":     s.cfg.Mode,
		"editable": s.isMaster(),
		"revision": snapshot.Revision,
		"runtime": map[string]interface{}{
			"upstream_mode":          s.cfg.UpstreamMode,
			"fallback_dns":           s.cfg.FallbackDNS,
			"bootstrap_dns":          s.cfg.BootstrapDNS,
			"ecs_client_subnet":      s.cfg.ECSClientSubnet,
			"blocking_mode":          s.cfg.BlockingMode,
			"block_custom_ipv4":      s.cfg.BlockCustomIP4,
			"block_custom_ipv6":      s.cfg.BlockCustomIP6,
			"safe_search":            s.cfg.SafeSearch,
			"bogus_nxdomain":         s.cfg.BogusNXDOMAIN,
			"aaaa_disabled":          s.cfg.AAAADisabled,
			"refuse_any":             s.cfg.RefuseANY,
			"dnssec":                 s.cfg.DNSSEC,
			"dns64":                  s.cfg.DNS64,
			"dns64_prefixes":         s.cfg.DNS64Prefixes,
			"private_ptr":            s.cfg.PrivatePTR,
			"rate_limit_qps":         s.cfg.RateLimitQPS,
			"blocked_services":       s.cfg.BlockedServices,
			"cache_min_ttl":          s.cfg.CacheMinTTL,
			"cache_max_ttl":          s.cfg.CacheMaxTTL,
			"cache_optimistic":       s.cfg.CacheOptimistic,
			"filter_update_interval": s.cfg.FilterUpdateInterval.String(),
			"doh_enabled":            s.cfg.DoHEnabled,
			"doh_path":               s.cfg.DoHPath,
			"dot_enabled":            s.cfg.DoTEnabled,
			"dot_port":               s.cfg.DoTPort,
			"dns_listen_address":     s.cfg.DNSListenAddr,
			"dns_listen_port":        s.cfg.DNSListenPort,
			"dns_allowed_clients":    s.cfg.DNSAllowedClients,
			"dns_disallowed_clients": s.cfg.DNSDisallowedClients,
			"healthcheck_domain":     s.cfg.HealthDomain,
			"history_retention":      s.cfg.HistoryRetention.String(),
		},
	})
}

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
		if !s.requireMaster(w) || !s.checkCSRF(w, r) {
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
		engine.RequestUpdate()
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok", "subscriptions": store.List()})
	default:
		w.Header().Set("Allow", "GET, PUT")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleUserRules(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodGet:
		data, err := os.ReadFile(s.userRulesPath()) // #nosec G304 -- path is derived from trusted HistoryDir configuration
		if err != nil && !os.IsNotExist(err) {
			http.Error(w, "Failed to read user rules", http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"rules": string(data)})
	case http.MethodPut:
		if !s.requireMaster(w) || !s.checkCSRF(w, r) {
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
	return nil
}

func (s *Server) handleSyncDNSConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.cfg.IngestSecret != "" {
		expected := "Bearer " + s.cfg.IngestSecret
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte(expected)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}
	if !s.isMaster() {
		http.Error(w, "Configuration snapshots are only served by the master", http.StatusConflict)
		return
	}
	snapshot, err := s.currentConfigSnapshot()
	if err != nil {
		http.Error(w, "Failed to build configuration snapshot", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(snapshot)
}

// ApplyConfigSnapshot persists and activates a validated master snapshot on a
// resolver node. The revision is accepted only when it matches the payload.
func (s *Server) ApplyConfigSnapshot(snapshot configsync.Snapshot) error {
	if err := validateSnapshotRevision(snapshot); err != nil {
		return err
	}
	if len(snapshot.Upstreams) == 0 {
		return errors.New("configuration snapshot has no upstreams")
	}
	for index, spec := range snapshot.Upstreams {
		if _, err := upstream.Parse(spec); err != nil {
			return fmt.Errorf("validate upstream %d: %w", index+1, err)
		}
	}
	for pattern, spec := range snapshot.Routes {
		if strings.TrimSpace(pattern) == "" {
			return errors.New("configuration snapshot has an empty DNS route pattern")
		}
		if _, err := upstream.Parse(spec); err != nil {
			return fmt.Errorf("validate DNS route upstream: %w", err)
		}
	}
	if err := filter.ValidateSubscriptions(snapshot.Subscriptions); err != nil {
		return fmt.Errorf("validate subscriptions: %w", err)
	}
	validationRewrites, err := rewrites.Load("", "")
	if err != nil {
		return fmt.Errorf("initialize rewrite validation: %w", err)
	}
	if err := validationRewrites.Replace(snapshot.Rewrites); err != nil {
		return fmt.Errorf("validate rewrites: %w", err)
	}
	validationClients, err := clients.Load("")
	if err != nil {
		return fmt.Errorf("initialize client validation: %w", err)
	}
	if err := validationClients.Replace(snapshot.Clients); err != nil {
		return fmt.Errorf("validate clients: %w", err)
	}

	s.fieldsMu.RLock()
	subscriptions := s.subscriptionStore
	rewriteStore := s.rewritesStore
	clientRegistry := s.clientsRegistry
	engine := s.filterEngine
	reloadUpstreams := s.upstreamReloadFn
	dnsRoutes := s.dnsRoutes
	s.fieldsMu.RUnlock()
	if subscriptions == nil || rewriteStore == nil || clientRegistry == nil || engine == nil || dnsRoutes == nil {
		return errors.New("DNS configuration stores are not initialized")
	}
	applied := make([]string, 0, 6)
	if err := subscriptions.Replace(snapshot.Subscriptions); err != nil {
		logConfigApplyFailure("subscriptions", applied)
		return fmt.Errorf("replace subscriptions: %w", err)
	}
	applied = append(applied, "subscriptions")
	if err := rewriteStore.Replace(snapshot.Rewrites); err != nil {
		logConfigApplyFailure("rewrites", applied)
		return fmt.Errorf("replace rewrites: %w", err)
	}
	applied = append(applied, "rewrites")
	if err := clientRegistry.Replace(snapshot.Clients); err != nil {
		logConfigApplyFailure("clients", applied)
		return fmt.Errorf("replace clients: %w", err)
	}
	applied = append(applied, "clients")
	if err := s.replaceUserRules(snapshot.UserRules); err != nil {
		logConfigApplyFailure("user rules", applied)
		return fmt.Errorf("replace user rules: %w", err)
	}
	applied = append(applied, "user rules")
	if err := dnsroutes.SaveUpstreams(s.cfg.FullUpstreamsPath(), snapshot.Upstreams); err != nil {
		logConfigApplyFailure("upstreams", applied)
		return fmt.Errorf("replace upstreams: %w", err)
	}
	applied = append(applied, "upstreams")
	if err := dnsRoutes.SetRoutes(snapshot.Routes); err != nil {
		logConfigApplyFailure("DNS routes", applied)
		return fmt.Errorf("replace DNS routes: %w", err)
	}
	engine.ReplaceURLSources(subscriptions.List())
	engine.RequestUpdate()
	if reloadUpstreams != nil {
		reloadUpstreams()
	}
	return nil
}

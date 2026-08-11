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
	"path/filepath"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/arumes31/resolix/webgui/internal/clients"
	"github.com/arumes31/resolix/webgui/internal/config"
	"github.com/arumes31/resolix/webgui/internal/configsync"
	"github.com/arumes31/resolix/webgui/internal/dnsroutes"
	"github.com/arumes31/resolix/webgui/internal/dnssettings"
	"github.com/arumes31/resolix/webgui/internal/filter"
	"github.com/arumes31/resolix/webgui/internal/rewrites"
	"github.com/arumes31/resolix/webgui/internal/upstream"
)

const maxUserRulesBytes = 1 << 20

var errUpstreamResolverRequired = errors.New("at least one upstream resolver is required")

func (s *Server) isController() bool {
	return s.cfg.Mode == "" || s.cfg.Mode == config.ModeController
}

func validateSnapshotRevision(snapshot configsync.Snapshot) error {
	if err := snapshot.Validate(); err != nil {
		return fmt.Errorf("validate configuration snapshot revision: %w", err)
	}
	return nil
}

func validateResolverSettings(upstreams, bootstrapServers []string) error {
	if len(upstreams) == 0 {
		return errUpstreamResolverRequired
	}
	requiresBootstrap := false
	seen := make(map[string]int, len(upstreams))
	for index, raw := range upstreams {
		spec, err := upstream.Parse(raw)
		if err != nil {
			return fmt.Errorf("upstream resolver %d is invalid: %w", index+1, err)
		}
		key := spec.NormalizedKey()
		if previous, exists := seen[key]; exists {
			return fmt.Errorf("upstream resolver %d duplicates normalized resolver %d (%s)", index+1, previous+1, key)
		}
		seen[key] = index
		requiresBootstrap = requiresBootstrap || spec.Hostname()
	}
	if requiresBootstrap && len(bootstrapServers) == 0 {
		return errors.New("hostname upstreams require at least one bootstrap resolver")
	}
	if err := upstream.ValidateBootstrapServers(bootstrapServers); err != nil {
		return fmt.Errorf("validate bootstrap resolvers: %w", err)
	}
	return nil
}

func validateSnapshotResolvers(snapshot configsync.Snapshot) error {
	err := validateResolverSettings(snapshot.Upstreams, snapshot.BootstrapServers)
	if errors.Is(err, errUpstreamResolverRequired) {
		return errors.New("configuration snapshot has no upstreams")
	}
	return err
}

func validateManagedDNSSettings(settings dnssettings.Settings, bootstrapServers []string) error {
	if err := settings.Validate(); err != nil {
		return err
	}
	resolvers := append([]string(nil), settings.FallbackDNS...)
	resolvers = append(resolvers, settings.PrivatePTRUpstreams...)
	for _, raw := range resolvers {
		spec, err := upstream.Parse(raw)
		if err != nil {
			return err
		}
		if spec.Hostname() && len(bootstrapServers) == 0 {
			return errors.New("hostname fallback resolvers require at least one bootstrap resolver")
		}
	}
	return nil
}

func validateSnapshotDNSSettings(snapshot configsync.Snapshot) error {
	if snapshot.DNSSettings == nil {
		return nil
	}
	if err := validateManagedDNSSettings(*snapshot.DNSSettings, snapshot.BootstrapServers); err != nil {
		return fmt.Errorf("validate DNS settings: %w", err)
	}
	return nil
}

func validateSnapshotUserRules(rules string) error {
	if len(rules) > maxUserRulesBytes {
		return errors.New("configuration snapshot user rules exceed 1 MiB")
	}
	_, diagnostics := filter.ValidateRuleText(rules)
	for _, diagnostic := range diagnostics {
		if diagnostic.Severity == "error" {
			return fmt.Errorf("configuration snapshot user rule line %d: %s", diagnostic.Line, diagnostic.Message)
		}
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

func (s *Server) requireController(w http.ResponseWriter) bool {
	if s.isController() {
		return true
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":  "error",
		"message": "configuration is read-only on resolver nodes; edit the controller node",
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

func (s *Server) configuredResolverSettings() dnsroutes.UpstreamSettings {
	settings := dnsroutes.UpstreamSettings{}
	if path := s.cfg.FullUpstreamsPath(); path != "" {
		settings = dnsroutes.LoadUpstreamSettings(path)
	}
	if len(settings.Upstreams) == 0 {
		settings.Upstreams = strings.Fields(s.cfg.UpstreamDNS)
	}
	if !settings.BootstrapConfigured {
		settings.BootstrapServers = strings.Fields(s.cfg.BootstrapDNS)
	}
	return settings
}

func (s *Server) configuredUpstreams() []string {
	return s.configuredResolverSettings().Upstreams
}

func (s *Server) configuredBootstrapServers() []string {
	return s.configuredResolverSettings().BootstrapServers
}

func dnsSettingsFromConfig(cfg *config.Config) dnssettings.Settings {
	return dnssettings.Settings{
		UpstreamMode:           cfg.UpstreamMode,
		FallbackDNS:            splitConfigValues(cfg.FallbackDNS),
		ECSClientSubnet:        cfg.ECSClientSubnet,
		BlockingMode:           cfg.BlockingMode,
		BlockCustomIPv4:        cfg.BlockCustomIP4,
		BlockCustomIPv6:        cfg.BlockCustomIP6,
		BlockedResponseTTL:     60,
		SafeSearch:             splitConfigValues(cfg.SafeSearch),
		BogusNXDOMAIN:          splitConfigValues(cfg.BogusNXDOMAIN),
		AAAADisabled:           cfg.AAAADisabled,
		RefuseANY:              cfg.RefuseANY,
		DNSSEC:                 cfg.DNSSEC,
		PrivatePTR:             cfg.PrivatePTR,
		ResolveClientHostnames: true,
		AllowedClients:         splitConfigValues(cfg.DNSAllowedClients),
		DisallowedClients:      splitConfigValues(cfg.DNSDisallowedClients),
		RateLimitQPS:           cfg.RateLimitQPS,
		InternalRateLimitQPS:   cfg.InternalRateLimitQPS,
		RateLimitEDE:           cfg.RateLimitEDE,
		RateLimitIPv4Prefix:    32,
		RateLimitIPv6Prefix:    128,
		CacheSize:              25000,
		CacheMinTTL:            cfg.CacheMinTTL,
		CacheMaxTTL:            cfg.CacheMaxTTL,
		CacheOptimistic:        cfg.CacheOptimistic,
		CachePrefetch:          cfg.CachePrefetch,
		CachePrefetchWindowMS:  cfg.CachePrefetchWindow.Milliseconds(),
		CachePrefetchHits:      cfg.CachePrefetchHits,
		CacheSERVFAILTTLMS:     cfg.CacheSERVFAILTTL.Milliseconds(),
	}.Normalize()
}

func splitConfigValues(raw string) []string {
	return strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\r' || r == '\n'
	})
}

func (s *Server) currentDNSSettings() dnssettings.Settings {
	s.fieldsMu.RLock()
	store := s.dnsSettings
	s.fieldsMu.RUnlock()
	if store != nil {
		return store.Get()
	}
	return dnsSettingsFromConfig(s.cfg)
}

func (s *Server) currentConfigSnapshot() (configsync.Snapshot, error) {
	rules, err := os.ReadFile(s.userRulesPath()) // #nosec G304 -- path is derived from trusted ConfigDir configuration
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
	resolverSettings := s.configuredResolverSettings()
	dnsSettings := s.currentDNSSettings()
	return configsync.NewSnapshotWithDNSSettings(
		resolverSettings.Upstreams, resolverSettings.BootstrapServers, routes,
		subscriptionItems, string(rules), rewritesList, clientsList, &dnsSettings,
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
	response := map[string]interface{}{
		"mode":         s.cfg.Mode,
		"editable":     s.isController(),
		"revision":     snapshot.Revision,
		"dns_settings": s.currentDNSSettings(),
		"runtime": map[string]interface{}{
			"bootstrap_dns":           strings.Join(snapshot.BootstrapServers, " "),
			"dns64":                   s.cfg.DNS64,
			"dns64_prefixes":          s.cfg.DNS64Prefixes,
			"dns_tcp_idle_timeout":    s.cfg.DNSTCPIdleTimeout.String(),
			"dns_tcp_max_queries":     s.cfg.DNSTCPMaxQueries,
			"dns_tcp_max_connections": s.cfg.DNSTCPMaxConnections,
			"filter_update_interval":  s.cfg.FilterUpdateInterval.String(),
			"doh_enabled":             s.cfg.DoHEnabled,
			"doh_path":                s.cfg.DoHPath,
			"dot_enabled":             s.cfg.DoTEnabled,
			"dot_port":                s.cfg.DoTPort,
			"dns_listen_address":      s.cfg.DNSListenAddr,
			"dns_listen_port":         s.cfg.DNSListenPort,
			"healthcheck_domain":      s.cfg.HealthDomain,
			"history_retention":       s.cfg.HistoryRetention.String(),
		},
	}
	if previous, err := s.loadPreviousConfigSnapshot(); err == nil {
		response["previous_revision"] = previous.Revision
		response["diff_from_previous"] = configsync.Diff(previous, snapshot)
	}
	s.fieldsMu.RLock()
	forwarder := s.forwarder
	s.fieldsMu.RUnlock()
	if forwarder != nil {
		response["sync"] = forwarder.SnapshotStatus(time.Now())
	}
	if dnsSrv := s.getDNSServer(); dnsSrv != nil {
		response["cache"] = dnsSrv.CacheStats()
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

func (s *Server) handleDNSSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(s.currentDNSSettings())
	case http.MethodPut:
		if !s.requireController(w) || !s.checkCSRF(w, r) {
			return
		}
		var settings dnssettings.Settings
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&settings); err != nil {
			http.Error(w, "Invalid DNS settings", http.StatusBadRequest)
			return
		}
		settings = settings.Normalize()
		if err := validateManagedDNSSettings(settings, s.configuredBootstrapServers()); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		s.fieldsMu.RLock()
		store := s.dnsSettings
		apply := s.dnsSettingsApplyFn
		s.fieldsMu.RUnlock()
		if store == nil {
			http.Error(w, "DNS settings store is unavailable", http.StatusServiceUnavailable)
			return
		}
		if err := store.Replace(settings); err != nil {
			log.Printf("[WARN] Persist DNS settings: %v", err)
			http.Error(w, "Failed to persist DNS settings", http.StatusInternalServerError)
			return
		}
		if apply != nil {
			apply(settings)
		}
		s.clearDNSCache()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(settings)
	default:
		w.Header().Set("Allow", http.MethodGet+", "+http.MethodPut)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleConfigSnapshot(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	snapshot, err := s.currentConfigSnapshot()
	if err != nil {
		http.Error(w, "Failed to read current configuration", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(snapshot)
}

// handleConfigDiff validates a complete candidate snapshot and returns a
// readable preview without mutating any managed store.
func (s *Server) handleConfigDiff(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.checkCSRF(w, r) {
		return
	}
	var candidate configsync.Snapshot
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2*1024*1024))
	if err := decoder.Decode(&candidate); err != nil {
		http.Error(w, "Invalid configuration snapshot", http.StatusBadRequest)
		return
	}
	if candidate.Revision == "" {
		var err error
		candidate, err = configsync.NewSnapshotWithDNSSettings(
			candidate.Upstreams,
			candidate.BootstrapServers,
			candidate.Routes,
			candidate.Subscriptions,
			candidate.UserRules,
			candidate.Rewrites,
			candidate.Clients,
			candidate.DNSSettings,
		)
		if err != nil {
			http.Error(w, "Invalid configuration snapshot", http.StatusBadRequest)
			return
		}
	} else if err := candidate.Validate(); err != nil {
		http.Error(w, "Invalid configuration snapshot", http.StatusBadRequest)
		return
	}
	if err := validateSnapshotResolvers(candidate); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	current, err := s.currentConfigSnapshot()
	if err != nil {
		http.Error(w, "Failed to read current configuration", http.StatusInternalServerError)
		return
	}
	diff := configsync.Diff(current, candidate)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"changed":          len(diff) > 0,
		"current_revision": current.Revision,
		"desired_revision": candidate.Revision,
		"changes":          diff,
	})
}

func (s *Server) handleConfigSyncNow(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.checkCSRF(w, r) {
		return
	}
	node := strings.TrimSpace(r.URL.Query().Get("node"))
	if s.isController() {
		identity := node
		if node != "" {
			status := s.store.GetNodeStatus(node)
			if status == nil {
				http.Error(w, "Node not found", http.StatusNotFound)
				return
			}
			identity = status.ID
		}
		s.syncRequestMu.Lock()
		if node == "" {
			s.clusterSyncGeneration++
		} else {
			s.nodeSyncGenerations[identity]++
		}
		s.syncRequestMu.Unlock()
	} else {
		s.fieldsMu.RLock()
		forwarder := s.forwarder
		s.fieldsMu.RUnlock()
		if node != "" && node != s.cfg.NodeName {
			http.Error(w, "This resolver can only synchronize itself", http.StatusBadRequest)
			return
		}
		if forwarder == nil || !forwarder.SyncNow() {
			http.Error(w, "Configuration synchronizer is unavailable", http.StatusServiceUnavailable)
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "scheduled", "node": node})
}

func (s *Server) syncGenerationFor(node string) string {
	s.syncRequestMu.RLock()
	cluster := s.clusterSyncGeneration
	individual := s.nodeSyncGenerations[node]
	s.syncRequestMu.RUnlock()
	return fmt.Sprintf("%d:%d", cluster, individual)
}

func (s *Server) previousConfigSnapshotPath() string {
	return filepath.Join(s.cfg.FullConfigDir(), "previous-config-snapshot.json")
}

func (s *Server) savePreviousConfigSnapshot(snapshot configsync.Snapshot) error {
	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal previous configuration snapshot: %w", err)
	}
	path := s.previousConfigSnapshotPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("create previous configuration directory: %w", err)
	}
	if err := writeFileAtomic(path, data, 0o600); err != nil {
		return fmt.Errorf("persist previous configuration snapshot: %w", err)
	}
	return nil
}

func (s *Server) loadPreviousConfigSnapshot() (configsync.Snapshot, error) {
	data, err := os.ReadFile(s.previousConfigSnapshotPath()) // #nosec G304 -- path is derived from trusted ConfigDir
	if err != nil {
		return configsync.Snapshot{}, err
	}
	var snapshot configsync.Snapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return configsync.Snapshot{}, fmt.Errorf("decode previous configuration snapshot: %w", err)
	}
	if err := snapshot.Validate(); err != nil {
		return configsync.Snapshot{}, fmt.Errorf("validate previous configuration snapshot: %w", err)
	}
	return snapshot, nil
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

func (s *Server) handleFilteringTest(w http.ResponseWriter, r *http.Request) {
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
	engine := s.getFilter()
	if engine == nil {
		http.Error(w, "Filter engine is not configured", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"evaluation": engine.Explain(domain), "allowlist_overrides": engine.AllowlistOverrides(100),
	})
}

func (s *Server) handleFilteringValidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.checkCSRF(w, r) {
		return
	}
	var request struct {
		Rules string `json:"rules"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxUserRulesBytes+4096)).Decode(&request); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	accepted, diagnostics := filter.ValidateRuleText(request.Rules)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"accepted": accepted, "diagnostics": diagnostics})
}

func (s *Server) handleFilteringRollback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireController(w) || !s.checkCSRF(w, r) {
		return
	}
	var request struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&request); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	engine := s.getFilter()
	if engine == nil {
		http.Error(w, "Filter engine is not configured", http.StatusServiceUnavailable)
		return
	}
	if err := engine.RollbackSource(strings.TrimSpace(request.ID)); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

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
	if !s.isController() {
		http.Error(w, "Configuration snapshots are only served by the controller", http.StatusConflict)
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

// ApplyConfigSnapshot persists and activates a validated controller snapshot on a
// resolver node. The revision is accepted only when it matches the payload.
func (s *Server) ApplyConfigSnapshot(snapshot configsync.Snapshot) error {
	s.configApplyMu.Lock()
	defer s.configApplyMu.Unlock()
	if err := validateSnapshotRevision(snapshot); err != nil {
		return err
	}
	if err := validateSnapshotResolvers(snapshot); err != nil {
		return err
	}
	if err := validateSnapshotUserRules(snapshot.UserRules); err != nil {
		return err
	}
	if err := validateSnapshotDNSSettings(snapshot); err != nil {
		return err
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
	dnsSettingsStore := s.dnsSettings
	applyDNSSettings := s.dnsSettingsApplyFn
	s.fieldsMu.RUnlock()
	if subscriptions == nil || rewriteStore == nil || clientRegistry == nil || engine == nil || dnsRoutes == nil ||
		(snapshot.DNSSettings != nil && dnsSettingsStore == nil) {
		return errors.New("DNS configuration stores are not initialized")
	}
	previous, err := s.currentConfigSnapshot()
	if err != nil {
		return fmt.Errorf("capture working configuration before apply: %w", err)
	}
	if previous.Revision == snapshot.Revision {
		return nil
	}
	if err := s.savePreviousConfigSnapshot(previous); err != nil {
		return err
	}
	stores := configApplyStores{
		subscriptions: subscriptions,
		rewrites:      rewriteStore,
		clients:       clientRegistry,
		engine:        engine,
		dnsRoutes:     dnsRoutes,
		dnsSettings:   dnsSettingsStore,
		applySettings: applyDNSSettings,
		reload:        reloadUpstreams,
	}
	if err := s.applyConfigStores(snapshot, stores, true); err != nil {
		rollbackErr := s.applyConfigStores(previous, stores, false)
		if rollbackErr != nil {
			log.Printf("[ERROR] DNS configuration rollback to %.12s failed: %v", previous.Revision, rollbackErr)
			return errors.Join(err, fmt.Errorf("rollback to previous configuration: %w", rollbackErr))
		}
		log.Printf("[WARN] Rolled back DNS configuration to revision %.12s after apply failure", previous.Revision)
		return err
	}
	return nil
}

type configApplyStores struct {
	subscriptions *filter.SubscriptionStore
	rewrites      *rewrites.Store
	clients       *clients.Registry
	engine        *filter.Engine
	dnsRoutes     *dnsroutes.DNSRoutes
	dnsSettings   *dnssettings.Store
	applySettings func(dnssettings.Settings)
	reload        func()
}

func (s *Server) applyConfigStores(snapshot configsync.Snapshot, stores configApplyStores, reportFailure bool) error {
	applied := make([]string, 0, 6)
	fail := func(store string, err error) error {
		if reportFailure {
			logConfigApplyFailure(store, applied)
		}
		return err
	}
	if err := stores.subscriptions.Replace(snapshot.Subscriptions); err != nil {
		return fail("subscriptions", fmt.Errorf("replace subscriptions: %w", err))
	}
	applied = append(applied, "subscriptions")
	if err := stores.rewrites.Replace(snapshot.Rewrites); err != nil {
		return fail("rewrites", fmt.Errorf("replace rewrites: %w", err))
	}
	applied = append(applied, "rewrites")
	if err := stores.clients.Replace(snapshot.Clients); err != nil {
		return fail("clients", fmt.Errorf("replace clients: %w", err))
	}
	applied = append(applied, "clients")
	if err := s.replaceUserRules(snapshot.UserRules); err != nil {
		return fail("user rules", fmt.Errorf("replace user rules: %w", err))
	}
	applied = append(applied, "user rules")
	if err := dnsroutes.SaveUpstreamSettings(s.cfg.FullUpstreamsPath(), dnsroutes.UpstreamSettings{
		Upstreams:           snapshot.Upstreams,
		BootstrapServers:    snapshot.BootstrapServers,
		BootstrapConfigured: true,
	}); err != nil {
		return fail("upstreams", fmt.Errorf("replace upstreams: %w", err))
	}
	applied = append(applied, "upstreams")
	if err := stores.dnsRoutes.SetRoutes(snapshot.Routes); err != nil {
		return fail("DNS routes", fmt.Errorf("replace DNS routes: %w", err))
	}
	applied = append(applied, "DNS routes")
	if snapshot.DNSSettings != nil && stores.dnsSettings != nil {
		if err := stores.dnsSettings.Replace(*snapshot.DNSSettings); err != nil {
			return fail("DNS settings", fmt.Errorf("replace DNS settings: %w", err))
		}
		if stores.applySettings != nil {
			stores.applySettings(stores.dnsSettings.Get())
		}
		applied = append(applied, "DNS settings")
	}
	stores.engine.ReplaceURLSources(stores.subscriptions.List())
	if stores.reload != nil {
		stores.reload()
	}
	s.clearDNSCache()
	return nil
}

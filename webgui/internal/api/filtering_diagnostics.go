package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strings"

	"github.com/miekg/dns"

	"github.com/arumes31/resolix/webgui/internal/clients"
	"github.com/arumes31/resolix/webgui/internal/filter"
	"github.com/arumes31/resolix/webgui/internal/policy"
	"github.com/arumes31/resolix/webgui/internal/rewrites"
)

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
	queryTypeName := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("type")))
	if queryTypeName == "" {
		queryTypeName = "A"
	}
	queryType, ok := filteringTestQTypes[queryTypeName]
	if !ok {
		http.Error(w, "Unsupported DNS record type", http.StatusBadRequest)
		return
	}
	clientIdentifier := strings.TrimSpace(r.URL.Query().Get("client"))
	if len(clientIdentifier) > 255 {
		http.Error(w, "Client identifier is too long", http.StatusBadRequest)
		return
	}

	response, err := s.evaluateFilteringTest(filteringTestRequest{
		domain:           domain,
		queryType:        queryType,
		queryTypeName:    queryTypeName,
		clientIdentifier: clientIdentifier,
	})
	if err != nil {
		if errors.Is(err, errFilterEngineUnavailable) {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
		} else {
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

var errFilterEngineUnavailable = errors.New("filter engine is not configured")

func (s *Server) evaluateFilteringTest(request filteringTestRequest) (filteringTestResponse, error) {
	s.fieldsMu.RLock()
	engine := s.filterEngine
	rewriteStore := s.rewritesStore
	clientRegistry := s.clientsRegistry
	s.fieldsMu.RUnlock()
	if engine == nil {
		return filteringTestResponse{}, errFilterEngineUnavailable
	}

	client, err := resolveFilteringTestClient(request.clientIdentifier, clientRegistry)
	if err != nil {
		return filteringTestResponse{}, err
	}
	evaluation := engine.Explain(request.domain)
	diagnostic := newFilteringDiagnostic(request, client, engine)
	settings := s.currentDNSSettings()

	if settings.RefuseANY && request.queryType == dns.TypeANY {
		diagnostic.Decision = "refused"
		diagnostic.Title = "Refused by DNS policy"
		diagnostic.Detail = "ANY queries are disabled before rewrites and filter rules are evaluated."
		diagnostic.MatchedRule = "REFUSE_ANY"
		diagnostic.Source = "DNS policy"
		diagnostic.Reason = policy.ReasonRefusedANY
		return filteringTestResult(engine, evaluation, diagnostic), nil
	}
	if settings.AAAADisabled && request.queryType == dns.TypeAAAA {
		diagnostic.Decision = "nodata"
		diagnostic.Title = "IPv6 resolution disabled"
		diagnostic.Detail = "AAAA queries receive an empty NOERROR response before rewrites and filter rules are evaluated."
		diagnostic.MatchedRule = "AAAA_DISABLED"
		diagnostic.Source = "DNS policy"
		diagnostic.Reason = policy.ReasonAAAADisabled
		return filteringTestResult(engine, evaluation, diagnostic), nil
	}

	if rewriteStore != nil {
		rewriteItems := rewriteStore.LookupForClient(request.domain, client.ip)
		if len(rewriteItems) > 0 {
			rewrite := rewriteForQuestion(rewriteItems, request.queryType)
			diagnostic.Decision = "rewrite"
			diagnostic.Title = "Answered by DNS rewrite"
			diagnostic.Detail = "A matching local rewrite takes precedence over safe search and filter rules."
			diagnostic.MatchedRule = rewrite.String()
			diagnostic.Source = "DNS rewrites"
			diagnostic.Reason = "Rewrite"
			return filteringTestResult(engine, evaluation, diagnostic), nil
		}
	}

	if target := filteringSafeSearchTarget(settings.SafeSearch, request.domain, client.profile); target != "" {
		diagnostic.Decision = "safe_search"
		diagnostic.Title = "Redirected by safe search"
		diagnostic.Detail = "Safe-search policy rewrites this name before filter rules are evaluated."
		diagnostic.MatchedRule = request.domain + " CNAME " + target
		diagnostic.Source = "Safe-search policy"
		diagnostic.Reason = policy.ReasonSafeSearch
		return filteringTestResult(engine, evaluation, diagnostic), nil
	}

	if !diagnostic.FilteringEnabled {
		diagnostic.Decision = "filtering_disabled"
		diagnostic.Title = "Filtering disabled for this client"
		diagnostic.Detail = "The matching client profile bypasses blocklists and custom filtering rules."
		diagnostic.Source = "Client policy"
		return filteringTestResult(engine, evaluation, diagnostic), nil
	}
	if diagnostic.ProtectionPaused {
		diagnostic.Decision = "protection_paused"
		diagnostic.Title = "Filtering protection is paused"
		diagnostic.Detail = "A matching rule may exist, but filtering is currently paused."
		diagnostic.Source = "Filtering status"
		return filteringTestResult(engine, evaluation, diagnostic), nil
	}
	if evaluation.Result.Allowed {
		diagnostic.Decision = "allowed"
		diagnostic.Title = "Allowed by exception rule"
		diagnostic.Detail = "An allowlist rule takes precedence over matching block rules."
		diagnostic.MatchedRule = evaluation.Result.Rule
		diagnostic.Source = evaluation.Result.Source
		return filteringTestResult(engine, evaluation, diagnostic), nil
	}
	if evaluation.Result.Blocked {
		diagnostic.Decision = "blocked"
		diagnostic.Title = "Blocked by filtering"
		diagnostic.Detail = "The request matches an active blocklist or custom filtering rule."
		diagnostic.MatchedRule = evaluation.Result.Rule
		diagnostic.Source = evaluation.Result.Source
		diagnostic.Reason = evaluation.Result.Reason
		return filteringTestResult(engine, evaluation, diagnostic), nil
	}

	diagnostic.Decision = "forwarded"
	diagnostic.Title = "No local policy match"
	diagnostic.Detail = "The request continues to cache, DNS routes, and upstream resolution."
	diagnostic.Source = "Upstream pipeline"
	return filteringTestResult(engine, evaluation, diagnostic), nil
}

func newFilteringDiagnostic(
	request filteringTestRequest,
	client filteringTestClient,
	engine *filter.Engine,
) filteringDiagnostic {
	diagnostic := filteringDiagnostic{
		Domain:           request.domain,
		QueryType:        request.queryTypeName,
		ClientIdentifier: client.identifier,
		ClientIP:         client.ip,
		FilteringEnabled: client.profile == nil || client.profile.UseGlobalSettings || client.profile.FilteringEnabled,
		ProtectionPaused: engine.Paused(),
	}
	if client.profile != nil {
		diagnostic.ClientName = client.profile.Name
	}
	return diagnostic
}

func filteringTestResult(
	engine *filter.Engine,
	evaluation filter.Evaluation,
	diagnostic filteringDiagnostic,
) filteringTestResponse {
	return filteringTestResponse{
		Evaluation:         evaluation,
		Diagnostic:         diagnostic,
		AllowlistOverrides: engine.AllowlistOverrides(100),
	}
}

func resolveFilteringTestClient(identifier string, registry *clients.Registry) (filteringTestClient, error) {
	client := filteringTestClient{identifier: identifier}
	if identifier == "" {
		return client, nil
	}
	if ip := net.ParseIP(identifier); ip != nil {
		client.ip = ip.String()
		if registry != nil {
			client.profile = registry.Find(client.ip)
		}
		return client, nil
	}
	if registry == nil {
		return filteringTestClient{}, fmt.Errorf("unknown client identifier %q", identifier)
	}
	for _, candidate := range registry.List() {
		if strings.EqualFold(candidate.Name, identifier) || slices.Contains(candidate.IDs, identifier) {
			matched := candidate
			client.profile = &matched
			client.ip = exactClientIP(candidate.IDs)
			return client, nil
		}
	}
	return filteringTestClient{}, fmt.Errorf("unknown client identifier %q", identifier)
}

func exactClientIP(identifiers []string) string {
	for _, identifier := range identifiers {
		if ip := net.ParseIP(strings.TrimSpace(identifier)); ip != nil {
			return ip.String()
		}
		ip, network, err := net.ParseCIDR(strings.TrimSpace(identifier))
		if err != nil {
			continue
		}
		ones, bits := network.Mask.Size()
		if ones == bits {
			return ip.String()
		}
	}
	return ""
}

func rewriteForQuestion(items []rewrites.Rewrite, queryType uint16) rewrites.Rewrite {
	for _, item := range items {
		if item.Type == rewrites.TypeNXDOMAIN || item.Type == rewrites.TypeREFUSED || item.Type == rewrites.TypeNOERROR {
			return item
		}
	}
	for _, item := range items {
		if item.BuildRR(dns.Fqdn(item.Domain), queryType) != nil {
			return item
		}
	}
	return items[0]
}

func filteringSafeSearchTarget(globalEngines []string, domain string, client *clients.Client) string {
	engines := policy.ParseEngines(globalEngines)
	if client != nil && !client.UseGlobalSettings {
		if !client.SafeSearchEnabled {
			return ""
		}
		if configured := policy.ParseEngines(client.SafeSearchEngines); len(configured) > 0 {
			engines = configured
		}
	}
	return policy.SafeSearchTargetFor(engines, domain)
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

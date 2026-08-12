package main

import (
	"context"
	"html/template"
	"io/fs"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/arumes31/resolix/webgui/internal/api"
	"github.com/arumes31/resolix/webgui/internal/clients"
	"github.com/arumes31/resolix/webgui/internal/config"
	"github.com/arumes31/resolix/webgui/internal/dnssettings"
	"github.com/arumes31/resolix/webgui/internal/filter"
	"github.com/arumes31/resolix/webgui/internal/health"
	"github.com/arumes31/resolix/webgui/internal/logger"
	"github.com/arumes31/resolix/webgui/internal/rewrites"
	"github.com/arumes31/resolix/webgui/internal/storage"
	"github.com/arumes31/resolix/webgui/internal/upstream"
)

func setupFilterEngine(ctx context.Context, cfg *config.Config, srv *api.Server) (*filter.Engine, *filter.SubscriptionStore) {
	eng := filter.New()

	// User rules (query-log block/unblock actions) — a plain file source.
	userRulesPath := cfg.FullUserRulesPath()
	if _, err := os.Stat(userRulesPath); os.IsNotExist(err) {
		if err := os.WriteFile(userRulesPath, []byte("! user rules (managed via /api/querylog)\n"), 0o600); err != nil {
			logger.Warning("Failed to create user rules file: %v", err)
		}
	}
	eng.AddFileSource(userRulesPath, false)

	if p := cfg.FullBlocklistPath(); p != "" {
		eng.AddFileSource(p, false)
	}
	if cfg.AllowlistFile != "" {
		eng.AddFileSource(cfg.AllowlistFile, true)
	}
	seeds := make([]filter.Subscription, 0)
	for _, u := range splitListEnv(cfg.BlocklistURLs) {
		seeds = append(seeds, filter.Subscription{URL: u, Enabled: true})
	}
	for _, u := range splitListEnv(cfg.AllowlistURLs) {
		seeds = append(seeds, filter.Subscription{URL: u, AllowOnly: true, Enabled: true})
	}
	subscriptionPath := cfg.FullFilterSubscriptionsPath()
	subscriptions, err := filter.LoadSubscriptionStore(subscriptionPath, seeds)
	if err != nil {
		logger.Fatal("Failed to load filter subscriptions: %v", err)
	}
	eng.ReplaceURLSources(subscriptions.List())
	eng.StartUpdateLoop(ctx, cfg.FilterUpdateInterval)
	srv.SetFilter(eng)
	srv.SetSubscriptionStore(subscriptions)
	return eng, subscriptions
}

// parseTemplates parses the embedded HTML templates, exiting fatally on error.
func parseTemplates() *template.Template {
	tmpl, err := template.ParseFS(embedFS, "templates/*.html")
	if err != nil {
		logger.Fatal("Fatal error parsing templates: %v", err)
	}
	return tmpl
}

// newStaticHandler creates the static file server from the embedded FS,
// exiting fatally on error.
func newStaticHandler() http.Handler {
	staticFS, err := fs.Sub(embedFS, "static")
	if err != nil {
		logger.Fatal("Fatal error creating static FS: %v", err)
	}
	return http.FileServer(http.FS(staticFS))
}

// setupClientsRegistry loads the per-client registry and starts hot-reload.
func setupClientsRegistry(ctx context.Context, cfg *config.Config, srv *api.Server) *clients.Registry {
	reg, err := clients.Load(cfg.FullClientsPath())
	if err != nil {
		logger.Warning("Failed to load clients registry: %v", err)
		reg, err = clients.Load("") // in-memory fallback
		if err != nil || reg == nil {
			logger.Fatal("Failed to initialize fallback clients registry: %v", err)
		}
	}
	if reg == nil {
		logger.Fatal("Clients registry initialization returned nil")
	}
	reg.StartReload(ctx)
	srv.SetClients(reg)
	return reg
}

// loadRewritesStore loads the typed rewrites store, seeding from the DOMAINS
// env on first boot; falls back to an in-memory store on load errors.
func loadRewritesStore(cfg *config.Config) *rewrites.Store {
	rwStore, err := rewrites.Load(cfg.FullRewritesPath(), cfg.Domains)
	if err != nil {
		logger.Warning("Failed to load rewrites store: %v", err)
		rwStore, err = rewrites.Load("", cfg.Domains) // in-memory fallback
		if err != nil || rwStore == nil {
			logger.Fatal("Failed to initialize fallback rewrites store: %v", err)
		}
	}
	if rwStore == nil {
		logger.Fatal("Rewrites store initialization returned nil")
	}
	return rwStore
}

// setupUpstreamPool builds the upstream pool, wires health data and the API
// reload callback, and starts the upstreams.json hot-reload poller.
func setupUpstreamPool(
	ctx context.Context,
	cfg *config.Config,
	dnsSettings dnssettings.Settings,
	store *storage.Store,
	srv *api.Server,
	checker *health.Checker,
	loadSettings func() ([]string, []string),
	currentSpecs []string,
	currentBootstrap []string,
) *upstream.Pool {
	pool := upstream.NewPool(upstream.PoolConfig{
		Mode:             dnsSettings.UpstreamMode,
		PrimarySpecs:     currentSpecs,
		FallbackSpecs:    dnsSettings.FallbackDNS,
		BootstrapServers: currentBootstrap,
		ECSClientSubnet:  dnsSettings.ECSClientSubnet,
		DNS64:            cfg.DNS64,
		DNS64Prefixes:    strings.Fields(cfg.DNS64Prefixes),
		CacheMinTTL:      cfg.CacheMinTTL,
		CacheMaxTTL:      cfg.CacheMaxTTL,
	})
	pool.SetHealthProvider(func() map[string]float64 {
		return store.GetUpstreamHealth()[cfg.NodeName]
	})
	srv.SetUpstreamPool(pool)
	var reloadMu sync.Mutex
	reload := func() {
		reloadMu.Lock()
		defer reloadMu.Unlock()
		specs, bootstrapServers := loadSettings()
		if !equalStringSlices(bootstrapServers, currentBootstrap) {
			pool.SetBootstrapServers(bootstrapServers)
			checker.UpdateBootstrapServers(bootstrapServers)
			currentBootstrap = append([]string(nil), bootstrapServers...)
		}
		pool.SetPrimarySpecs(specs)
		checker.UpdateUpstreams(specs)
		currentSpecs = append([]string(nil), specs...)
	}
	srv.SetUpstreamReloadFunc(func() {
		reload()
	})

	// Hot-reload upstreams.json: poll for changes (covers external edits).
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				specs, bootstrapServers := loadSettings()
				reloadMu.Lock()
				changed := !equalStringSlices(specs, currentSpecs) ||
					!equalStringSlices(bootstrapServers, currentBootstrap)
				reloadMu.Unlock()
				if changed {
					logger.Info("Upstream list changed, reloading pool (%d upstreams)", len(specs))
					reload()
				}
			}
		}
	}()
	return pool
}

func defaultDNSSettings(cfg *config.Config) dnssettings.Settings {
	return dnssettings.Settings{
		UpstreamMode:           cfg.UpstreamMode,
		FallbackDNS:            splitListEnv(cfg.FallbackDNS),
		ECSClientSubnet:        cfg.ECSClientSubnet,
		BlockingMode:           cfg.BlockingMode,
		BlockCustomIPv4:        cfg.BlockCustomIP4,
		BlockCustomIPv6:        cfg.BlockCustomIP6,
		BlockedResponseTTL:     60,
		SafeSearch:             splitListEnv(cfg.SafeSearch),
		BogusNXDOMAIN:          splitListEnv(cfg.BogusNXDOMAIN),
		AAAADisabled:           cfg.AAAADisabled,
		RefuseANY:              cfg.RefuseANY,
		DNSSEC:                 cfg.DNSSEC,
		PrivatePTR:             cfg.PrivatePTR,
		ResolveClientHostnames: true,
		AllowedClients:         splitListEnv(cfg.DNSAllowedClients),
		DisallowedClients:      splitListEnv(cfg.DNSDisallowedClients),
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

// splitListEnv splits a space/comma-separated env list into trimmed entries.
func splitListEnv(v string) []string {
	return strings.FieldsFunc(v, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	})
}

// equalStringSlices reports whether two string slices are equal.
func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// waitForHTTPServer waits for the HTTP server goroutine to finish, giving up
// after cfg.HTTPShutdownTimeout.

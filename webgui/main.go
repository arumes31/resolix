// Package main is the entry point for Resolix.
// application. It initializes configuration, storage, parsers, and the
// HTTP server, then manages the application lifecycle including graceful
// shutdown.
package main

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/arumes31/resolix/webgui/internal/api"
	"github.com/arumes31/resolix/webgui/internal/blocklist"
	"github.com/arumes31/resolix/webgui/internal/config"
	"github.com/arumes31/resolix/webgui/internal/configsync"
	"github.com/arumes31/resolix/webgui/internal/controllertls"
	"github.com/arumes31/resolix/webgui/internal/dnsroutes"
	"github.com/arumes31/resolix/webgui/internal/dnsserver"
	"github.com/arumes31/resolix/webgui/internal/dnssettings"
	"github.com/arumes31/resolix/webgui/internal/forwarder"
	"github.com/arumes31/resolix/webgui/internal/health"
	"github.com/arumes31/resolix/webgui/internal/logger"
	"github.com/arumes31/resolix/webgui/internal/magicdns"
	"github.com/arumes31/resolix/webgui/internal/models"
	"github.com/arumes31/resolix/webgui/internal/parser"
	"github.com/arumes31/resolix/webgui/internal/policy"
	"github.com/arumes31/resolix/webgui/internal/resolver"
	"github.com/arumes31/resolix/webgui/internal/storage"
)

// Version is injected for packaged builds and otherwise loaded from VERSION.
// BuildInfo identifies the source revision used for the build.
var (
	Version   string
	BuildInfo = "local"
)

//go:embed VERSION
var embeddedVersion string

func init() {
	if Version == "" {
		Version = strings.TrimSpace(embeddedVersion)
	}
}

//go:embed templates static
var embedFS embed.FS

// generateNonce creates a cryptographically random base64-encoded nonce.
func generateNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate CSP nonce: %w", err)
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// cspMiddleware generates a nonce per request, sets CSP headers, and injects
// the nonce into the request context for template rendering.
func cspMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nonce, err := generateNonce()
		if err != nil {
			logger.Error("Failed to generate CSP nonce: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		// Set Content-Security-Policy HTTP header
		csp := "default-src 'self'; " +
			"script-src 'nonce-" + nonce + "'; " +
			"style-src 'self' 'nonce-" + nonce + "'; " +
			"font-src 'self'; " +
			"img-src 'self' data:; " +
			"connect-src 'self'; " +
			"frame-ancestors 'none'"
		w.Header().Set("Content-Security-Policy", csp)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("X-XSS-Protection", "0")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")

		// Store nonce in context for handlers to access
		ctx := context.WithValue(r.Context(), nonceKey{}, nonce)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// nonceKey is the context key for the CSP nonce.
type nonceKey struct{}

// nonceFromContext retrieves the CSP nonce from the request context.
func nonceFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(nonceKey{}).(string); ok {
		return v
	}
	return ""
}

// verifyConfig runs pre-flight checks on the configuration before the server starts.
// Critical failures cause the program to exit; non-critical issues produce warnings.
func verifyConfig(cfg *config.Config) {
	errs, warnings := cfg.VerifyConfig()

	for _, w := range warnings {
		logger.Warning("%s", w)
	}

	for _, e := range errs {
		logger.Error("%s", e)
	}

	if len(errs) > 0 {
		logger.Fatal("Critical configuration errors detected, exiting")
	}
}

func migrateTLSState(cfg *config.Config) {
	if cfg.WebTLSMode != controllertls.WebTLSAuto && cfg.ControllerTLSTrust != controllertls.TrustTOFUTailnet {
		return
	}
	legacyTLSDir := filepath.Join(cfg.HistoryDir, "tls")
	migratedTLSFiles, err := controllertls.MigrateLegacyState(
		legacyTLSDir,
		cfg.FullTLSStateDir(),
		cfg.ControllerTLSPinFile,
	)
	if err != nil {
		logger.Fatal("Failed to migrate legacy TLS state: %v", err)
	}
	if migratedTLSFiles > 0 {
		logger.Info("Copied %d legacy TLS state file(s) to the dedicated state directory", migratedTLSFiles)
	}
}

func migrateConfigState(cfg *config.Config) {
	migratedConfigFiles, err := config.MigrateLegacyState(cfg)
	if err != nil {
		logger.Fatal("Failed to migrate managed configuration: %v", err)
	}
	if migratedConfigFiles > 0 {
		logger.Info("Copied %d managed configuration file(s) to the dedicated config directory", migratedConfigFiles)
	}
}

// generateEnvFile creates a default .env file in the working directory if one does not exist.
// It reads from .env.example if available, otherwise generates from hardcoded defaults.
// It never overwrites an existing .env file.

func main() {
	// Generate .env file if missing (Item 52)
	generateEnvFile()

	// Load configuration
	cfg := config.LoadConfig()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigChan)

	runApplication(cfg, sigChan)
}

// runApplication initializes the application, waits for a shutdown request,
// and releases all resources. The injected signal channel keeps the lifecycle
// deterministic in tests while main retains ownership of OS signal handling.
func runApplication(cfg *config.Config, sigChan <-chan os.Signal) {
	migrateConfigState(cfg)
	configureLogging(cfg)

	// Run startup configuration verification (Items 54 & 55)
	verifyConfig(cfg)
	migrateTLSState(cfg)

	// Initialize storage
	store := storage.NewStore(cfg)
	store.Init()

	// Start client aliases file reload if configured (Item 50)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cfg.StartClientAliasesReload(ctx)

	tmpl := parseTemplates()
	prs := parser.NewParser(store, cfg.Debug)
	srv := api.NewServer(cfg, store, prs, tmpl)
	srv.SetBuildInfo(Version, BuildInfo)
	dnsSettingsStore, err := dnssettings.Load(cfg.FullDNSSettingsPath(), defaultDNSSettings(cfg))
	if err != nil {
		logger.Fatal("Failed to load managed DNS settings: %v", err)
	}
	srv.SetDNSSettingsStore(dnsSettingsStore)
	managedDNS := dnsSettingsStore.Get()

	magicDNSStore, magicDNSSyncer := setupMagicDNS(cfg)
	srv.SetMagicDNS(magicDNSStore, magicDNSSyncer)

	// Item 59: Initialize and start reverse DNS resolver
	res := resolver.New()
	srv.SetResolver(res)
	go res.Start(ctx)
	logger.Info("Reverse DNS resolver started")

	// Item 61: Initialize and start blocklist
	bl := blocklist.New(cfg.FullBlocklistPath())
	srv.SetBlocklist(bl)
	bl.StartReload(ctx)
	logger.Info("Blocklist loaded with %d entries", bl.Count())

	// Item 66: Initialize and start DNS routes
	dr := dnsroutes.New(cfg.FullDNSRoutesPath())
	srv.SetDNSRoutes(dr)
	dr.StartReload(ctx)
	logger.Info("DNS routes loaded: %d rules", dr.Count())

	// Item 65: Start DNS loop detection
	srv.StartDNSLoopDetection(ctx)
	logger.Info("DNS loop detection started")

	fwd := forwarder.NewForwarder(cfg)
	srv.SetForwarder(fwd)

	// Item 88: Set forwarder version to match main version (settable via -ldflags)
	forwarder.Version = Version

	// Items 90, 91, 94: Wire forwarder sync callbacks for agent mode
	fwd.SetDNSRoutesFn(func(routes map[string]string) {
		if err := dr.SetRoutes(routes); err != nil {
			logger.Warning("Failed to sync DNS routes from controller: %v", err)
		}
	})
	fwd.SetAliasesFn(func(aliases map[string]string) {
		cfg.SetClientAliases(aliases)
	})
	fwd.SetMagicDNSFn(magicDNSStore.Apply)
	fwd.SetUpstreamHealthFn(func(node string, health map[string]float64) {
		store.SetUpstreamHealth(node, health)
	})

	// Create static file server from embedded FS
	staticHandler := newStaticHandler()

	// Controller-managed upstream settings override their environment bootstrap
	// values when present and are hot-reloaded below and after API saves.
	loadResolverSettings := func() ([]string, []string) {
		bootstrapServers := strings.Fields(cfg.BootstrapDNS)
		if p := cfg.FullUpstreamsPath(); p != "" {
			settings := dnsroutes.LoadUpstreamSettings(p)
			if settings.BootstrapConfigured {
				bootstrapServers = settings.BootstrapServers
			}
			if len(settings.Upstreams) > 0 {
				return settings.Upstreams, bootstrapServers
			}
		}
		return strings.Fields(cfg.UpstreamDNS), bootstrapServers
	}
	upstreamSpecs, bootstrapServers := loadResolverSettings()

	// Initialize the protocol-aware health checker with the same bootstrap
	// resolvers used by the live upstream pool.
	checker := health.NewChecker(cfg, strings.Join(upstreamSpecs, " "), bootstrapServers)

	// Start Trend Analysis
	store.StartStatsTrends(ctx)

	// History Archiver (periodic plus automatic high-water draining)
	go store.RunArchiver(ctx, cfg.BatchArchiveInterval)

	// Cleanup (uses configurable CleanupPendingInterval)
	go func() {
		ticker := time.NewTicker(cfg.CleanupPendingInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				store.CleanupPending(time.Now())
			}
		}
	}()

	errChan := make(chan error, 2)

	// Embedded DNS server (replaces dnsmasq). Pipeline: refuse-ANY/AAAA-disable
	// → typed rewrites → MagicDNS → private PTR → safe-search → filter
	// → cache → client upstreams → route → global pool → bogus-NXDOMAIN →
	// cache store → respond.
	// Each answered query becomes a QueryEvent fed into Store + SSE (and the
	// forwarder in agent mode). dnsDone closes when both listeners have
	// stopped, so shutdown can archive after events have ceased.

	// Filter engine (Step 2): local files (BLOCKLIST_FILE entries now
	// actually block) plus URL subscriptions with conditional auto-update.
	filterEng, _ := setupFilterEngine(ctx, cfg, srv)

	// Typed rewrites store (Step 3): loaded from the persistence file, or
	// seeded from the DOMAINS env on first boot only.
	rwStore := loadRewritesStore(cfg)
	srv.SetRewritesStore(rwStore)

	// Per-client registry (Step 5): JSON-persisted, hot-reloaded.
	clientReg := setupClientsRegistry(ctx, cfg, srv)

	// Policy (Step 3): safe search, bogus NXDOMAIN, AAAA disable, refuse ANY.
	pol := policy.New(policy.Config{
		SafeSearch:   managedDNS.SafeSearch,
		BogusNets:    managedDNS.BogusNXDOMAIN,
		AAAADisabled: managedDNS.AAAADisabled,
		RefuseANY:    managedDNS.RefuseANY,
	})

	// Upstream pool (Step 4): modes, fallback, bootstrap, ECS, DNS64.
	pool := setupUpstreamPool(
		ctx,
		cfg,
		managedDNS,
		store,
		srv,
		checker,
		loadResolverSettings,
		upstreamSpecs,
		bootstrapServers,
	)
	checker.SetProbeFunc(pool.Probe)
	go checker.Start(ctx, func(_ []string, latencies map[string]float64) {
		store.SetUpstreamHealth(cfg.NodeName, latencies)
		if cfg.Mode == config.ModeAgent {
			fwd.ReportHealth(latencies)
		}
		logger.Debug("Health status updated for node %s. Latencies: %v", cfg.NodeName, latencies)
	})
	fwd.SetDNSConfigFn(func(snapshot configsync.Snapshot) error {
		return srv.ApplyConfigSnapshot(snapshot)
	})

	// Start forwarding only after every config-sync target is initialized, so
	// the initial agent sync cannot race application startup.
	forwarderDone := make(chan error, 1)

	dnsSrv := dnsserver.New(dnsserver.Config{
		Addr:                cfg.DNSListenAddr,
		Port:                cfg.DNSListenPort,
		Upstreams:           upstreamSpecs,
		Rewrites:            rwStore,
		MagicDNS:            magicDNSStore,
		MagicDNSTTL:         cfg.MagicDNSTTL,
		Policy:              pol,
		Pool:                pool,
		Routes:              dr,
		Clients:             clientReg,
		AliasFunc:           store.GetAlias,
		CacheSize:           managedDNS.CacheSize,
		CacheMinTTL:         managedDNS.CacheMinTTL,
		CacheMaxTTL:         managedDNS.CacheMaxTTL,
		CacheOptimistic:     managedDNS.CacheOptimistic,
		CachePrefetch:       managedDNS.CachePrefetch,
		CachePrefetchWindow: time.Duration(managedDNS.CachePrefetchWindowMS) * time.Millisecond,
		CachePrefetchHits:   managedDNS.CachePrefetchHits,
		CacheSERVFAILTTL:    time.Duration(managedDNS.CacheSERVFAILTTLMS) * time.Millisecond,
		// Step 6: ACL, rate limit, private PTR, DNSSEC, DoT.
		AllowedClients:         strings.Join(managedDNS.AllowedClients, " "),
		DisallowedClients:      strings.Join(managedDNS.DisallowedClients, " "),
		RateLimitQPS:           managedDNS.RateLimitQPS,
		InternalRateLimitQPS:   managedDNS.InternalRateLimitQPS,
		RateLimitEDE:           managedDNS.RateLimitEDE,
		RateLimitIPv4Prefix:    managedDNS.RateLimitIPv4Prefix,
		RateLimitIPv6Prefix:    managedDNS.RateLimitIPv6Prefix,
		RateLimitAllowlist:     strings.Join(managedDNS.RateLimitAllowlist, " "),
		PrivatePTR:             managedDNS.PrivatePTR,
		PrivatePTRUpstreams:    managedDNS.PrivatePTRUpstreams,
		ResolveClientHostnames: managedDNS.ResolveClientHostnames,
		DNSSEC:                 managedDNS.DNSSEC,
		Resolver:               res,
		DoTEnabled:             cfg.DoTEnabled,
		DoTPort:                cfg.DoTPort,
		TLSCertFile:            cfg.TLSCertFile,
		TLSKeyFile:             cfg.TLSKeyFile,
		TCPIdleTimeout:         cfg.DNSTCPIdleTimeout,
		TCPMaxQueries:          cfg.DNSTCPMaxQueries,
		TCPMaxConnections:      cfg.DNSTCPMaxConnections,
		NodeName:               cfg.NodeName,
		Filter:                 filterEng,
		BlockingMode:           managedDNS.BlockingMode,
		BlockCustomIP4:         managedDNS.BlockCustomIPv4,
		BlockCustomIP6:         managedDNS.BlockCustomIPv6,
		BlockedResponseTTL:     managedDNS.BlockedResponseTTL,
	}, func(ev models.QueryEvent, excludeFromStats bool) {
		// exclude_from_stats clients emit to SSE only (no store/forwarder).
		if !excludeFromStats {
			store.AddEvent(ev)
			if cfg.Mode == config.ModeAgent {
				fwd.EnqueueEvent(ev)
			}
		}
		srv.BroadcastEvent(ev)
	})
	dnsDone := make(chan struct{})
	srv.SetDNSServer(dnsSrv)
	magicDNSStore.SetOnChange(func() { dnsSrv.ClearCache() })
	if magicDNSSyncer != nil {
		go magicDNSSyncer.Run(ctx, func(syncErr error) {
			if syncErr != nil {
				logger.Warning("MagicDNS synchronization failed; retaining last-good records: %v", syncErr)
				return
			}
			snapshot := magicDNSStore.Snapshot()
			logger.Info("MagicDNS synchronized %d records; next refresh in %s", len(snapshot.Records), cfg.MagicDNSSyncInterval)
		})
	}
	srv.SetDNSSettingsApplyFunc(func(settings dnssettings.Settings) {
		pool.SetRuntimeSettings(settings.UpstreamMode, settings.FallbackDNS, settings.ECSClientSubnet)
		dnsSrv.ApplySettings(settings)
	})
	go func() {
		err := fwd.Start()
		forwarderDone <- err
		if err != nil {
			errChan <- err
		}
	}()
	dr.SetOnChange(func() {
		pool.ClearRouteCache()
		dnsSrv.ClearCache()
	})
	go func() {
		defer close(dnsDone)
		protocols := "UDP+TCP"
		if cfg.DoTEnabled {
			protocols += fmt.Sprintf("+DoT:%d", cfg.DoTPort)
		}
		logger.Info("DNS server listening on %s (%s)", dnsSrv.ListenAddr(), protocols)
		if err := dnsSrv.Start(ctx); err != nil {
			errChan <- err
		}
	}()

	// Start HTTP server and report completion so shutdown can wait before
	// closing storage used by in-flight handlers.
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- srv.Start(ctx, staticHandler, cspMiddleware, nonceFromContext)
	}()

	serverStopped := false
	select {
	case sig := <-sigChan:
		logger.Info("Received signal %v, initiating graceful shutdown", sig)
	case err := <-errChan:
		logger.Error("Server error: %v", err)
	case err := <-serverDone:
		serverStopped = true
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("HTTP server error: %v", err)
		}
	}

	// Step 1: Cancel context to stop all background goroutines
	logger.Info("Shutdown step 1: Stopping background goroutines...")
	cancel()

	// Step 2: Stop the log forwarder
	logger.Info("Shutdown step 2: Stopping log forwarder...")
	fwd.Stop()
	waitForForwarder(cfg, forwarderDone)

	// Step 3: Stop DNS routes reload
	logger.Info("Shutdown step 3: Stopping DNS routes reload...")
	dr.Stop()

	// Step 4: Stop blocklist reload
	logger.Info("Shutdown step 4: Stopping blocklist reload...")
	bl.Stop()

	// Step 5: Wait for HTTP handlers to finish before closing storage.
	logger.Info("Shutdown step 5: Waiting for HTTP server to finish...")
	if !serverStopped {
		waitForHTTPServer(cfg, serverDone)
	}

	// Step 6: Flush pending batch buffers to SQLite. Wait for the DNS
	// listeners to stop first so no in-flight query races the archive.
	logger.Info("Shutdown step 6: Waiting for DNS server to stop...")
	waitForDNSServer(cfg, dnsDone)
	logger.Info("Shutdown step 6: Flushing pending batch buffers to SQLite...")
	archived := store.ArchiveStep(time.Now())
	logger.Info("Shutdown step 6: Archived %d events to SQLite", archived)

	// Step 7: Close the database and release resources
	logger.Info("Shutdown step 7: Closing storage (database, prepared statements, background goroutines)...")
	store.Close()

	// Step 8: Flush and close log file if file logging is enabled
	logger.Info("Shutdown step 8: Flushing log file...")
	logger.Flush()
	logger.CloseFile()

	logger.Info("Graceful shutdown complete")
}

func configureLogging(cfg *config.Config) {
	// Initialize the level-aware logger (Item 51)
	logger.SetLevel(cfg.LogLevel)
	logger.Info("Resolix v%s starting in %s mode", Version, cfg.Mode)
	logger.Info("Log level set to %s", cfg.LogLevel)

	// Enable file logging if configured (Item 84)
	if cfg.LogFile != "" {
		if err := logger.EnableFileLogging(cfg.LogFile); err != nil {
			logger.Warning("Failed to enable file logging: %v", err)
		}
	}

	if cfg.BaseURL != "/" {
		logger.Info("Base URL set to %s", cfg.BaseURL)
	}
}

func setupMagicDNS(cfg *config.Config) (*magicdns.Store, *magicdns.Syncer) {
	magicDNSStore := magicdns.NewStore(cfg.FullMagicDNSStatePath())
	if cfg.Mode == config.ModeAgent || cfg.MagicDNSEnabled {
		loadedStore, err := magicdns.Load(cfg.FullMagicDNSStatePath())
		if err != nil {
			logger.Fatal("Failed to load MagicDNS state: %v", err)
		}
		magicDNSStore = loadedStore
	}
	if cfg.Mode != config.ModeController || !cfg.MagicDNSEnabled {
		return magicDNSStore, nil
	}
	if snapshot := magicDNSStore.Snapshot(); snapshot.Tailnet != "" && snapshot.Tailnet != cfg.MagicDNSTailnet {
		if err := magicDNSStore.Replace(cfg.MagicDNSTailnet, []magicdns.Record{}, time.Time{}); err != nil {
			logger.Fatal("Failed to reset MagicDNS state for the configured tailnet: %v", err)
		}
	}
	magicDNSClient, err := magicdns.NewClient(
		cfg.MagicDNSClientID,
		cfg.MagicDNSClientSecret,
		cfg.MagicDNSTailnet,
	)
	if err != nil {
		logger.Fatal("Failed to configure MagicDNS client: %v", err)
	}
	magicDNSSyncer, err := magicdns.NewSyncer(
		magicDNSClient,
		magicDNSStore,
		cfg.MagicDNSTailnet,
		cfg.MagicDNSSyncInterval,
	)
	if err != nil {
		logger.Fatal("Failed to configure MagicDNS synchronization: %v", err)
	}
	return magicDNSStore, magicDNSSyncer
}

// setupFilterEngine builds and starts the filter engine from configuration
// and wires it into the API server.
func waitForHTTPServer(cfg *config.Config, serverDone chan error) {
	timer := time.NewTimer(cfg.HTTPShutdownTimeout)
	select {
	case err := <-serverDone:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Warning("HTTP server shutdown error: %v", err)
		}
	case <-timer.C:
		logger.Warning("HTTP server did not stop within %s", cfg.HTTPShutdownTimeout)
	}
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
}

func waitForDNSServer(cfg *config.Config, dnsDone <-chan struct{}) {
	timer := time.NewTimer(cfg.HTTPShutdownTimeout)
	select {
	case <-dnsDone:
	case <-timer.C:
		logger.Warning("DNS server did not stop within %s", cfg.HTTPShutdownTimeout)
	}
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
}

// waitForForwarder ensures Start has returned after its final durable backlog
// flush before shutdown can proceed to close shared resources.
func waitForForwarder(cfg *config.Config, forwarderDone <-chan error) {
	timer := time.NewTimer(cfg.HTTPShutdownTimeout)
	defer timer.Stop()
	select {
	case err := <-forwarderDone:
		if err != nil {
			logger.Warning("Forwarder shutdown error: %v", err)
		}
	case <-timer.C:
		logger.Warning("Forwarder did not stop within %s", cfg.HTTPShutdownTimeout)
	}
}

// init ensures the working directory is set correctly for .env generation.
func init() {
	// If running from a different directory, try to find the project root
	// by looking for go.mod or .env.example
	if _, err := os.Stat(".env.example"); err != nil {
		// Check if we're in the webgui/ subdirectory
		if _, err := os.Stat(filepath.Join("..", ".env.example")); err == nil {
			// Best effort: move to the project root; failure is non-fatal.
			_ = os.Chdir("..")
		}
	}
}

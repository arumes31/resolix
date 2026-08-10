// Package main is the entry point for the tailscale-dnsrewrite web GUI
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
	"html/template"
	"io/fs"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"tailscale-dnsrewrite/webgui/internal/api"
	"tailscale-dnsrewrite/webgui/internal/blocklist"
	"tailscale-dnsrewrite/webgui/internal/clients"
	"tailscale-dnsrewrite/webgui/internal/config"
	"tailscale-dnsrewrite/webgui/internal/dnsroutes"
	"tailscale-dnsrewrite/webgui/internal/dnsserver"
	"tailscale-dnsrewrite/webgui/internal/filter"
	"tailscale-dnsrewrite/webgui/internal/forwarder"
	"tailscale-dnsrewrite/webgui/internal/health"
	"tailscale-dnsrewrite/webgui/internal/logger"
	"tailscale-dnsrewrite/webgui/internal/models"
	"tailscale-dnsrewrite/webgui/internal/parser"
	"tailscale-dnsrewrite/webgui/internal/policy"
	"tailscale-dnsrewrite/webgui/internal/resolver"
	"tailscale-dnsrewrite/webgui/internal/rewrites"
	"tailscale-dnsrewrite/webgui/internal/storage"
	"tailscale-dnsrewrite/webgui/internal/upstream"
)

// Version represents the current application version.
var (
	Version   = "dev"
	BuildInfo = "local"
)

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

// generateEnvFile creates a default .env file in the working directory if one does not exist.
// It reads from .env.example if available, otherwise generates from hardcoded defaults.
// It never overwrites an existing .env file.
func generateEnvFile() {
	envPath := ".env"
	if _, err := os.Stat(envPath); err == nil {
		logger.Debug(".env file already exists, skipping generation")
		return
	}

	// Try to copy from .env.example
	examplePath := ".env.example"
	content := defaultEnvContent()

	if exampleData, err := os.ReadFile(examplePath); err == nil {
		content = string(exampleData)
		logger.Info("Using .env.example as template for .env generation")
	} else {
		logger.Info(".env.example not found, generating .env from defaults")
	}

	if err := os.WriteFile(envPath, []byte(content), 0600); err != nil { // #nosec G703 -- path is the hardcoded constant ".env" in the working directory, never user input
		logger.Warning("Failed to generate .env file: %v", err)
	} else {
		logger.Info("Generated default .env file at %s", envPath)
	}
}

// defaultEnvContent returns the default .env file content with all supported variables.
func defaultEnvContent() string {
	return `# Tailscale Authentication Key
TS_AUTHKEY=tskey-auth-xxxxx
# Prefer a mounted secret file in containers; TS_AUTHKEY takes precedence.
# TS_AUTHKEY_FILE=/run/secrets/tailscale_authkey

# Space-separated upstream DNS servers
UPSTREAM_DNS="8.8.8.8 8.8.4.4"

# Comma-separated domain:ip mappings
DOMAINS=.internal.net:100.1.2.3,app.example.com:100.4.5.6

# Domain used for upstream health checks
HEALTHCHECK_DOMAIN=google.com

# Web GUI listening port
PORT=35353
# Web/API bind address
WEB_LISTEN_ADDR=0.0.0.0

# Run mode (master or slave)
MODE=master

# URL of the Master node (Required for slave mode)
# NOTE: HTTPS is strongly preferred (use https:// with valid TLS certificates) to encrypt
# master/slave communication. Plain HTTP transmits data unencrypted and should only be
# used on trusted/private networks (e.g., Tailscale).
# Example: MASTER_URL=https://master-node:35353
# MASTER_URL=http://master-ip:35353

# Unique identifier for this node
NODE_NAME=dns-server-1

# Secret token to authenticate logs from slave nodes
# INGEST_SECRET=your-secret-token

# Web GUI authentication. Set both values together. INGEST_SECRET is required
# when web authentication is disabled.
# WEB_USERNAME=admin
# WEB_PASSWORD=

# Log level: DEBUG, INFO, WARNING, ERROR (default: INFO)
LOG_LEVEL=INFO

# Base URL for hosting behind a reverse proxy subpath (default: /)
# Example: BASE_URL=/dashboard
BASE_URL=/
# Comma-separated proxy IPs/CIDRs allowed to supply Forwarded/X-Forwarded-*.
# TRUSTED_PROXIES=127.0.0.1,10.0.0.0/8
# COOKIE_SECURE=true

# Database file name or absolute path (default: dns.db)
# If relative, it is placed inside HISTORY_DIR
DB_PATH=dns.db

# Path to a file with client IP=Alias mappings (one per line, # comments supported)
# CLIENT_ALIASES_FILE=/etc/tailscale-dnsrewrite/aliases.txt

# Comma-separated client IP:Alias mappings (alternative to file-based aliases)
# CLIENT_ALIASES=192.168.1.1:Gateway,100.64.0.1:Router

# Path to a hosts-format blocklist file (Item 61)
# BLOCKLIST_FILE=/etc/tailscale-dnsrewrite/blocklist.hosts

# Path to a JSON file with upstream DNS server list (Item 62)
# UPSTREAMS_FILE=/etc/tailscale-dnsrewrite/upstreams.json

# Path to a JSON file with domain-specific DNS routing rules (Item 66)
# DNS_ROUTES_FILE=/etc/tailscale-dnsrewrite/dns-routes.json

# DNS server listen address and port for the embedded DNS server (replaces dnsmasq)
# DNS_LISTEN_ADDR defaults to TAILSCALE_IP (set by entrypoint.sh), then 0.0.0.0
# DNS_LISTEN_ADDR=0.0.0.0
# DNS_LISTEN_PORT=53

# Filter engine (blocklists with adblock/hosts/domain-list/regex syntax)
# Space- or comma-separated subscription URLs, auto-updated with ETag/Last-Modified
# BLOCKLIST_URLS=https://example.com/blocklist.txt
# ALLOWLIST_URLS=https://example.com/allowlist.txt
# Local exceptions-only list (@@ semantics for every entry)
# ALLOWLIST_FILE=/etc/tailscale-dnsrewrite/allowlist.txt
# FILTER_UPDATE_INTERVAL=24h

# Blocking response mode: nxdomain (default), null_ip (0.0.0.0/::), refused,
# or custom_ip (BLOCK_CUSTOM_IP4/BLOCK_CUSTOM_IP6)
# BLOCKING_MODE=nxdomain
# BLOCK_CUSTOM_IP4=0.0.0.0
# BLOCK_CUSTOM_IP6=::

# Typed DNS rewrites (A/AAAA/CNAME/PTR/MX/TXT/SRV + RCODE), managed via
# /api/rewrites and persisted here. DOMAINS seeds it on first boot only.
# REWRITES_FILE=rewrites.json

# Policy features
# SAFE_SEARCH=google,bing,ddg,youtube
# BOGUS_NXDOMAIN=10.0.0.0/8,192.0.2.33 (answers fully inside these become NXDOMAIN)
# AAAA_DISABLED=true (AAAA queries get NOERROR-empty answers)
# REFUSE_ANY=true (default; QTYPE ANY is refused)

# Upstream pool (Step 4): schemes udp:// tcp:// tls:// https:// (DoT/DoH)
# UPSTREAM_MODE=load_balance (default) | parallel | strict
# FALLBACK_DNS=9.9.9.9 (used only when all primary upstreams fail)
# BOOTSTRAP_DNS=8.8.8.8 (plain UDP; required for hostname upstreams like tls://dns.google)
# ECS_CLIENT_SUBNET=192.0.2.0/24 (EDNS0 client subnet sent to upstreams)
# DNS64=true (synthesize AAAA from A on empty AAAA answers)
# DNS64_PREFIXES=64:ff9b::/96
# CACHE_OPTIMISTIC=true (serve stale entries while refreshing in background)
# CACHE_MIN_TTL=60
# CACHE_MAX_TTL=600

# Per-client policies (Step 5)
# CLIENTS_FILE=clients.json (per-client registry: filtering/safe-search/blocked
#   services/custom upstreams/schedules, hot-reloaded every 30s)
# BLOCKED_SERVICES=facebook,tiktok (global blocked-service IDs; per-client
#   overrides live in the clients file)

# DNS access and encrypted serving (Step 6)
# Comma/space-separated IPs or CIDRs. Disallowed clients are dropped; when an
# allowed list is set, all clients outside it receive REFUSED.
# DNS_ALLOWED_CLIENTS=100.64.0.0/10,192.168.0.0/16
# DNS_DISALLOWED_CLIENTS=100.64.0.5
# RATE_LIMIT_QPS=20 (per IPv4 /24 or IPv6 /56; 0 disables)
# PRIVATE_PTR=true (answer known RFC1918/CGNAT/ULA client PTRs as <name>.lan)
# DNSSEC=false (pass the DNSSEC DO bit upstream; no local validation)
# DOH_ENABLED=false
# DOH_PATH=/dns-query
# DOH_AUTH_TOKEN=change-me (Bearer token; when unset, only private/tailnet clients)
# DOT_ENABLED=false
# DOT_PORT=853
# TLS_CERT_FILE=/etc/tailscale-dnsrewrite/tls.crt
# TLS_KEY_FILE=/etc/tailscale-dnsrewrite/tls.key

# Upstream latency alert threshold in milliseconds (Item 68, default: 200)
# UPSTREAM_LATENCY_THRESHOLD=200

# Configurable timeout values (Item 80)
# SSE_KEEPALIVE_INTERVAL=30s
# Maximum periodic interval; busy queues also archive at the trigger size.
# BATCH_ARCHIVE_INTERVAL=30m
# ARCHIVE_QUEUE_CAPACITY=100000
# ARCHIVE_TRIGGER_SIZE=5000
# ARCHIVE_WRITE_BATCH_SIZE=5000
# CLEANUP_INTERVAL=1h
# FORWARDER_RETRY_INTERVAL=5s
# HTTP_READ_TIMEOUT=10s
# HTTP_WRITE_TIMEOUT=30s
# HTTP_SHUTDOWN_TIMEOUT=10s
# MAX_REQUEST_SIZE=1048576

# Optional log file for file-based logging (default: empty = stderr only)
# LOG_FILE=/var/log/tailscale-dnsrewrite.log

# ===== Distributed Architecture (Items 85-94) =====
# Maximum retry attempts for forwarding with exponential backoff (default: 6)
# MAX_RETRY_ATTEMPTS=6

# Interval for slave heartbeats to master (default: 30s)
# HEARTBEAT_INTERVAL=30s

# Interval for syncing client aliases from master (default: 5m)
# SYNC_ALIASES_INTERVAL=5m

# Interval for syncing DNS routes from master (default: 5m)
# SYNC_DNSROUTES_INTERVAL=5m

# Interval for syncing upstream health from master (default: 1m)
# SYNC_UPSTREAM_HEALTH_INTERVAL=1m

# Time after which a node is considered offline without heartbeat (default: 90s)
# NODE_OFFLINE_THRESHOLD=90s
`
}

func main() {
	// Generate .env file if missing (Item 52)
	generateEnvFile()

	// Load configuration
	cfg := config.LoadConfig()

	// Initialize the level-aware logger (Item 51)
	logger.SetLevel(cfg.LogLevel)
	logger.Info("Tailscale DNS Monitor v%s starting in %s mode", Version, cfg.Mode)
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

	// Run startup configuration verification (Items 54 & 55)
	verifyConfig(cfg)

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

	// Items 90, 91, 94: Wire forwarder sync callbacks for slave mode
	fwd.SetDNSRoutesFn(func(routes map[string]string) {
		if err := dr.SetRoutes(routes); err != nil {
			logger.Warning("Failed to sync DNS routes from master: %v", err)
		}
	})
	fwd.SetAliasesFn(func(aliases map[string]string) {
		cfg.SetClientAliases(aliases)
	})
	fwd.SetUpstreamHealthFn(func(node string, health map[string]float64) {
		store.SetUpstreamHealth(node, health)
	})

	// Create static file server from embedded FS
	staticHandler := newStaticHandler()

	// Upstream specs: upstreams.json overrides env upstreams when the file
	// contains entries (hot-reloaded below and after API saves).
	loadSpecs := func() []string {
		if p := cfg.FullUpstreamsPath(); p != "" {
			if list := dnsroutes.LoadUpstreams(p); len(list) > 0 {
				return list
			}
		}
		return strings.Fields(cfg.UpstreamDNS)
	}
	upstreamSpecs := loadSpecs()

	// Initialize health checker (UDP probe; covers plain-IP upstreams only)
	checker := health.NewChecker(cfg, strings.Join(upstreamSpecs, " "))
	go checker.Start(ctx, func(_ []string, latencies map[string]float64) {
		store.SetUpstreamHealth(cfg.NodeName, latencies)
		if cfg.Mode == "slave" {
			fwd.ReportHealth(latencies)
		}
		logger.Debug("Health status updated for node %s. Latencies: %v", cfg.NodeName, latencies)
	})

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

	// Start Forwarder for Slave mode
	go func() {
		if err := fwd.Start(); err != nil {
			errChan <- err
		}
	}()

	// Embedded DNS server (replaces dnsmasq). Pipeline: refuse-ANY/AAAA-disable
	// → typed rewrites → private PTR → safe-search → filter → blocked services
	// → cache → client upstreams → route → global pool → bogus-NXDOMAIN →
	// cache store → respond.
	// Each answered query becomes a QueryEvent fed into Store + SSE (and the
	// forwarder in slave mode). dnsDone closes when both listeners have
	// stopped, so shutdown can archive after events have ceased.

	// Filter engine (Step 2): local files (BLOCKLIST_FILE entries now
	// actually block) plus URL subscriptions with conditional auto-update.
	filterEng := setupFilterEngine(ctx, cfg, srv)

	// Typed rewrites store (Step 3): loaded from the persistence file, or
	// seeded from the DOMAINS env on first boot only.
	rwStore := loadRewritesStore(cfg)
	srv.SetRewritesStore(rwStore)

	// Per-client registry (Step 5): JSON-persisted, hot-reloaded.
	clientReg := setupClientsRegistry(ctx, cfg, srv)

	// Policy (Step 3): safe search, bogus NXDOMAIN, AAAA disable, refuse ANY.
	pol := policy.New(policy.Config{
		SafeSearch:   splitListEnv(cfg.SafeSearch),
		BogusNets:    splitListEnv(cfg.BogusNXDOMAIN),
		AAAADisabled: cfg.AAAADisabled,
		RefuseANY:    cfg.RefuseANY,
	})

	// Upstream pool (Step 4): modes, fallback, bootstrap, ECS, DNS64.
	pool := setupUpstreamPool(ctx, cfg, store, srv, checker, loadSpecs, upstreamSpecs)
	dr.SetOnChange(pool.ClearRouteCache)

	dnsSrv := dnsserver.New(dnsserver.Config{
		Addr:            cfg.DNSListenAddr,
		Port:            cfg.DNSListenPort,
		Upstreams:       upstreamSpecs,
		Rewrites:        rwStore,
		Policy:          pol,
		Pool:            pool,
		Routes:          dr,
		Clients:         clientReg,
		BlockedServices: splitListEnv(cfg.BlockedServices),
		AliasFunc:       store.GetAlias,
		CacheMinTTL:     cfg.CacheMinTTL,
		CacheMaxTTL:     cfg.CacheMaxTTL,
		CacheOptimistic: cfg.CacheOptimistic,
		// Step 6: ACL, rate limit, private PTR, DNSSEC, DoT.
		AllowedClients:    cfg.DNSAllowedClients,
		DisallowedClients: cfg.DNSDisallowedClients,
		RateLimitQPS:      cfg.RateLimitQPS,
		PrivatePTR:        cfg.PrivatePTR,
		DNSSEC:            cfg.DNSSEC,
		Resolver:          res,
		DoTEnabled:        cfg.DoTEnabled,
		DoTPort:           cfg.DoTPort,
		TLSCertFile:       cfg.TLSCertFile,
		TLSKeyFile:        cfg.TLSKeyFile,
		NodeName:          cfg.NodeName,
		Filter:            filterEng,
		BlockingMode:      cfg.BlockingMode,
		BlockCustomIP4:    cfg.BlockCustomIP4,
		BlockCustomIP6:    cfg.BlockCustomIP6,
	}, func(ev models.QueryEvent, excludeFromStats bool) {
		// exclude_from_stats clients emit to SSE only (no store/forwarder).
		if !excludeFromStats {
			store.AddEvent(ev)
			if cfg.Mode == "slave" {
				fwd.EnqueueEvent(ev)
			}
		}
		srv.BroadcastEvent(ev)
	})
	dnsDone := make(chan struct{})
	srv.SetDNSServer(dnsSrv)
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

	// Graceful shutdown with signal handling (Item 56)
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

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

// setupFilterEngine builds and starts the filter engine from configuration
// and wires it into the API server.
func setupFilterEngine(ctx context.Context, cfg *config.Config, srv *api.Server) *filter.Engine {
	eng := filter.New()

	// User rules (query-log block/unblock actions) — a plain file source.
	userRulesPath := filepath.Join(cfg.HistoryDir, "user_rules.txt")
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
	for _, u := range splitListEnv(cfg.BlocklistURLs) {
		eng.AddURLSource(u, false)
	}
	for _, u := range splitListEnv(cfg.AllowlistURLs) {
		eng.AddURLSource(u, true)
	}
	eng.StartUpdateLoop(ctx, cfg.FilterUpdateInterval)
	srv.SetFilter(eng)
	return eng
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
func setupUpstreamPool(ctx context.Context, cfg *config.Config, store *storage.Store, srv *api.Server, checker *health.Checker, loadSpecs func() []string, current []string) *upstream.Pool {
	pool := upstream.NewPool(upstream.PoolConfig{
		Mode:             cfg.UpstreamMode,
		PrimarySpecs:     current,
		FallbackSpecs:    strings.Fields(cfg.FallbackDNS),
		BootstrapServers: strings.Fields(cfg.BootstrapDNS),
		ECSClientSubnet:  cfg.ECSClientSubnet,
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
		specs := loadSpecs()
		pool.SetPrimarySpecs(specs)
		checker.UpdateUpstreams(specs)
		current = append([]string(nil), specs...)
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
				specs := loadSpecs()
				reloadMu.Lock()
				changed := !equalStringSlices(specs, current)
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

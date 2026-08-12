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

	"github.com/arumes31/resolix/webgui/internal/api"
	"github.com/arumes31/resolix/webgui/internal/blocklist"
	"github.com/arumes31/resolix/webgui/internal/clients"
	"github.com/arumes31/resolix/webgui/internal/config"
	"github.com/arumes31/resolix/webgui/internal/configsync"
	"github.com/arumes31/resolix/webgui/internal/controllertls"
	"github.com/arumes31/resolix/webgui/internal/dnsroutes"
	"github.com/arumes31/resolix/webgui/internal/dnsserver"
	"github.com/arumes31/resolix/webgui/internal/dnssettings"
	"github.com/arumes31/resolix/webgui/internal/filter"
	"github.com/arumes31/resolix/webgui/internal/forwarder"
	"github.com/arumes31/resolix/webgui/internal/health"
	"github.com/arumes31/resolix/webgui/internal/logger"
	"github.com/arumes31/resolix/webgui/internal/models"
	"github.com/arumes31/resolix/webgui/internal/parser"
	"github.com/arumes31/resolix/webgui/internal/policy"
	"github.com/arumes31/resolix/webgui/internal/resolver"
	"github.com/arumes31/resolix/webgui/internal/rewrites"
	"github.com/arumes31/resolix/webgui/internal/storage"
	"github.com/arumes31/resolix/webgui/internal/upstream"
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
# Direct controller HTTPS. Leave off behind a TLS-terminating reverse proxy.
# Auto mode requires a Tailscale IPv4 address and manages its own CA/leaf.
# WEB_TLS_MODE=off
# WEB_TLS_IP falls back to TAILSCALE_IP from entrypoint.sh.
# WEB_TLS_IP=100.64.0.10

# Run mode (controller or agent)
MODE=controller

# HTTPS URL of the Controller node (required for agent mode).
# Resolix rejects plain HTTP for controller/agent synchronization.
# Example: CONTROLLER_URL=https://controller-node:35353
# CONTROLLER_URL=https://controller-ip:35353
# Agent trust: system for a public/reverse-proxy certificate, or tofu-tailnet
# to pin the first CA seen at a direct 100.64.0.0/10 controller address.
# Generated CA and agent pin state use a dedicated persistent directory.
# TLS_STATE_DIR=/var/lib/resolix-tls
# CONTROLLER_TLS_TRUST=system
# CONTROLLER_TLS_PIN_FILE=controller-ca-pin.json
# Legacy upgrades may still use MASTER_URL; CONTROLLER_URL takes precedence.

# Unique identifier for this node
NODE_NAME=resolix-1
# Optional stable cluster identity. Nodes generate HISTORY_DIR/node-id when unset.
# NODE_ID=resolver-vienna-01

# Secret token to authenticate logs from agent nodes
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

# Database file name or absolute path (default: dns.db)
# Query history and managed DNS configuration use separate persistent mounts.
# HISTORY_DIR=/var/lib/resolix
# CONFIG_DIR=/var/lib/resolix-config
# If relative, it is placed inside HISTORY_DIR
DB_PATH=dns.db

# Path to a file with client IP=Alias mappings (one per line, # comments supported)
# CLIENT_ALIASES_FILE=/etc/resolix/aliases.txt

# Comma-separated client IP:Alias mappings (alternative to file-based aliases)
# CLIENT_ALIASES=192.168.1.1:Gateway,100.64.0.1:Router

# Path to a hosts-format blocklist file (Item 61)
# BLOCKLIST_FILE=/etc/resolix/blocklist.hosts

# Managed upstream file, relative to CONFIG_DIR unless absolute (Item 62)
# UPSTREAMS_FILE=upstreams.json

# Managed domain-route file, relative to CONFIG_DIR unless absolute (Item 66)
# DNS_ROUTES_FILE=dns-routes.json

# DNS server listen address and port for the embedded DNS server (replaces dnsmasq)
# DNS_LISTEN_ADDR defaults to TAILSCALE_IP (set by entrypoint.sh), then 0.0.0.0
# DNS_LISTEN_ADDR=0.0.0.0
# DNS_LISTEN_PORT=53

# Filter engine (blocklists with adblock/hosts/domain-list/regex syntax)
# Space- or comma-separated subscription URLs, auto-updated with ETag/Last-Modified
# BLOCKLIST_URLS=https://example.com/blocklist.txt
# ALLOWLIST_URLS=https://example.com/allowlist.txt
# Local exceptions-only list (@@ semantics for every entry)
# ALLOWLIST_FILE=/etc/resolix/allowlist.txt
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
# AAAA_DISABLED=false (set true so AAAA queries get NOERROR-empty answers)
# REFUSE_ANY=true (default; QTYPE ANY is refused)

# Upstream pool (Step 4): schemes udp:// tcp:// tls:// https:// (DoT/DoH)
# UPSTREAM_MODE=load_balance (default) | parallel | strict
# FALLBACK_DNS=9.9.9.9 (used only when all primary upstreams fail)
# BOOTSTRAP_DNS="9.9.9.9 1.1.1.1" (initial plain UDP IP resolvers for hostname DoT/DoH; /config overrides)
# ECS_CLIENT_SUBNET=192.0.2.0/24 (EDNS0 client subnet sent to upstreams)
# DNS64=false (set true to synthesize AAAA from A on empty AAAA answers)
# DNS64_PREFIXES=64:ff9b::/96
# CACHE_OPTIMISTIC=false (set true to serve stale entries while refreshing in background)
# CACHE_MIN_TTL=60
# CACHE_MAX_TTL=600
# CACHE_PREFETCH=false
# CACHE_PREFETCH_WINDOW=30s
# CACHE_PREFETCH_HITS=3
# CACHE_SERVFAIL_TTL=0s (optional; maximum 1s)
# DNS_TCP_IDLE_TIMEOUT=8s
# DNS_TCP_MAX_QUERIES=128
# DNS_TCP_MAX_CONNECTIONS=256

# Per-client policies (Step 5)
# CLIENTS_FILE=clients.json (per-client registry: filtering, safe search,
#   custom upstreams, and log/stat exclusions; hot-reloaded every 30s)

# DNS access and encrypted serving (Step 6)
# Comma/space-separated IPs or CIDRs. Deny-list matches, allow-list misses,
# and rate-limit excess are dropped silently without a DNS response.
# DNS_ALLOWED_CLIENTS=127.0.0.0/8,10.0.0.0/8,100.64.0.0/10,172.16.0.0/12,192.168.0.0/16
# DNS_DISALLOWED_CLIENTS=100.64.0.5
# RATE_LIMIT_QPS=80 (public clients, per IP; 0 disables)
# RATE_LIMIT_INTERNAL_QPS=1000 (LAN/Tailscale clients, per IP; 0 disables)
# RATE_LIMIT_EDE=false (opt-in REFUSED+EDE; default silently drops excess queries)
# PRIVATE_PTR=true (answer known RFC1918/CGNAT/ULA client PTRs as <name>.lan)
# DNSSEC=false (pass the DNSSEC DO bit upstream; no local validation)
# DOH_ENABLED=false
# DOH_PATH=/dns-query
# DOH_AUTH_TOKEN=change-me (Bearer token; when unset, only private/tailnet clients)
# DOT_ENABLED=false
# DOT_PORT=853
# TLS_CERT_FILE=/etc/resolix/tls.crt
# TLS_KEY_FILE=/etc/resolix/tls.key

# Upstream latency alert threshold in milliseconds (Item 68, default: 200)
# UPSTREAM_LATENCY_THRESHOLD=200

# Configurable timeout values (Item 80)
# SSE_KEEPALIVE_INTERVAL=30s
# Maximum periodic interval; busy queues also archive at the trigger size.
# BATCH_ARCHIVE_INTERVAL=30m
# ARCHIVE_QUEUE_CAPACITY=1000000
# ARCHIVE_TRIGGER_SIZE=20000
# ARCHIVE_WRITE_BATCH_SIZE=20000
# CLEANUP_INTERVAL=1h
# FORWARDER_RETRY_INTERVAL=5s
# HTTP_READ_TIMEOUT=10s
# HTTP_WRITE_TIMEOUT=30s
# HTTP_SHUTDOWN_TIMEOUT=10s
# MAX_REQUEST_SIZE=1048576

# Optional log file for file-based logging (default: empty = stderr only)
# LOG_FILE=/var/log/resolix.log
# DEBUG=false

# ===== Distributed Architecture (Items 85-94) =====
# Maximum retry attempts for forwarding with exponential backoff (default: 6)
# MAX_RETRY_ATTEMPTS=6

# Interval for agent heartbeats to controller (default: 30s)
# HEARTBEAT_INTERVAL=30s

# Interval for syncing client aliases from controller (default: 5m)
# SYNC_ALIASES_INTERVAL=5m

# Interval for syncing DNS routes from controller (default: 5m)
# SYNC_DNSROUTES_INTERVAL=5m

# Interval for syncing upstream health from controller (default: 1m)
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
	// → typed rewrites → private PTR → safe-search → filter
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

// setupFilterEngine builds and starts the filter engine from configuration
// and wires it into the API server.
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

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
	"syscall"
	"time"

	"tailscale-dnsrewrite/webgui/internal/api"
	"tailscale-dnsrewrite/webgui/internal/blocklist"
	"tailscale-dnsrewrite/webgui/internal/config"
	"tailscale-dnsrewrite/webgui/internal/dnsroutes"
	"tailscale-dnsrewrite/webgui/internal/dnsserver"
	"tailscale-dnsrewrite/webgui/internal/forwarder"
	"tailscale-dnsrewrite/webgui/internal/health"
	"tailscale-dnsrewrite/webgui/internal/logger"
	"tailscale-dnsrewrite/webgui/internal/models"
	"tailscale-dnsrewrite/webgui/internal/parser"
	"tailscale-dnsrewrite/webgui/internal/resolver"
	"tailscale-dnsrewrite/webgui/internal/storage"
)

// Version represents the current application version.
var Version = "2.0.0" // Changed from const to var for -ldflags build-time setting (Item 88)

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

# Space-separated upstream DNS servers
UPSTREAM_DNS=8.8.8.8 8.8.4.4

# Comma-separated domain:ip mappings
DOMAINS=.internal.net:100.1.2.3,app.example.com:100.4.5.6

# Domain used for upstream health checks
HEALTHCHECK_DOMAIN=google.com

# Web GUI listening port
PORT=35353

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

# Web GUI authentication (leave empty to disable auth)
# WEB_USERNAME=admin
# WEB_PASSWORD=

# Log level: DEBUG, INFO, WARNING, ERROR (default: INFO)
LOG_LEVEL=INFO

# Base URL for hosting behind a reverse proxy subpath (default: /)
# Example: BASE_URL=/dashboard
BASE_URL=/

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

# Deprecated: dnsmasq was replaced by the in-process DNS server (Item 63)
# DNSMASQ_PID_FILE=/run/dnsmasq.pid

# Upstream latency alert threshold in milliseconds (Item 68, default: 200)
# UPSTREAM_LATENCY_THRESHOLD=200

# Configurable timeout values (Item 80)
# SSE_KEEPALIVE_INTERVAL=30s
# BATCH_ARCHIVE_INTERVAL=30m
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

	tmpl, err := template.ParseFS(embedFS, "templates/*.html")
	if err != nil {
		logger.Fatal("Fatal error parsing templates: %v", err)
	}

	prs := parser.NewParser(store, cfg.Debug)
	srv := api.NewServer(cfg, store, prs, tmpl)

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
	staticFS, err := fs.Sub(embedFS, "static")
	if err != nil {
		logger.Fatal("Fatal error creating static FS: %v", err)
	}
	staticHandler := http.FileServer(http.FS(staticFS))

	// Initialize health checker
	checker := health.NewChecker(cfg, cfg.UpstreamDNS)
	go checker.Start(ctx, func(_ []string, latencies map[string]float64) {
		store.SetUpstreamHealth(cfg.NodeName, latencies)
		if cfg.Mode == "slave" {
			fwd.ReportHealth(latencies)
		}
		logger.Debug("Health status updated for node %s. Latencies: %v", cfg.NodeName, latencies)
	})

	// Start Trend Analysis
	store.StartStatsTrends(ctx)

	// History Archiver (uses configurable BatchArchiveInterval)
	go func() {
		ticker := time.NewTicker(cfg.ArchiveInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				store.ArchiveStep(time.Now())
			}
		}
	}()

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

	// Embedded DNS server (replaces dnsmasq). Pipeline: static rewrites →
	// cache → strict-order upstream forward → cache store → respond. Each
	// answered query becomes a QueryEvent fed into Store + SSE (and the
	// forwarder in slave mode). dnsDone closes when both listeners have
	// stopped, so shutdown can archive after events have ceased.
	dnsSrv := dnsserver.New(dnsserver.Config{
		Addr:        cfg.DNSListenAddr,
		Port:        cfg.DNSListenPort,
		Upstreams:   strings.Fields(cfg.UpstreamDNS),
		StaticHosts: dnsserver.ParseStaticHosts(cfg.Domains),
		NodeName:    cfg.NodeName,
	}, func(ev models.QueryEvent) {
		store.AddEvent(ev)
		srv.BroadcastEvent(ev)
		if cfg.Mode == "slave" {
			fwd.EnqueueEvent(ev)
		}
	})
	dnsDone := make(chan struct{})
	go func() {
		defer close(dnsDone)
		logger.Info("DNS server listening on %s (UDP+TCP)", dnsSrv.ListenAddr())
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
	<-dnsDone
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

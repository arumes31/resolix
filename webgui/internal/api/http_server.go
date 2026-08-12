package api

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"runtime"
	"strings"
	"time"

	"github.com/arumes31/resolix/webgui/internal/controllertls"
)

// SetStaticHandler configures the static file server, CSP middleware, and nonce function.
func (s *Server) SetStaticHandler(static http.Handler, cspMW func(http.Handler) http.Handler, nonceFn func(context.Context) string) {
	s.staticHandler = static
	s.cspMiddleware = cspMW
	s.nonceFromCtx = nonceFn
}

func (s *Server) maxBytesMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxRequestSize)
		}
		next.ServeHTTP(w, r)
	})
}

// SetupMux configures the API routes and middleware.
func (s *Server) SetupMux() http.Handler {
	mux := http.NewServeMux()

	// Public routes (no auth required)
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/readyz", s.handleReadyz)
	mux.HandleFunc("/login", s.handleLogin)
	mux.HandleFunc("/logout", s.handleLogout)

	// DoH endpoint (RFC 8484): functional without session auth — protected
	// by DOH_AUTH_TOKEN when set, otherwise restricted to private client IPs.
	if s.cfg.DoHEnabled {
		mux.HandleFunc(s.cfg.DoHPath, s.handleDoH)
	}

	// Metrics can leak internal state; require authentication.
	mux.Handle("/metrics", s.authMiddleware(http.HandlerFunc(s.handleMetrics)))

	// Protected routes
	mux.Handle("/", s.authMiddleware(http.HandlerFunc(s.handleRoot)))
	mux.Handle("/querylog", s.authMiddleware(http.HandlerFunc(s.handleQueryLogPage)))
	mux.Handle("/cluster", s.authMiddleware(http.HandlerFunc(s.handleClusterPage)))
	mux.Handle("/config", s.authMiddleware(http.HandlerFunc(s.handleConfigPage)))
	mux.Handle("/api/events", s.authMiddleware(http.HandlerFunc(s.handleEvents)))
	mux.Handle("/api/history", s.authMiddleware(http.HandlerFunc(s.handleHistory)))
	mux.Handle("/api/stats", s.authMiddleware(http.HandlerFunc(s.handleStats)))
	mux.Handle("/api/dashboard/v1/stats", s.authMiddleware(http.HandlerFunc(s.handleDashboardV1Stats)))
	mux.Handle("/api/storage/status", s.authMiddleware(http.HandlerFunc(s.handleStorageStatus)))
	mux.Handle("/api/client_stats", s.authMiddleware(http.HandlerFunc(s.handleClientStats)))
	mux.Handle("/api/simulate", s.authMiddleware(http.HandlerFunc(s.handleSimulate)))

	// Item 61: Blocklist status endpoint
	mux.Handle("/api/blocklist/status", s.authMiddleware(http.HandlerFunc(s.handleBlocklistStatus)))

	// Filter engine: pause/resume protection and status
	mux.Handle("/api/filtering/pause", s.authMiddleware(http.HandlerFunc(s.handleFilteringPause)))
	mux.Handle("/api/filtering/status", s.authMiddleware(http.HandlerFunc(s.handleFilteringStatus)))
	mux.Handle("/api/filtering/update", s.authMiddleware(http.HandlerFunc(s.handleFilteringUpdate)))
	mux.Handle("/api/filtering/test", s.authMiddleware(http.HandlerFunc(s.handleFilteringTest)))
	mux.Handle("/api/filtering/validate", s.authMiddleware(http.HandlerFunc(s.handleFilteringValidate)))
	mux.Handle("/api/filtering/rollback", s.authMiddleware(http.HandlerFunc(s.handleFilteringRollback)))
	mux.Handle("/api/config/status", s.authMiddleware(http.HandlerFunc(s.handleConfigStatus)))
	mux.Handle("/api/config/dns-settings", s.authMiddleware(http.HandlerFunc(s.handleDNSSettings)))
	mux.Handle("/api/config/snapshot", s.authMiddleware(http.HandlerFunc(s.handleConfigSnapshot)))
	mux.Handle("/api/config/diff", s.authMiddleware(http.HandlerFunc(s.handleConfigDiff)))
	mux.Handle("/api/config/sync-now", s.authMiddleware(http.HandlerFunc(s.handleConfigSyncNow)))
	mux.Handle("/api/config/subscriptions", s.authMiddleware(http.HandlerFunc(s.handleFilterSubscriptions)))
	mux.Handle("/api/config/subscriptions/export", s.authMiddleware(http.HandlerFunc(s.handleFilterSubscriptionsExport)))
	mux.Handle("/api/config/subscriptions/import", s.authMiddleware(http.HandlerFunc(s.handleFilterSubscriptionsImport)))
	mux.Handle("/api/config/subscriptions/bulk", s.authMiddleware(http.HandlerFunc(s.handleFilterSubscriptionsBulk)))
	mux.Handle("/api/config/user-rules", s.authMiddleware(http.HandlerFunc(s.handleUserRules)))

	// Typed DNS rewrites CRUD
	mux.Handle("/api/rewrites", s.authMiddleware(http.HandlerFunc(s.handleRewrites)))

	// Per-client registry CRUD (Step 5)
	mux.Handle("/api/clients", s.authMiddleware(http.HandlerFunc(s.handleClients)))

	// Query-log actions: block/unblock a domain via filter user rules
	mux.Handle("/api/querylog/block", s.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.handleQuerylogAction(w, r, true)
	})))
	mux.Handle("/api/querylog/unblock", s.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.handleQuerylogAction(w, r, false)
	})))

	// Item 62: Upstream configuration editor
	mux.Handle("/api/upstreams", s.authMiddleware(http.HandlerFunc(s.handleUpstreams)))
	mux.Handle("/api/upstream-settings", s.authMiddleware(http.HandlerFunc(s.handleUpstreamSettings)))
	mux.Handle("/api/upstreams/test", s.authMiddleware(http.HandlerFunc(s.handleUpstreamTest)))

	// Item 63: Cache clear endpoint
	mux.Handle("/api/cache/clear", s.authMiddleware(http.HandlerFunc(s.handleCacheClear)))
	mux.Handle("/api/cache/status", s.authMiddleware(http.HandlerFunc(s.handleCacheStatus)))

	// Item 65: DNS loop detection endpoint
	mux.Handle("/api/dns/loop-status", s.authMiddleware(http.HandlerFunc(s.handleDNSLoopStatus)))

	// Item 66: Domain-specific routing rules
	mux.Handle("/api/dns/routes", s.authMiddleware(http.HandlerFunc(s.handleDNSRoutes)))
	mux.Handle("/api/dns/routes/test", s.authMiddleware(http.HandlerFunc(s.handleDNSRouteTest)))

	// Item 68: Upstream latency alerts
	mux.Handle("/api/upstreams/latency", s.authMiddleware(http.HandlerFunc(s.handleUpstreamLatency)))

	// Internal/System routes use their bearer secret when configured and fall
	// back to normal web authentication otherwise.
	mux.Handle("/api/ingest", s.internalAuth(http.HandlerFunc(s.handleIngest)))

	// Item 92: Heartbeat endpoint for agent nodes
	mux.Handle("/api/heartbeat", s.internalAuth(http.HandlerFunc(s.handleHeartbeat)))

	// Items 90, 91, 94: Sync endpoints for agent configuration
	mux.Handle("/api/sync/aliases", s.internalAuth(http.HandlerFunc(s.handleSyncAliases)))
	mux.Handle("/api/sync/dns-routes", s.internalAuth(http.HandlerFunc(s.handleSyncDNSRoutes)))
	mux.Handle("/api/sync/upstream-health", s.internalAuth(http.HandlerFunc(s.handleSyncUpstreamHealth)))
	mux.Handle("/api/sync/dns-config", s.internalAuth(http.HandlerFunc(s.handleSyncDNSConfig)))

	// Item 89: Node discovery and status endpoint
	mux.Handle("/api/nodes", s.authMiddleware(http.HandlerFunc(s.handleNodes)))
	mux.Handle("/api/version", s.authMiddleware(http.HandlerFunc(s.handleVersion)))

	handler := s.requestMetricsMiddleware(s.gzipMiddleware(mux))

	rootMux := http.NewServeMux()
	var staticAssets http.Handler
	if s.staticHandler != nil {
		staticAssets = staticCacheMiddleware(s.gzipMiddleware(s.staticHandler))
	}

	if s.cfg.BaseURL != "/" {
		// Subpath mode: all routes are under the base URL prefix
		base := s.cfg.BaseURL

		// Static file server at <base>/static/ (public, compressed, and cacheable).
		if staticAssets != nil {
			staticPrefix := base + "/static/"
			rootMux.Handle(staticPrefix, http.StripPrefix(staticPrefix, staticAssets))
		}

		// Strip the base URL prefix before passing to the app handler
		appHandler := http.StripPrefix(base, handler)
		rootMux.Handle(base+"/", s.maxBytesMiddleware(appHandler))
		rootMux.Handle(base+"/api/stream", s.authMiddleware(http.HandlerFunc(s.handleStream)))
		// Keep infrastructure probes stable when the dashboard is mounted at
		// a reverse-proxy subpath.
		rootMux.HandleFunc("/healthz", s.handleHealthz)
		rootMux.HandleFunc("/readyz", s.handleReadyz)

		// Redirect bare root to the base URL
		rootMux.Handle("/", http.RedirectHandler(base+"/", http.StatusMovedPermanently))
	} else {
		// Default mode: no subpath prefix
		if staticAssets != nil {
			rootMux.Handle("/static/", http.StripPrefix("/static/", staticAssets))
		}
		rootMux.Handle("/", s.maxBytesMiddleware(handler))
		rootMux.Handle("/api/stream", s.authMiddleware(http.HandlerFunc(s.handleStream)))
	}

	return rootMux
}

// handleHealthz returns a simple health check response for container liveness probes.
// This endpoint does NOT require authentication and performs no database queries.
func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(w, `{"status":"ok"}`)
}

func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	dnsReady := false
	if dnsSrv := s.getDNSServer(); dnsSrv != nil {
		dnsReady = dnsSrv.Ready()
	}

	dbReady := s.store.DB() != nil
	if dbReady {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second)
		defer cancel()
		dbReady = s.store.DB().PingContext(ctx) == nil
	}
	if !s.webReady.Load() || !dnsReady || !dbReady {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "not_ready", "dns": dnsReady, "database": dbReady})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ready"})
}

func (s *Server) handleVersion(w http.ResponseWriter, _ *http.Request) {
	version, buildInfo := s.buildMetadata()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"version":    version,
		"go_version": runtime.Version(),
		"build":      buildInfo,
	})
}

// ===== DNS-over-HTTPS (RFC 8484) =====

// dohPrivateNets are the client ranges allowed to use DoH when no
// DOH_AUTH_TOKEN is configured: loopback, RFC1918, Tailscale CGNAT, ULA.

func (s *Server) gzipMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Vary", "Accept-Encoding")
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Content-Encoding", "gzip")
		gz := gzip.NewWriter(w)
		defer func() { _ = gz.Close() }()
		next.ServeHTTP(gzipResponseWriter{Writer: gz, ResponseWriter: w}, r)
	})
}

func staticCacheMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", staticAssetCaching)
		next.ServeHTTP(w, r)
	})
}

type gzipResponseWriter struct {
	io.Writer
	http.ResponseWriter
}

func (w gzipResponseWriter) Write(b []byte) (int, error) {
	w.Header().Del("Content-Length")
	return w.Writer.Write(b)
}

func (w gzipResponseWriter) WriteHeader(statusCode int) {
	w.Header().Del("Content-Length")
	w.ResponseWriter.WriteHeader(statusCode)
}

// Start launches the HTTP server and listens for requests.
func (s *Server) Start(ctx context.Context, staticHandler http.Handler, cspMiddleware func(http.Handler) http.Handler, nonceFromCtx func(context.Context) string) error {
	// Configure static handler, CSP middleware, and nonce function
	s.SetStaticHandler(staticHandler, cspMiddleware, nonceFromCtx)

	// Build the handler chain: CSP middleware wraps the entire mux
	handler := s.cspMiddleware(s.SetupMux())

	server := &http.Server{
		Addr:              net.JoinHostPort(s.cfg.WebListenAddr, s.cfg.Port),
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       s.cfg.HTTPReadTimeout,
		WriteTimeout:      s.cfg.HTTPWriteTimeout,
		IdleTimeout:       120 * time.Second,
	}
	var tlsManager *controllertls.Manager
	if s.cfg.WebTLSMode == controllertls.WebTLSAuto {
		manager, err := controllertls.NewManager(s.cfg.FullTLSStateDir(), s.cfg.WebTLSIP)
		if err != nil {
			return fmt.Errorf("configure generated web TLS: %w", err)
		}
		tlsManager = manager
		server.TLSConfig = manager.TLSConfig()
	}

	ln, err := net.Listen("tcp", server.Addr)
	if err != nil {
		return err
	}
	s.webReady.Store(true)
	defer s.webReady.Store(false)

	shutdownDone := make(chan struct{})
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.cfg.HTTPShutdownTimeout)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			log.Printf("HTTP server shutdown error: %v", err)
		}
		close(shutdownDone)
	}()

	if tlsManager != nil {
		go tlsManager.Run(ctx, func(rotationErr error) {
			log.Printf("Controller TLS certificate rotation failed: %v", rotationErr)
		})
		log.Printf("Starting Advanced Web GUI with generated HTTPS on %s (CA %s)", server.Addr, tlsManager.CAFingerprint())
		err = server.ServeTLS(ln, "", "")
	} else {
		log.Printf("Starting Advanced Web GUI on %s", server.Addr)
		err = server.Serve(ln)
	}
	if ctx.Err() != nil {
		<-shutdownDone
	}
	return err
}

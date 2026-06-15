// Package api implements the HTTP API and web GUI server for the
// tailscale-dnsrewrite application. It handles authentication, SSE
// broadcasting, Prometheus metrics, request size limiting, and all
// API endpoints.
package api

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/bcrypt"

	"tailscale-dnsrewrite/webgui/internal/blocklist"
	"tailscale-dnsrewrite/webgui/internal/config"
	"tailscale-dnsrewrite/webgui/internal/dnsroutes"
	apperr "tailscale-dnsrewrite/webgui/internal/errors"
	"tailscale-dnsrewrite/webgui/internal/models"
	"tailscale-dnsrewrite/webgui/internal/parser"
	"tailscale-dnsrewrite/webgui/internal/resolver"
	"tailscale-dnsrewrite/webgui/internal/storage"
)

const (
	sessionCookieName = "ts_dns_session"
	csrfCookieName    = "ts_dns_csrf"
	csrfTokenBytes    = 32
)

// isHTTPS determines whether the request was made over HTTPS,
// either directly (TLS) or via a reverse proxy (X-Forwarded-Proto).
func isHTTPS(r *http.Request) bool {
	return r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
}

// rateLimitEntry tracks failed login attempts for a single IP.
type rateLimitEntry struct {
	count    int
	lastSeen time.Time
}

// Metrics holds Prometheus-format counters and gauges for the application.
// All fields use atomic operations for thread-safe access.
type Metrics struct {
	QueriesTotal      atomic.Int64
	QueriesBlocked    atomic.Int64
	CacheHits         atomic.Int64
	CacheMisses       atomic.Int64
	StartTime         time.Time
	queriesByType     sync.Map // map[string]*atomic.Int64
	upstreamLatencies sync.Map // map[string]*latencyBucket
}

// latencyBucket tracks upstream latency samples for histogram emulation.
type latencyBucket struct {
	mu      sync.Mutex
	count   int64
	sum     float64
	buckets [5]int64 // <10ms, <50ms, <100ms, <500ms, >=500ms
}

// addSample records a latency measurement in milliseconds.
func (lb *latencyBucket) addSample(ms float64) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	lb.count++
	lb.sum += ms
	switch {
	case ms < 10:
		lb.buckets[0]++
	case ms < 50:
		lb.buckets[1]++
	case ms < 100:
		lb.buckets[2]++
	case ms < 500:
		lb.buckets[3]++
	default:
		lb.buckets[4]++
	}
}

// IncQueriesByType increments the counter for a specific DNS query type.
func (m *Metrics) IncQueriesByType(qtype string) {
	if v, ok := m.queriesByType.Load(qtype); ok {
		v.(*atomic.Int64).Add(1)
		return
	}
	newV := &atomic.Int64{}
	newV.Add(1)
	if actual, loaded := m.queriesByType.LoadOrStore(qtype, newV); loaded {
		actual.(*atomic.Int64).Add(1)
	}
}

// RecordUpstreamLatency records a latency measurement for an upstream server.
func (m *Metrics) RecordUpstreamLatency(upstream string, latencyMs float64) {
	if v, ok := m.upstreamLatencies.Load(upstream); ok {
		v.(*latencyBucket).addSample(latencyMs)
		return
	}
	newV := &latencyBucket{}
	newV.addSample(latencyMs)
	if actual, loaded := m.upstreamLatencies.LoadOrStore(upstream, newV); loaded {
		actual.(*latencyBucket).addSample(latencyMs)
	}
}

// Server handles HTTP API and Web GUI requests.
type Server struct {
	cfg    *config.Config
	store  *storage.Store
	parser *parser.Parser
	tmpl   *template.Template

	// SSE Broadcaster
	subscribers map[chan models.QueryEvent]int
	subMu       sync.RWMutex
	subDropCnt  atomic.Int64

	// Static file handler and nonce function (set via SetStaticHandler)
	staticHandler http.Handler
	cspMiddleware func(http.Handler) http.Handler
	nonceFromCtx  func(context.Context) string

	// Rate limiter for login attempts (per-IP)
	rateLimits map[string]*rateLimitEntry
	rateMu     sync.Mutex

	// Hashed password (bcrypt) — populated at startup
	hashedPassword string

	// Reverse DNS resolver (Item 59)
	resolver *resolver.Resolver

	// Blocklist (Item 61)
	blocklist *blocklist.Blocklist

	// DNS routes (Item 66)
	dnsRoutes *dnsroutes.DNSRoutes

	// Mutex protecting resolver, blocklist, and dnsRoutes fields
	fieldsMu sync.RWMutex

	// DNS loop detection (Item 65)
	dnsLoopDetected bool
	dnsLoopMu       sync.Mutex
	dnsLoopDetails  string

	// Prometheus metrics (Item 77)
	metrics *Metrics
}

// NewServer initializes a new API server.
func NewServer(cfg *config.Config, store *storage.Store, prs *parser.Parser, tmpl *template.Template) *Server {
	s := &Server{
		cfg:         cfg,
		store:       store,
		parser:      prs,
		tmpl:        tmpl,
		subscribers: make(map[chan models.QueryEvent]int),
		rateLimits:  make(map[string]*rateLimitEntry),
		metrics:     &Metrics{StartTime: time.Now()},
	}

	// Hash the configured password at startup if auth is enabled
	if cfg.WebPassword != "" {
		if isBcryptHash(cfg.WebPassword) {
			s.hashedPassword = cfg.WebPassword
		} else {
			hash, err := bcrypt.GenerateFromPassword([]byte(cfg.WebPassword), bcrypt.DefaultCost)
			if err != nil {
				log.Fatalf("Failed to hash password: %v", err)
			}
			s.hashedPassword = string(hash)
			log.Println("Password auto-hashed with bcrypt at startup")
		}
	}

	// Start stale rate-limit entry cleanup goroutine
	go s.cleanupRateLimits()

	return s
}

// SetResolver configures the reverse DNS resolver for enriching events with hostnames.
func (s *Server) SetResolver(r *resolver.Resolver) {
	s.fieldsMu.Lock()
	defer s.fieldsMu.Unlock()
	s.resolver = r
}

// SetBlocklist configures the blocklist for checking blocked domains.
func (s *Server) SetBlocklist(bl *blocklist.Blocklist) {
	s.fieldsMu.Lock()
	defer s.fieldsMu.Unlock()
	s.blocklist = bl
}

// SetDNSRoutes configures the domain-specific DNS routing rules.
func (s *Server) SetDNSRoutes(dr *dnsroutes.DNSRoutes) {
	s.fieldsMu.Lock()
	defer s.fieldsMu.Unlock()
	s.dnsRoutes = dr
}

// isBcryptHash returns true if the string looks like a bcrypt hash.
func isBcryptHash(s string) bool {
	return strings.HasPrefix(s, "$2a$") ||
		strings.HasPrefix(s, "$2b$") ||
		strings.HasPrefix(s, "$2y$")
}

// checkPassword compares a supplied plaintext password against the stored bcrypt hash
// using constant-time comparison.
func checkPassword(hashedPassword, suppliedPassword string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(suppliedPassword))
	return err == nil
}

// generateCSRFToken creates a cryptographically random base64-encoded token.
func generateCSRFToken() string {
	b := make([]byte, csrfTokenBytes)
	if _, err := rand.Read(b); err != nil {
		log.Printf("Warning: crypto/rand failed for CSRF token: %v", err)
		return base64.StdEncoding.EncodeToString([]byte(time.Now().Format("20060102150405.000000000")))
	}
	return base64.StdEncoding.EncodeToString(b)
}

// clientIP extracts the client IP from the request, respecting X-Forwarded-For.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.SplitN(xff, ",", 2)
		return strings.TrimSpace(parts[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// getRateLimitBackoff returns the required backoff duration and whether the IP is rate-limited.
// Exponential backoff: 1 failure = 0s, 2 = 1s, 3 = 2s, 4 = 4s, 5+ = 8s (capped).
func getRateLimitBackoff(count int) time.Duration {
	if count <= 1 {
		return 0
	}
	seconds := math.Pow(2, float64(count-2))
	if seconds > 8 {
		seconds = 8
	}
	return time.Duration(seconds) * time.Second
}

// checkRateLimit checks if the given IP is rate-limited. Returns true if the request
// should be rejected (429). It also enforces exponential backoff by checking elapsed time.
func (s *Server) checkRateLimit(ip string) (bool, time.Duration) {
	s.rateMu.Lock()
	defer s.rateMu.Unlock()

	entry, exists := s.rateLimits[ip]
	if !exists || entry.count == 0 {
		return false, 0
	}

	// If the last attempt was more than 5 minutes ago, reset
	if time.Since(entry.lastSeen) > 5*time.Minute {
		delete(s.rateLimits, ip)
		return false, 0
	}

	backoff := getRateLimitBackoff(entry.count)
	elapsed := time.Since(entry.lastSeen)

	if elapsed < backoff {
		remaining := backoff - elapsed
		return true, remaining
	}

	return false, 0
}

// recordFailedLogin increments the failed login counter for the given IP.
func (s *Server) recordFailedLogin(ip string) {
	s.rateMu.Lock()
	defer s.rateMu.Unlock()

	entry, exists := s.rateLimits[ip]
	if !exists {
		entry = &rateLimitEntry{}
		s.rateLimits[ip] = entry
	}
	entry.count++
	entry.lastSeen = time.Now()
}

// resetRateLimit clears the rate limit counter for the given IP (on successful login).
func (s *Server) resetRateLimit(ip string) {
	s.rateMu.Lock()
	defer s.rateMu.Unlock()
	delete(s.rateLimits, ip)
}

// cleanupRateLimits periodically removes stale entries older than 10 minutes.
func (s *Server) cleanupRateLimits() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		s.rateMu.Lock()
		now := time.Now()
		for ip, entry := range s.rateLimits {
			if now.Sub(entry.lastSeen) > 10*time.Minute {
				delete(s.rateLimits, ip)
			}
		}
		s.rateMu.Unlock()
	}
}

// SetStaticHandler configures the static file server, CSP middleware, and nonce function.
func (s *Server) SetStaticHandler(static http.Handler, cspMW func(http.Handler) http.Handler, nonceFn func(context.Context) string) {
	s.staticHandler = static
	s.cspMiddleware = cspMW
	s.nonceFromCtx = nonceFn
}

// Subscribe registers a channel to receive broadcast events.
// Returns the channel that the caller should read from.
func (s *Server) Subscribe() chan models.QueryEvent {
	ch := make(chan models.QueryEvent, 100)
	s.subMu.Lock()
	s.subscribers[ch] = 0
	s.subMu.Unlock()
	return ch
}

// Unsubscribe removes a subscriber channel and closes it.
func (s *Server) Unsubscribe(ch chan models.QueryEvent) {
	s.subMu.Lock()
	delete(s.subscribers, ch)
	s.subMu.Unlock()
	// Non-blocking close to prevent panic on double-close
	select {
	case <-ch:
		// already closed or drained
	default:
		close(ch)
	}
}

// BroadcastEvent safely sends an event to all SSE subscribers.
// Slow subscribers are handled with non-blocking sends; if a subscriber's
// channel is full, the event is dropped and the drop counter is incremented.
// Subscribers that exceed 10 consecutive drops are removed.
func (s *Server) BroadcastEvent(e models.QueryEvent) {
	// Item 59: Enrich with reverse DNS hostname
	s.fieldsMu.RLock()
	resolver := s.resolver
	bl := s.blocklist
	s.fieldsMu.RUnlock()

	if resolver != nil && e.ClientIP != "" {
		if hostname := resolver.GetHostname(e.ClientIP); hostname != "" {
			e.ClientHostname = hostname
		}
	}

	// Item 61: Check blocklist
	if bl != nil && e.Domain != "" {
		if bl.IsBlocked(e.Domain) {
			e.Blocked = true
		}
	}

	// Update Prometheus metrics
	s.metrics.QueriesTotal.Add(1)
	s.metrics.IncQueriesByType(e.Type)
	if e.Blocked {
		s.metrics.QueriesBlocked.Add(1)
	}
	if e.Upstream == "System Cache" {
		s.metrics.CacheHits.Add(1)
	} else if e.Upstream != "" {
		s.metrics.CacheMisses.Add(1)
	}
	if e.Latency.Valid && e.Upstream != "" && e.Upstream != "System Cache" && e.Upstream != "Local Override" {
		s.metrics.RecordUpstreamLatency(e.Upstream, e.Latency.Float64)
	}

	s.subMu.RLock()
	defer s.subMu.RUnlock()
	for ch, drops := range s.subscribers {
		select {
		case ch <- e:
			if drops > 0 {
				s.subMu.RUnlock()
				s.subMu.Lock()
				s.subscribers[ch] = 0
				s.subMu.Unlock()
				s.subMu.RLock()
			}
		default:
			s.subDropCnt.Add(1)
			s.subMu.RUnlock()
			s.subMu.Lock()
			s.subscribers[ch] = drops + 1
			if s.subscribers[ch] > 10 {
				log.Printf("Dropping slow subscriber")
				delete(s.subscribers, ch)
				close(ch)
			}
			s.subMu.Unlock()
			s.subMu.RLock()
		}
	}
}

// Broadcast is a convenience method that calls BroadcastEvent.
// It enriches the event with hostname and blocklist data before broadcasting.
func (s *Server) Broadcast(e models.QueryEvent) {
	s.BroadcastEvent(e)
}

// StartDNSLoopDetection begins periodic DNS loop detection checks.
func (s *Server) StartDNSLoopDetection(ctx context.Context) {
	// Check immediately on startup
	s.checkDNSLoop()

	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.checkDNSLoop()
			}
		}
	}()
}

// checkDNSLoop checks if the server's own IP is configured as an upstream.
func (s *Server) checkDNSLoop() {
	localAddrs, err := net.InterfaceAddrs()
	if err != nil {
		log.Printf("[WARN] Failed to get local interface addresses: %v", err)
		return
	}

	localIPs := make(map[string]bool)
	for _, addr := range localAddrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipNet.IP
		if !ip.IsLoopback() && !ip.IsUnspecified() {
			localIPs[ip.String()] = true
		}
	}

	// Get upstream IPs from the UPSTREAM_DNS config
	upstreamIPs := make(map[string]bool)
	if s.cfg.UpstreamDNS != "" {
		for _, u := range strings.Fields(s.cfg.UpstreamDNS) {
			// Strip port if present
			host := u
			if h, _, err := net.SplitHostPort(u); err == nil {
				host = h
			}
			upstreamIPs[host] = true
		}
	}

	// Also check upstreams file
	s.fieldsMu.RLock()
	dnsRoutes := s.dnsRoutes
	s.fieldsMu.RUnlock()
	if dnsRoutes != nil {
		// Check routes for loop patterns
		routes := dnsRoutes.GetRoutesMap()
		for _, upstream := range routes {
			host := upstream
			if h, _, err := net.SplitHostPort(upstream); err == nil {
				host = h
			}
			upstreamIPs[host] = true
		}
	}

	// Check for overlap
	var loopIPs []string
	for localIP := range localIPs {
		if upstreamIPs[localIP] {
			loopIPs = append(loopIPs, localIP)
		}
	}

	s.dnsLoopMu.Lock()
	defer s.dnsLoopMu.Unlock()
	if len(loopIPs) > 0 {
		s.dnsLoopDetected = true
		s.dnsLoopDetails = fmt.Sprintf("Local IP(s) %s found in upstream configuration", strings.Join(loopIPs, ", "))
		log.Printf("[WARN] DNS loop detected: %s", s.dnsLoopDetails)
	} else {
		s.dnsLoopDetected = false
		s.dnsLoopDetails = ""
	}
}

// maxBytesMiddleware limits the size of request bodies for POST endpoints.
// It uses http.MaxBytesReader to enforce the configured maximum body size.
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
	mux.HandleFunc("/login", s.handleLogin)
	mux.HandleFunc("/logout", s.handleLogout)
	mux.HandleFunc("/metrics", s.handleMetrics)

	// Protected routes
	mux.Handle("/", s.authMiddleware(http.HandlerFunc(s.handleRoot)))
	mux.Handle("/api/events", s.authMiddleware(http.HandlerFunc(s.handleEvents)))
	mux.Handle("/api/stats", s.authMiddleware(http.HandlerFunc(s.handleStats)))
	mux.Handle("/api/client_stats", s.authMiddleware(http.HandlerFunc(s.handleClientStats)))
	mux.Handle("/api/simulate", s.authMiddleware(http.HandlerFunc(s.handleSimulate)))

	// Item 61: Blocklist status endpoint
	mux.Handle("/api/blocklist/status", s.authMiddleware(http.HandlerFunc(s.handleBlocklistStatus)))

	// Item 62: Upstream configuration editor
	mux.Handle("/api/upstreams", s.authMiddleware(http.HandlerFunc(s.handleUpstreams)))

	// Item 63: Cache clear endpoint
	mux.Handle("/api/cache/clear", s.authMiddleware(http.HandlerFunc(s.handleCacheClear)))

	// Item 65: DNS loop detection endpoint
	mux.Handle("/api/dns/loop-status", s.authMiddleware(http.HandlerFunc(s.handleDNSLoopStatus)))

	// Item 66: Domain-specific routing rules
	mux.Handle("/api/dns/routes", s.authMiddleware(http.HandlerFunc(s.handleDNSRoutes)))

	// Item 68: Upstream latency alerts
	mux.Handle("/api/upstreams/latency", s.authMiddleware(http.HandlerFunc(s.handleUpstreamLatency)))

	// Internal/System routes (protected by IngestSecret if set, or authMiddleware)
	mux.HandleFunc("/api/ingest", s.handleIngest)

	// Item 92: Heartbeat endpoint for slave nodes
	mux.HandleFunc("/api/heartbeat", s.handleHeartbeat)

	// Items 90, 91, 94: Sync endpoints for slave configuration
	mux.HandleFunc("/api/sync/aliases", s.handleSyncAliases)
	mux.HandleFunc("/api/sync/dns-routes", s.handleSyncDNSRoutes)
	mux.HandleFunc("/api/sync/upstream-health", s.handleSyncUpstreamHealth)

	// Item 89: Node discovery and status endpoint
	mux.Handle("/api/nodes", s.authMiddleware(http.HandlerFunc(s.handleNodes)))

	handler := s.gzipMiddleware(mux)

	rootMux := http.NewServeMux()

	if s.cfg.BaseURL != "/" {
		// Subpath mode: all routes are under the base URL prefix
		base := s.cfg.BaseURL

		// Static file server at <base>/static/ (no auth, no gzip for static assets)
		if s.staticHandler != nil {
			staticPrefix := base + "/static/"
			rootMux.Handle(staticPrefix, http.StripPrefix(staticPrefix, s.staticHandler))
		}

		// Strip the base URL prefix before passing to the app handler
		appHandler := http.StripPrefix(base, handler)
		rootMux.Handle(base+"/", s.maxBytesMiddleware(appHandler))
		rootMux.Handle(base+"/api/stream", s.authMiddleware(http.HandlerFunc(s.handleStream)))

		// Redirect bare root to the base URL
		rootMux.Handle("/", http.RedirectHandler(base+"/", http.StatusMovedPermanently))
	} else {
		// Default mode: no subpath prefix
		if s.staticHandler != nil {
			rootMux.Handle("/static/", http.StripPrefix("/static/", s.staticHandler))
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

// handleMetrics exposes Prometheus-format metrics on the /metrics endpoint.
// No authentication is required (standard Prometheus practice).
func (s *Server) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	var buf bytes.Buffer
	m := s.metrics

	// dns_queries_total
	fmt.Fprintf(&buf, "# HELP dns_queries_total Total DNS queries processed\n")
	fmt.Fprintf(&buf, "# TYPE dns_queries_total counter\n")
	fmt.Fprintf(&buf, "dns_queries_total %d\n", m.QueriesTotal.Load())

	// dns_queries_blocked_total
	fmt.Fprintf(&buf, "# HELP dns_queries_blocked_total Total blocked queries\n")
	fmt.Fprintf(&buf, "# TYPE dns_queries_blocked_total counter\n")
	fmt.Fprintf(&buf, "dns_queries_blocked_total %d\n", m.QueriesBlocked.Load())

	// dns_queries_by_type
	fmt.Fprintf(&buf, "# HELP dns_queries_by_type Queries by DNS record type\n")
	fmt.Fprintf(&buf, "# TYPE dns_queries_by_type counter\n")
	m.queriesByType.Range(func(key, value interface{}) bool {
		fmt.Fprintf(&buf, "dns_queries_by_type{type=\"%s\"} %d\n", key, value.(*atomic.Int64).Load())
		return true
	})

	// dns_upstream_latency_seconds
	fmt.Fprintf(&buf, "# HELP dns_upstream_latency_seconds Upstream latency in seconds\n")
	fmt.Fprintf(&buf, "# TYPE dns_upstream_latency_seconds summary\n")
	m.upstreamLatencies.Range(func(key, value interface{}) bool {
		lb := value.(*latencyBucket)
		lb.mu.Lock()
		defer lb.mu.Unlock()
		if lb.count > 0 {
			avg := lb.sum / float64(lb.count) / 1000.0 // ms to seconds
			fmt.Fprintf(&buf, "dns_upstream_latency_seconds{upstream=\"%s\",quantile=\"avg\"} %f\n", key, avg)
			fmt.Fprintf(&buf, "dns_upstream_latency_seconds_count{upstream=\"%s\"} %d\n", key, lb.count)
			fmt.Fprintf(&buf, "dns_upstream_latency_seconds_sum{upstream=\"%s\"} %f\n", key, lb.sum/1000.0)
		}
		return true
	})

	// dns_cache_hits_total
	fmt.Fprintf(&buf, "# HELP dns_cache_hits_total Cache hit count\n")
	fmt.Fprintf(&buf, "# TYPE dns_cache_hits_total counter\n")
	fmt.Fprintf(&buf, "dns_cache_hits_total %d\n", m.CacheHits.Load())

	// dns_cache_misses_total
	fmt.Fprintf(&buf, "# HELP dns_cache_misses_total Cache miss count\n")
	fmt.Fprintf(&buf, "# TYPE dns_cache_misses_total counter\n")
	fmt.Fprintf(&buf, "dns_cache_misses_total %d\n", m.CacheMisses.Load())

	// go_goroutines
	fmt.Fprintf(&buf, "# HELP go_goroutines Current goroutine count\n")
	fmt.Fprintf(&buf, "# TYPE go_goroutines gauge\n")
	fmt.Fprintf(&buf, "go_goroutines %d\n", runtime.NumGoroutine())

	// process_uptime_seconds
	uptime := time.Since(m.StartTime).Seconds()
	fmt.Fprintf(&buf, "# HELP process_uptime_seconds Application uptime in seconds\n")
	fmt.Fprintf(&buf, "# TYPE process_uptime_seconds gauge\n")
	fmt.Fprintf(&buf, "process_uptime_seconds %f\n", uptime)

	_, _ = buf.WriteTo(w)
}

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// If no auth is configured, allow all
		if s.cfg.WebUsername == "" || s.cfg.WebPassword == "" {
			next.ServeHTTP(w, r)
			return
		}

		// Check for session cookie
		cookie, err := r.Cookie(sessionCookieName)
		if err == nil && cookie.Value == "authenticated" {
			next.ServeHTTP(w, r)
			return
		}

		// Redirect to login for HTML requests, return 401 for API
		if strings.Contains(r.Header.Get("Accept"), "text/html") {
			loginURL := s.cfg.BaseURL + "/login"
			http.Redirect(w, r, loginURL, http.StatusSeeOther)
		} else {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
		}
	})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	nonce := ""
	if s.nonceFromCtx != nil {
		nonce = s.nonceFromCtx(r.Context())
	}

	if r.Method == http.MethodGet {
		// Generate CSRF token
		csrfToken := generateCSRFToken()

		// Set CSRF cookie (HttpOnly, Secure if HTTPS, SameSite=Strict)
		http.SetCookie(w, &http.Cookie{
			Name:     csrfCookieName,
			Value:    csrfToken,
			Path:     "/",
			HttpOnly: true,
			Secure:   isHTTPS(r),
			SameSite: http.SameSiteStrictMode,
			MaxAge:   86400 * 7, // 1 week, matches session cookie
		})

		if err := s.tmpl.ExecuteTemplate(w, "login.html", map[string]interface{}{
			"Nonce":     nonce,
			"CSRFToken": csrfToken,
			"BaseURL":   s.cfg.BaseURL,
		}); err != nil {
			log.Printf("Template execution error: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
		return
	}

	if r.Method == http.MethodPost {
		// --- Rate limiting check ---
		ip := clientIP(r)
		if limited, remaining := s.checkRateLimit(ip); limited {
			w.Header().Set("Retry-After", fmt.Sprintf("%.0f", remaining.Seconds()))
			http.Error(w, apperr.NewErrRateLimited("too many login attempts", nil).Error(), http.StatusTooManyRequests)
			return
		}

		// --- CSRF validation ---
		csrfCookie, err := r.Cookie(csrfCookieName)
		if err != nil {
			http.Error(w, apperr.NewErrCSRFMismatch("missing CSRF token", err).Error(), http.StatusForbidden)
			return
		}
		csrfSubmitted := r.FormValue("csrf_token")
		if csrfSubmitted == "" {
			csrfSubmitted = r.Header.Get("X-CSRF-Token")
		}
		if subtle.ConstantTimeCompare([]byte(csrfCookie.Value), []byte(csrfSubmitted)) != 1 {
			http.Error(w, apperr.NewErrCSRFMismatch("invalid CSRF token", nil).Error(), http.StatusForbidden)
			return
		}

		// --- Authentication ---
		username := r.FormValue("username")
		password := r.FormValue("password")

		if username == s.cfg.WebUsername && checkPassword(s.hashedPassword, password) {
			// Successful login — reset rate limiter for this IP
			s.resetRateLimit(ip)

			http.SetCookie(w, &http.Cookie{
				Name:     sessionCookieName,
				Value:    "authenticated",
				Path:     "/",
				HttpOnly: true,
				Secure:   isHTTPS(r),
				MaxAge:   86400 * 7, // 1 week
				SameSite: http.SameSiteStrictMode,
			})
			http.Redirect(w, r, s.cfg.BaseURL+"/", http.StatusSeeOther)
			return
		}

		// Failed login — record for rate limiting
		s.recordFailedLogin(ip)

		_ = s.tmpl.ExecuteTemplate(w, "login.html", map[string]interface{}{
			"Error":   "Invalid username or password",
			"Nonce":   nonce,
			"BaseURL": s.cfg.BaseURL,
		})
	}
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   isHTTPS(r),
		MaxAge:   -1,
		SameSite: http.SameSiteStrictMode,
	})
	// Also clear the CSRF cookie
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   isHTTPS(r),
		MaxAge:   -1,
		SameSite: http.SameSiteStrictMode,
	})
	http.Redirect(w, r, s.cfg.BaseURL+"/login", http.StatusSeeOther)
}

func (s *Server) handleIngest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 1. Enforce Authentication
	if s.cfg.IngestSecret != "" {
		auth := r.Header.Get("Authorization")
		expected := "Bearer " + s.cfg.IngestSecret
		if subtle.ConstantTimeCompare([]byte(auth), []byte(expected)) != 1 {
			http.Error(w, apperr.NewErrAuthFailed("invalid ingest secret", nil).Error(), http.StatusUnauthorized)
			return
		}
	}

	// 2. Limit Total Payload Size
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxRequestSize)

	// Item 85: Handle gzip-encoded request body
	var bodyReader io.Reader = r.Body
	if r.Header.Get("Content-Encoding") == "gzip" {
		gzReader, err := gzip.NewReader(r.Body)
		if err != nil {
			http.Error(w, apperr.NewErrParseFailed("gzip decompress error", err).Error(), http.StatusBadRequest)
			return
		}
		defer func() { _ = gzReader.Close() }()
		bodyReader = gzReader
	}

	var payload struct {
		Node   string             `json:"node"`
		Line   string             `json:"line"`
		Batch  []string           `json:"batch"`
		Health map[string]float64 `json:"health,omitempty"`
	}
	if err := json.NewDecoder(bodyReader).Decode(&payload); err != nil {
		http.Error(w, apperr.NewErrParseFailed("payload too large or bad request", err).Error(), http.StatusBadRequest)
		return
	}

	// 3. Strict Input Validation
	if len(payload.Batch) > 100 {
		http.Error(w, "Batch too large (max 100)", http.StatusRequestEntityTooLarge)
		return
	}

	processLine := func(line string) {
		if len(line) > 1024 { // Cap max bytes per line
			return
		}
		ev := s.parser.ParseLogBytes([]byte(line), payload.Node)
		if ev != nil {
			s.BroadcastEvent(*ev)
		}
	}

	if payload.Line != "" {
		processLine(payload.Line)
	}
	for _, l := range payload.Batch {
		processLine(l)
	}
	if len(payload.Health) > 0 {
		s.store.SetUpstreamHealth(payload.Node, payload.Health)
	}

	// Item 88: Update node status from version headers on ingest
	if payload.Node != "" {
		nodeVersion := r.Header.Get("X-Node-Version")
		goVersion := r.Header.Get("X-Go-Version")
		buildInfo := r.Header.Get("X-Node-Build")
		s.store.SetNodeStatus(payload.Node, models.NodeStatus{
			Name:      payload.Node,
			Version:   nodeVersion,
			GoVersion: goVersion,
			BuildInfo: buildInfo,
		})
	}

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	nonce := ""
	if s.nonceFromCtx != nil {
		nonce = s.nonceFromCtx(r.Context())
	}

	currentEvents := s.store.GetOrderedEvents(s.cfg.ScanLimit)
	var buf bytes.Buffer
	if err := s.tmpl.Execute(&buf, map[string]interface{}{
		"Events":  currentEvents,
		"Nonce":   nonce,
		"BaseURL": s.cfg.BaseURL,
		"Mode":    s.cfg.Mode,
	}); err != nil {
		log.Printf("Template execution error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = buf.WriteTo(w)
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	sinceStr := r.URL.Query().Get("since")
	var since int64
	if sinceStr != "" {
		_, _ = fmt.Sscanf(sinceStr, "%d", &since)
	}
	result := s.store.GetRecentEvents(since)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}

func (s *Server) handleStats(w http.ResponseWriter, _ *http.Request) {
	stats := s.store.GetStats()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(stats)
}

func (s *Server) handleClientStats(w http.ResponseWriter, r *http.Request) {
	if s.cfg.IngestSecret != "" {
		auth := r.Header.Get("Authorization")
		expected := "Bearer " + s.cfg.IngestSecret
		if subtle.ConstantTimeCompare([]byte(auth), []byte(expected)) != 1 {
			http.Error(w, apperr.NewErrAuthFailed("invalid ingest secret", nil).Error(), http.StatusUnauthorized)
			return
		}
	}

	ip := r.URL.Query().Get("ip")
	if ip == "" || net.ParseIP(ip) == nil {
		http.Error(w, "Missing or invalid ip parameter", http.StatusBadRequest)
		return
	}
	stats := s.store.GetClientStats(ip)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(stats)
}

func (s *Server) handleSimulate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		http.Error(w, "Missing domain parameter", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	ips, err := (&net.Resolver{}).LookupIPAddr(ctx, domain)
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			w.WriteHeader(http.StatusGatewayTimeout)
		} else {
			var dnsErr *net.DNSError
			if errors.As(err, &dnsErr) {
				w.WriteHeader(http.StatusBadGateway)
			} else {
				w.WriteHeader(http.StatusInternalServerError)
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "error", "error": err.Error()})
		return
	}
	res := make([]string, 0, len(ips))
	for _, ip := range ips {
		res = append(res, ip.String())
	}
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "success", "ips": res})
}

func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch := s.Subscribe()

	defer func() {
		s.Unsubscribe(ch)
	}()

	notify := r.Context().Done()
	keepalive := s.cfg.SSEKeepaliveInterval
	timer := time.NewTimer(keepalive)
	defer timer.Stop()

	for {
		select {
		case <-notify:
			return
		case ev, ok := <-ch:
			if !ok {
				return
			}
			data, _ := json.Marshal(ev)
			_, _ = fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(keepalive)
		case <-timer.C:
			// Keepalive comment
			_, _ = fmt.Fprintf(w, ": keepalive\n\n")
			flusher.Flush()
			timer.Reset(keepalive)
		}
	}
}

// ===== Item 61: Blocklist Status Endpoint =====
func (s *Server) handleBlocklistStatus(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	s.fieldsMu.RLock()
	bl := s.blocklist
	s.fieldsMu.RUnlock()
	if bl == nil {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"count": 0,
			"file":  "",
		})
		return
	}
	_ = json.NewEncoder(w).Encode(bl.Status())
}

// ===== Item 62: Upstream Configuration Editor =====
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

	upstreamsPath := s.cfg.FullUpstreamsPath()
	var upstreams []string
	if upstreamsPath != "" {
		upstreams = dnsroutes.LoadUpstreams(upstreamsPath)
	}
	if upstreams == nil {
		upstreams = []string{}
	}

	_ = json.NewEncoder(w).Encode(upstreams)
}

func (s *Server) handlePostUpstreams(w http.ResponseWriter, r *http.Request) {
	var req []struct {
		Address string `json:"address"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
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
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"error": "Invalid upstream address format (expected ip:port)",
				"input": addr,
			})
			return
		}
		if net.ParseIP(host) == nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"error": "Invalid upstream IP address",
				"input": host,
			})
			return
		}
		portNum, err := strconv.Atoi(port)
		if err != nil || portNum < 1 || portNum > 65535 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"error": "Invalid upstream port (must be 1-65535)",
				"input": port,
			})
			return
		}
		upstreams = append(upstreams, addr)
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

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "ok",
		"upstreams": upstreams,
	})
}

// ===== Item 63: Cache Clear Endpoint =====
func (s *Server) handleCacheClear(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// On Windows, SIGUSR1 is not supported
	if runtime.GOOS == "windows" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "Cache clear signal (SIGUSR1) is not supported on Windows",
		})
		return
	}

	pidFile := s.cfg.DNSMasqPIDFile
	data, err := os.ReadFile(pidFile)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": fmt.Sprintf("PID file not found: %s", pidFile),
		})
		return
	}

	pidStr := strings.TrimSpace(string(data))
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": fmt.Sprintf("Invalid PID in file: %s", pidStr),
		})
		return
	}

	proc, err := os.FindProcess(pid)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": fmt.Sprintf("Failed to find process %d: %v", pid, err),
		})
		return
	}

	if err := sendCacheClearSignal(proc); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": fmt.Sprintf("Failed to send cache clear signal to process %d: %v", pid, err),
		})
		return
	}

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "ok",
		"message": "DNS cache clear signal sent",
	})
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

func (s *Server) handlePostDNSRoutes(w http.ResponseWriter, r *http.Request) {
	var routesMap map[string]string
	if err := json.NewDecoder(r.Body).Decode(&routesMap); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
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
// handleHeartbeat processes heartbeat messages from slave nodes.
// It updates the node status in storage and is protected by IngestSecret.
func (s *Server) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Authenticate with IngestSecret (same as ingest endpoint)
	if s.cfg.IngestSecret != "" {
		auth := r.Header.Get("Authorization")
		expected := "Bearer " + s.cfg.IngestSecret
		if subtle.ConstantTimeCompare([]byte(auth), []byte(expected)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}

	// Handle gzip-encoded request body
	var bodyReader io.Reader = r.Body
	if r.Header.Get("Content-Encoding") == "gzip" {
		gzReader, err := gzip.NewReader(r.Body)
		if err != nil {
			http.Error(w, "gzip decompress error", http.StatusBadRequest)
			return
		}
		defer func() { _ = gzReader.Close() }()
		bodyReader = gzReader
	}

	// Limit payload size
	limitedReader := io.LimitReader(bodyReader, s.cfg.MaxRequestSize)

	var hb models.HeartbeatPayload
	if err := json.NewDecoder(limitedReader).Decode(&hb); err != nil {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}

	if hb.Node == "" {
		http.Error(w, "missing node name", http.StatusBadRequest)
		return
	}

	// Extract version info from headers (Item 88)
	nodeVersion := r.Header.Get("X-Node-Version")
	goVersion := r.Header.Get("X-Go-Version")
	buildInfo := r.Header.Get("X-Node-Build")

	// Use header values if payload fields are empty
	if hb.Version == "" && nodeVersion != "" {
		hb.Version = nodeVersion
	}
	if hb.GoVersion == "" && goVersion != "" {
		hb.GoVersion = goVersion
	}
	if hb.BuildInfo == "" && buildInfo != "" {
		hb.BuildInfo = buildInfo
	}

	// Update node status in storage
	status := models.NodeStatus{
		Name:           hb.Node,
		Version:        hb.Version,
		GoVersion:      hb.GoVersion,
		BuildInfo:      hb.BuildInfo,
		MemoryMB:       hb.MemoryMB,
		Goroutines:     hb.Goroutines,
		DBSizeMB:       hb.DBSizeMB,
		UpstreamHealth: hb.Health,
	}
	s.store.SetNodeStatus(hb.Node, status)

	// Also store upstream health if provided
	if len(hb.Health) > 0 {
		s.store.SetUpstreamHealth(hb.Node, hb.Health)
	}

	log.Printf("[INFO] Heartbeat received from node %s (v%s, %d goroutines, %.1fMB mem)",
		hb.Node, hb.Version, hb.Goroutines, hb.MemoryMB)

	w.WriteHeader(http.StatusNoContent)
}

// ===== Item 90: Sync Client Aliases Endpoint =====
// handleSyncAliases returns the current client aliases configuration.
// Slaves call this to sync their aliases with the master.
func (s *Server) handleSyncAliases(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Authenticate with IngestSecret
	if s.cfg.IngestSecret != "" {
		auth := r.Header.Get("Authorization")
		expected := "Bearer " + s.cfg.IngestSecret
		if subtle.ConstantTimeCompare([]byte(auth), []byte(expected)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}

	aliases := s.cfg.ClientAliases
	if aliases == nil {
		aliases = make(map[string]string)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(aliases)
}

// ===== Item 91: Sync DNS Routes Endpoint =====
// handleSyncDNSRoutes returns the current DNS routes configuration.
// Slaves call this to sync their DNS routes with the master.
func (s *Server) handleSyncDNSRoutes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Authenticate with IngestSecret
	if s.cfg.IngestSecret != "" {
		auth := r.Header.Get("Authorization")
		expected := "Bearer " + s.cfg.IngestSecret
		if subtle.ConstantTimeCompare([]byte(auth), []byte(expected)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}

	routes := make(map[string]string)
	s.fieldsMu.RLock()
	dr := s.dnsRoutes
	s.fieldsMu.RUnlock()
	if dr != nil {
		routes = dr.GetRoutesMap()
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"routes": routes,
	})
}

// ===== Item 94: Sync Upstream Health Endpoint =====
// handleSyncUpstreamHealth returns the upstream health data for all nodes.
// Slaves call this to sync their upstream health view with the master.
func (s *Server) handleSyncUpstreamHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Authenticate with IngestSecret
	if s.cfg.IngestSecret != "" {
		auth := r.Header.Get("Authorization")
		expected := "Bearer " + s.cfg.IngestSecret
		if subtle.ConstantTimeCompare([]byte(auth), []byte(expected)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}

	healthData := s.store.GetUpstreamHealth()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(healthData)
}

// ===== Item 89: Node Discovery and Status Endpoint =====
// handleNodes returns the status of all known nodes in the cluster.
func (s *Server) handleNodes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	nodes := s.store.GetNodeStatuses()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"nodes": nodes,
	})
}

func (s *Server) gzipMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

type gzipResponseWriter struct {
	io.Writer
	http.ResponseWriter
}

func (w gzipResponseWriter) Write(b []byte) (int, error) {
	return w.Writer.Write(b)
}

// Start launches the HTTP server and listens for requests.
func (s *Server) Start(ctx context.Context, staticHandler http.Handler, cspMiddleware func(http.Handler) http.Handler, nonceFromCtx func(context.Context) string) error {
	// Configure static handler, CSP middleware, and nonce function
	s.SetStaticHandler(staticHandler, cspMiddleware, nonceFromCtx)

	// Build the handler chain: CSP middleware wraps the entire mux
	handler := s.cspMiddleware(s.SetupMux())

	server := &http.Server{
		Addr:              ":" + s.cfg.Port,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       s.cfg.HTTPReadTimeout,
		WriteTimeout:      s.cfg.HTTPWriteTimeout,
		IdleTimeout:       120 * time.Second,
	}

	ln, err := net.Listen("tcp", server.Addr)
	if err != nil {
		return err
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.cfg.HTTPShutdownTimeout)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	log.Printf("Starting Advanced Web GUI on %s", server.Addr)
	return server.Serve(ln)
}

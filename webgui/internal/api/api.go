// Package api implements the HTTP API and web GUI server for the
// Resolix application. It handles authentication, SSE
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
	"mime"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/miekg/dns"

	"github.com/arumes31/resolix/webgui/internal/blocklist"
	"github.com/arumes31/resolix/webgui/internal/clients"
	"github.com/arumes31/resolix/webgui/internal/config"
	"github.com/arumes31/resolix/webgui/internal/dnsroutes"
	"github.com/arumes31/resolix/webgui/internal/dnsserver"
	apperr "github.com/arumes31/resolix/webgui/internal/errors"
	"github.com/arumes31/resolix/webgui/internal/filter"
	"github.com/arumes31/resolix/webgui/internal/forwarder"
	"github.com/arumes31/resolix/webgui/internal/models"
	"github.com/arumes31/resolix/webgui/internal/parser"
	"github.com/arumes31/resolix/webgui/internal/policy"
	"github.com/arumes31/resolix/webgui/internal/resolver"
	"github.com/arumes31/resolix/webgui/internal/rewrites"
	"github.com/arumes31/resolix/webgui/internal/storage"
	"github.com/arumes31/resolix/webgui/internal/upstream"
)

const (
	sessionCookieName   = "ts_dns_session"
	csrfCookieName      = "ts_dns_csrf"
	csrfTokenBytes      = 32
	sessionTokenBytes   = 32
	sessionLifetime     = 7 * 24 * time.Hour
	maxIngestFutureSkew = 5 * time.Minute
	statsResponseTTL    = 5 * time.Second
	staticAssetCaching  = "public, max-age=300"
)

var userRulesMu sync.Mutex

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
	httpRequests      sync.Map // map["method status"]*atomic.Int64
	httpDurationNanos atomic.Int64
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
func (m *Metrics) RecordUpstreamLatency(upstreamName string, latencyMs float64) {
	if v, ok := m.upstreamLatencies.Load(upstreamName); ok {
		v.(*latencyBucket).addSample(latencyMs)
		return
	}
	newV := &latencyBucket{}
	newV.addSample(latencyMs)
	if actual, loaded := m.upstreamLatencies.LoadOrStore(upstreamName, newV); loaded {
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
	sessions       map[string]time.Time
	sessionMu      sync.Mutex

	// Reverse DNS resolver (Item 59)
	resolver *resolver.Resolver

	// Blocklist (Item 61)
	blocklist *blocklist.Blocklist

	// Filter engine (Step 2: rule-based filtering with subscriptions)
	filterEngine      *filter.Engine
	subscriptionStore *filter.SubscriptionStore

	// Typed rewrites store (Step 3) and DNS server (pipeline metrics)
	rewritesStore *rewrites.Store
	dnsServer     *dnsserver.Server

	// Per-client registry (Step 5)
	clientsRegistry *clients.Registry

	// upstreamReloadFn reloads the upstream pool after upstreams.json saves
	upstreamReloadFn func()
	upstreamPool     *upstream.Pool
	forwarder        *forwarder.Forwarder

	// DNS routes (Item 66)
	dnsRoutes *dnsroutes.DNSRoutes

	// Mutex protecting resolver, blocklist, and dnsRoutes fields
	fieldsMu sync.RWMutex

	// DNS loop detection (Item 65)
	dnsLoopDetected bool
	dnsLoopMu       sync.Mutex
	dnsLoopDetails  string

	// Short-lived response cache coalesces expensive SQLite stats aggregation
	// across dashboard clients while keeping live counters reasonably fresh.
	statsCacheMu   sync.Mutex
	statsCacheBody []byte
	statsCacheAt   time.Time

	// Prometheus metrics (Item 77)
	metrics   *Metrics
	webReady  atomic.Bool
	version   string
	buildInfo string
}

// SetBuildInfo publishes build metadata through the API and node status.
func (s *Server) SetBuildInfo(version, buildInfo string) {
	s.fieldsMu.Lock()
	s.version = version
	s.buildInfo = buildInfo
	s.fieldsMu.Unlock()
}

func (s *Server) buildMetadata() (version, buildInfo string) {
	s.fieldsMu.RLock()
	defer s.fieldsMu.RUnlock()
	return s.version, s.buildInfo
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
		sessions:    make(map[string]time.Time),
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

// SetFilter configures the filter engine for status/pause endpoints and metrics.
func (s *Server) SetFilter(eng *filter.Engine) {
	s.fieldsMu.Lock()
	defer s.fieldsMu.Unlock()
	s.filterEngine = eng
}

// SetSubscriptionStore configures persistent URL filter subscriptions.
func (s *Server) SetSubscriptionStore(store *filter.SubscriptionStore) {
	s.fieldsMu.Lock()
	defer s.fieldsMu.Unlock()
	s.subscriptionStore = store
}

// SetRewritesStore configures the typed-rewrites store for the CRUD API.
func (s *Server) SetRewritesStore(store *rewrites.Store) {
	s.fieldsMu.Lock()
	defer s.fieldsMu.Unlock()
	s.rewritesStore = store
}

// SetDNSServer configures the DNS server for pipeline metrics.
func (s *Server) SetDNSServer(srv *dnsserver.Server) {
	s.fieldsMu.Lock()
	defer s.fieldsMu.Unlock()
	s.dnsServer = srv
}

// SetClients configures the per-client registry for the clients API.
func (s *Server) SetClients(reg *clients.Registry) {
	s.fieldsMu.Lock()
	defer s.fieldsMu.Unlock()
	s.clientsRegistry = reg
}

// SetUpstreamReloadFunc configures the callback invoked after the upstreams
// file is saved via the API, so the pool picks up changes immediately.
func (s *Server) SetUpstreamReloadFunc(fn func()) {
	s.fieldsMu.Lock()
	defer s.fieldsMu.Unlock()
	s.upstreamReloadFn = fn
}

// SetUpstreamPool configures upstream runtime metrics.
func (s *Server) SetUpstreamPool(pool *upstream.Pool) {
	s.fieldsMu.Lock()
	s.upstreamPool = pool
	s.fieldsMu.Unlock()
}

// SetForwarder configures forwarding queue metrics.
func (s *Server) SetForwarder(fwd *forwarder.Forwarder) {
	s.fieldsMu.Lock()
	s.forwarder = fwd
	s.fieldsMu.Unlock()
}

// getFilter returns the configured filter engine (may be nil).
func (s *Server) getFilter() *filter.Engine {
	s.fieldsMu.RLock()
	defer s.fieldsMu.RUnlock()
	return s.filterEngine
}

// getDNSServer returns the configured DNS server (may be nil).
func (s *Server) getDNSServer() *dnsserver.Server {
	s.fieldsMu.RLock()
	defer s.fieldsMu.RUnlock()
	return s.dnsServer
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
func generateCSRFToken() (string, error) {
	b := make([]byte, csrfTokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate CSRF token: %w", err)
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// checkCSRF validates the double-submit token used by authenticated browser
// sessions. CSRF protection is unnecessary when web authentication is off.
func (s *Server) checkCSRF(w http.ResponseWriter, r *http.Request) bool {
	if s.cfg.WebUsername == "" && s.cfg.WebPassword == "" {
		return true
	}
	cookie, err := r.Cookie(csrfCookieName)
	if err != nil {
		http.Error(w, apperr.NewErrCSRFMismatch("missing CSRF token", err).Error(), http.StatusForbidden)
		return false
	}
	submitted := r.Header.Get("X-CSRF-Token")
	if submitted == "" {
		submitted = r.FormValue("csrf_token")
	}
	if subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(submitted)) != 1 {
		http.Error(w, apperr.NewErrCSRFMismatch("invalid CSRF token", nil).Error(), http.StatusForbidden)
		return false
	}
	return true
}

func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func (s *Server) isTrustedProxy(r *http.Request) bool {
	return s.isTrustedProxyIP(remoteIP(r))
}

// isTrustedProxyIP reports whether the given IP string belongs to a trusted proxy.
func (s *Server) isTrustedProxyIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, trusted := range s.cfg.TrustedProxies {
		if trustedIP := net.ParseIP(trusted); trustedIP != nil {
			if trustedIP.Equal(ip) {
				return true
			}
			continue
		}
		if _, network, err := net.ParseCIDR(trusted); err == nil && network.Contains(ip) {
			return true
		}
	}
	return false
}

// isHTTPS determines whether the request was made over HTTPS. Forwarded
// headers are honored only when the immediate peer is explicitly trusted.
func (s *Server) isHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if !s.isTrustedProxy(r) {
		return false
	}
	forwardedEntries := strings.Split(strings.Join(r.Header.Values("Forwarded"), ","), ",")
	for i := len(forwardedEntries) - 1; i >= 0; i-- {
		if strings.TrimSpace(forwardedEntries[i]) == "" {
			continue
		}
		for _, parameter := range strings.Split(forwardedEntries[i], ";") {
			key, value, ok := strings.Cut(strings.TrimSpace(parameter), "=")
			if ok && strings.EqualFold(key, "proto") {
				return strings.EqualFold(strings.Trim(value, `"`), "https")
			}
		}
		break
	}
	protos := strings.Split(strings.Join(r.Header.Values("X-Forwarded-Proto"), ","), ",")
	for i := len(protos) - 1; i >= 0; i-- {
		if proto := strings.TrimSpace(protos[i]); proto != "" {
			return strings.EqualFold(proto, "https")
		}
	}
	return false
}

func (s *Server) newSecureCookie(name, value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     s.cookiePath(),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   maxAge,
	}
}

// sanitizeLogValue strips CR/LF characters from an untrusted value before it
// is written to the logs, preventing log injection (gosec G706).
func sanitizeLogValue(s string) string {
	return strings.NewReplacer("\r", "", "\n", "").Replace(s)
}

// clientIP extracts the client IP from the request. Forwarded headers are
// honored only when the immediate peer is explicitly trusted; the
// X-Forwarded-For list is then walked right-to-left and the first address
// that is not itself a trusted proxy is returned.
func (s *Server) clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" && s.isTrustedProxy(r) {
		parts := strings.Split(xff, ",")
		for i := len(parts) - 1; i >= 0; i-- {
			ip := strings.TrimSpace(parts[i])
			if ip != "" && !s.isTrustedProxyIP(ip) {
				return ip
			}
		}
	}
	if forwarded := r.Header.Get("Forwarded"); forwarded != "" && s.isTrustedProxy(r) {
		entries := strings.Split(forwarded, ",")
		for i := len(entries) - 1; i >= 0; i-- {
			for _, parameter := range strings.Split(entries[i], ";") {
				key, value, ok := strings.Cut(strings.TrimSpace(parameter), "=")
				if !ok || !strings.EqualFold(key, "for") {
					continue
				}
				ip := strings.Trim(strings.TrimSpace(value), `"`)
				if host, _, err := net.SplitHostPort(ip); err == nil {
					ip = host
				}
				ip = strings.Trim(ip, "[]")
				if net.ParseIP(ip) != nil && !s.isTrustedProxyIP(ip) {
					return ip
				}
			}
		}
	}
	return remoteIP(r)
}

func (s *Server) cookiePath() string {
	if s.cfg.BaseURL == "" {
		return "/"
	}
	return s.cfg.BaseURL
}

func (s *Server) newSession() (string, error) {
	tokenBytes := make([]byte, sessionTokenBytes)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", fmt.Errorf("generate session token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)
	now := time.Now()
	s.sessionMu.Lock()
	for existing, expires := range s.sessions {
		if !expires.After(now) {
			delete(s.sessions, existing)
		}
	}
	s.sessions[token] = now.Add(sessionLifetime)
	s.sessionMu.Unlock()
	return token, nil
}

func (s *Server) validSession(token string) bool {
	now := time.Now()
	valid := 0
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()
	for existing, expires := range s.sessions {
		if !expires.After(now) {
			delete(s.sessions, existing)
			continue
		}
		valid |= subtle.ConstantTimeCompare([]byte(existing), []byte(token))
	}
	return valid == 1
}

func (s *Server) deleteSession(token string) {
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()
	for existing := range s.sessions {
		if subtle.ConstantTimeCompare([]byte(existing), []byte(token)) == 1 {
			delete(s.sessions, existing)
		}
	}
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

// Unsubscribe removes a subscriber channel. BroadcastEvent owns channel
// closure so removal cannot race with a concurrent send.
func (s *Server) Unsubscribe(ch chan models.QueryEvent) {
	s.subMu.Lock()
	delete(s.subscribers, ch)
	s.subMu.Unlock()
}

// BroadcastEvent safely sends an event to all SSE subscribers.
// Slow subscribers are handled with non-blocking sends; if a subscriber's
// channel is full, the event is dropped and the drop counter is incremented.
// Subscribers that exceed 10 consecutive drops are removed.
func (s *Server) BroadcastEvent(e models.QueryEvent) {
	// Item 59: Enrich with reverse DNS hostname
	s.fieldsMu.RLock()
	res := s.resolver
	bl := s.blocklist
	s.fieldsMu.RUnlock()

	if res != nil && e.ClientIP != "" {
		if hostname := res.GetHostname(e.ClientIP); hostname != "" {
			e.ClientHostname = hostname
		}
	}

	// Item 61: Check blocklist — fallback for legacy-ingested events only;
	// the DNS pipeline (filter engine) is the source of truth for Blocked.
	if !e.Blocked && bl != nil && e.Domain != "" {
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

	s.subMu.Lock()
	defer s.subMu.Unlock()
	for ch, drops := range s.subscribers {
		select {
		case ch <- e:
			if drops > 0 {
				s.subscribers[ch] = 0
			}
		default:
			s.subDropCnt.Add(1)
			s.subscribers[ch] = drops + 1
			if s.subscribers[ch] > 10 {
				log.Printf("Dropping slow subscriber")
				delete(s.subscribers, ch)
				close(ch)
			}
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

type statusResponseWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusResponseWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusResponseWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (w *statusResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func metricMethod(method string) string {
	switch method {
	case http.MethodConnect,
		http.MethodDelete,
		http.MethodGet,
		http.MethodHead,
		http.MethodOptions,
		http.MethodPatch,
		http.MethodPost,
		http.MethodPut,
		http.MethodTrace:
		return method
	default:
		return "OTHER"
	}
}

func (s *Server) requestMetricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		requestIDBytes := make([]byte, 12)
		if _, err := rand.Read(requestIDBytes); err == nil {
			w.Header().Set("X-Request-ID", base64.RawURLEncoding.EncodeToString(requestIDBytes))
		}
		rw := &statusResponseWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rw, r)
		key := metricMethod(r.Method) + " " + strconv.Itoa(rw.status)
		counter := &atomic.Int64{}
		actual, _ := s.metrics.httpRequests.LoadOrStore(key, counter)
		actual.(*atomic.Int64).Add(1)
		s.metrics.httpDurationNanos.Add(time.Since(started).Nanoseconds())
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
	mux.Handle("/config", s.authMiddleware(http.HandlerFunc(s.handleConfigPage)))
	mux.Handle("/api/events", s.authMiddleware(http.HandlerFunc(s.handleEvents)))
	mux.Handle("/api/stats", s.authMiddleware(http.HandlerFunc(s.handleStats)))
	mux.Handle("/api/client_stats", s.authMiddleware(http.HandlerFunc(s.handleClientStats)))
	mux.Handle("/api/simulate", s.authMiddleware(http.HandlerFunc(s.handleSimulate)))

	// Item 61: Blocklist status endpoint
	mux.Handle("/api/blocklist/status", s.authMiddleware(http.HandlerFunc(s.handleBlocklistStatus)))

	// Filter engine: pause/resume protection and status
	mux.Handle("/api/filtering/pause", s.authMiddleware(http.HandlerFunc(s.handleFilteringPause)))
	mux.Handle("/api/filtering/status", s.authMiddleware(http.HandlerFunc(s.handleFilteringStatus)))
	mux.Handle("/api/config/status", s.authMiddleware(http.HandlerFunc(s.handleConfigStatus)))
	mux.Handle("/api/config/subscriptions", s.authMiddleware(http.HandlerFunc(s.handleFilterSubscriptions)))
	mux.Handle("/api/config/user-rules", s.authMiddleware(http.HandlerFunc(s.handleUserRules)))

	// Typed DNS rewrites CRUD
	mux.Handle("/api/rewrites", s.authMiddleware(http.HandlerFunc(s.handleRewrites)))

	// Per-client registry CRUD (Step 5)
	mux.Handle("/api/clients", s.authMiddleware(http.HandlerFunc(s.handleClients)))
	mux.Handle("/api/services", s.authMiddleware(http.HandlerFunc(s.handleServices)))

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

	// Item 63: Cache clear endpoint
	mux.Handle("/api/cache/clear", s.authMiddleware(http.HandlerFunc(s.handleCacheClear)))

	// Item 65: DNS loop detection endpoint
	mux.Handle("/api/dns/loop-status", s.authMiddleware(http.HandlerFunc(s.handleDNSLoopStatus)))

	// Item 66: Domain-specific routing rules
	mux.Handle("/api/dns/routes", s.authMiddleware(http.HandlerFunc(s.handleDNSRoutes)))

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
var dohPrivateNets = mustParseCIDRs([]string{
	"127.0.0.0/8", "::1/128",
	"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
	"100.64.0.0/10", "fc00::/7",
})

func mustParseCIDRs(raws []string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(raws))
	for _, raw := range raws {
		_, n, err := net.ParseCIDR(raw)
		if err != nil {
			panic(err)
		}
		out = append(out, n)
	}
	return out
}

// dohClientAllowed enforces the DoH auth model: Bearer token when
// DOH_AUTH_TOKEN is set, otherwise private/tailnet client IPs only.
func (s *Server) dohClientAllowed(r *http.Request) bool {
	if token := s.cfg.DoHAuthToken; token != "" {
		auth := r.Header.Get("Authorization")
		return subtle.ConstantTimeCompare([]byte(auth), []byte("Bearer "+token)) == 1
	}
	peerIP := net.ParseIP(remoteIP(r))
	// Forwarded headers are not proof that a loopback peer is a proxy: any
	// local process can forge them. Loopback proxies must authenticate with
	// DOH_AUTH_TOKEN, which is handled above.
	if peerIP != nil && peerIP.IsLoopback() {
		return false
	}
	ip := net.ParseIP(s.clientIP(r))
	if ip == nil {
		return false
	}
	for _, n := range dohPrivateNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// handleDoH serves DNS-over-HTTPS (RFC 8484 GET+POST) through the same
// pipeline as the UDP/TCP/DoT listeners.
func (s *Server) handleDoH(w http.ResponseWriter, r *http.Request) {
	dnsSrv := s.getDNSServer()
	if dnsSrv == nil {
		http.Error(w, "DNS server not available", http.StatusServiceUnavailable)
		return
	}
	if !s.dohClientAllowed(r) {
		if s.cfg.DoHAuthToken != "" {
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
		} else {
			http.Error(w, "Forbidden", http.StatusForbidden)
		}
		return
	}

	var wire []byte
	switch r.Method {
	case http.MethodGet:
		raw := r.URL.Query().Get("dns")
		if raw == "" {
			http.Error(w, "Missing dns parameter", http.StatusBadRequest)
			return
		}
		decoded, err := base64.RawURLEncoding.DecodeString(raw)
		if err != nil {
			http.Error(w, "Invalid dns parameter", http.StatusBadRequest)
			return
		}
		if len(decoded) > 65535 {
			http.Error(w, "DNS message too large", http.StatusRequestEntityTooLarge)
			return
		}
		wire = decoded
	case http.MethodPost:
		mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || mediaType != "application/dns-message" {
			http.Error(w, "Unsupported content type", http.StatusUnsupportedMediaType)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64*1024))
		if err != nil {
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				http.Error(w, "DNS message too large", http.StatusRequestEntityTooLarge)
				return
			}
			http.Error(w, "Failed to read body", http.StatusBadRequest)
			return
		}
		if len(body) > 65535 {
			http.Error(w, "DNS message too large", http.StatusRequestEntityTooLarge)
			return
		}
		wire = body
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	req := new(dns.Msg)
	if err := req.Unpack(wire); err != nil {
		http.Error(w, "Invalid DNS message", http.StatusBadRequest)
		return
	}

	resp, drop := dnsSrv.Resolve(req, s.clientIP(r))
	if drop || resp == nil {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	out, err := resp.Pack()
	if err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/dns-message")
	_, _ = w.Write(out) // #nosec G705 -- RFC 8484 response is packed binary DNS, not HTML
}

// handleMetrics exposes Prometheus-format metrics on the /metrics endpoint.
// The route is protected by authMiddleware (see SetupMux).
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
		fmt.Fprintf(&buf, "dns_queries_by_type{type=\"%s\"} %d\n", escapePrometheusLabel(fmt.Sprint(key)), value.(*atomic.Int64).Load())
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
			label := escapePrometheusLabel(fmt.Sprint(key))
			fmt.Fprintf(&buf, "dns_upstream_latency_seconds_count{upstream=\"%s\"} %d\n", label, lb.count)
			fmt.Fprintf(&buf, "dns_upstream_latency_seconds_sum{upstream=\"%s\"} %f\n", label, lb.sum/1000.0)
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
	fmt.Fprintf(&buf, "# HELP sse_subscriber_drops_total Events dropped for slow SSE subscribers\n")
	fmt.Fprintf(&buf, "# TYPE sse_subscriber_drops_total counter\n")
	fmt.Fprintf(&buf, "sse_subscriber_drops_total %d\n", s.subDropCnt.Load())
	if s.store != nil {
		archiveMetrics := s.store.ArchiveMetrics()
		fmt.Fprintf(&buf, "# HELP sqlite_archive_pending_events Events waiting to be archived to SQLite\n")
		fmt.Fprintf(&buf, "# TYPE sqlite_archive_pending_events gauge\n")
		fmt.Fprintf(&buf, "sqlite_archive_pending_events %d\n", archiveMetrics.Pending)
		fmt.Fprintf(&buf, "# HELP sqlite_archive_queue_capacity Maximum events held while waiting for SQLite\n")
		fmt.Fprintf(&buf, "# TYPE sqlite_archive_queue_capacity gauge\n")
		fmt.Fprintf(&buf, "sqlite_archive_queue_capacity %d\n", archiveMetrics.Capacity)
		fmt.Fprintf(&buf, "# HELP sqlite_archive_trigger_events Pending events that trigger an archive pass\n")
		fmt.Fprintf(&buf, "# TYPE sqlite_archive_trigger_events gauge\n")
		fmt.Fprintf(&buf, "sqlite_archive_trigger_events %d\n", archiveMetrics.Trigger)
		fmt.Fprintf(&buf, "# HELP sqlite_archive_write_batch_events Maximum events written per SQLite transaction\n")
		fmt.Fprintf(&buf, "# TYPE sqlite_archive_write_batch_events gauge\n")
		fmt.Fprintf(&buf, "sqlite_archive_write_batch_events %d\n", archiveMetrics.WriteBatch)
		fmt.Fprintf(&buf, "# HELP sqlite_archive_dropped_events_total Events dropped after the SQLite archive queue reached its hard limit\n")
		fmt.Fprintf(&buf, "# TYPE sqlite_archive_dropped_events_total counter\n")
		fmt.Fprintf(&buf, "sqlite_archive_dropped_events_total %d\n", archiveMetrics.Dropped)
	}

	fmt.Fprintf(&buf, "# HELP http_requests_total HTTP requests by method and status\n")
	fmt.Fprintf(&buf, "# TYPE http_requests_total counter\n")
	var requestCount int64
	m.httpRequests.Range(func(key, value interface{}) bool {
		parts := strings.SplitN(fmt.Sprint(key), " ", 2)
		if len(parts) == 2 {
			count := value.(*atomic.Int64).Load()
			requestCount += count
			fmt.Fprintf(&buf, "http_requests_total{method=\"%s\",status=\"%s\"} %d\n", escapePrometheusLabel(parts[0]), escapePrometheusLabel(parts[1]), count)
		}
		return true
	})
	fmt.Fprintf(&buf, "# HELP http_request_duration_seconds_sum Total HTTP request duration\n")
	fmt.Fprintf(&buf, "# TYPE http_request_duration_seconds_sum counter\n")
	fmt.Fprintf(&buf, "http_request_duration_seconds_sum %f\n", float64(m.httpDurationNanos.Load())/float64(time.Second))
	fmt.Fprintf(&buf, "# HELP http_request_duration_seconds_count Total timed HTTP requests\n")
	fmt.Fprintf(&buf, "# TYPE http_request_duration_seconds_count counter\n")
	fmt.Fprintf(&buf, "http_request_duration_seconds_count %d\n", requestCount)

	// Filter engine metrics
	if eng := s.getFilter(); eng != nil {
		blocked, allowed := eng.Stats()
		fmt.Fprintf(&buf, "# HELP filter_blocked_total Queries blocked by the filter engine\n")
		fmt.Fprintf(&buf, "# TYPE filter_blocked_total counter\n")
		fmt.Fprintf(&buf, "filter_blocked_total %d\n", blocked)
		fmt.Fprintf(&buf, "# HELP filter_allowed_total Queries allowed by filter exception rules\n")
		fmt.Fprintf(&buf, "# TYPE filter_allowed_total counter\n")
		fmt.Fprintf(&buf, "filter_allowed_total %d\n", allowed)
		fmt.Fprintf(&buf, "# HELP filter_rules_total Loaded filter rules per source\n")
		fmt.Fprintf(&buf, "# TYPE filter_rules_total gauge\n")
		for _, src := range eng.Sources() {
			label := escapePrometheusLabel(src.Name)
			kind := escapePrometheusLabel(src.Kind)
			fmt.Fprintf(&buf, "filter_rules_total{source=\"%s\",kind=\"%s\",type=\"block\"} %d\n", label, kind, src.RuleCount)
			fmt.Fprintf(&buf, "filter_rules_total{source=\"%s\",kind=\"%s\",type=\"allow\"} %d\n", label, kind, src.AllowRuleCount)
		}
		fmt.Fprintf(&buf, "# HELP filter_paused Whether filtering is currently paused (1) or active (0)\n")
		fmt.Fprintf(&buf, "# TYPE filter_paused gauge\n")
		paused := 0
		if eng.Paused() {
			paused = 1
		}
		fmt.Fprintf(&buf, "filter_paused %d\n", paused)
	}

	// DNS pipeline counters (rewrites / safe-search / bogus-NXDOMAIN)
	if dnsSrv := s.getDNSServer(); dnsSrv != nil {
		rewriteHits, safeSearchHits, bogusNXHits := dnsSrv.Stats()
		fmt.Fprintf(&buf, "# HELP rewrites_hits_total Queries answered by typed rewrites\n")
		fmt.Fprintf(&buf, "# TYPE rewrites_hits_total counter\n")
		fmt.Fprintf(&buf, "rewrites_hits_total %d\n", rewriteHits)
		fmt.Fprintf(&buf, "# HELP safesearch_hits_total Queries rewritten by safe search\n")
		fmt.Fprintf(&buf, "# TYPE safesearch_hits_total counter\n")
		fmt.Fprintf(&buf, "safesearch_hits_total %d\n", safeSearchHits)
		fmt.Fprintf(&buf, "# HELP bogus_nxdomain_total Upstream answers converted to NXDOMAIN (bogus ranges)\n")
		fmt.Fprintf(&buf, "# TYPE bogus_nxdomain_total counter\n")
		fmt.Fprintf(&buf, "bogus_nxdomain_total %d\n", bogusNXHits)

		fmt.Fprintf(&buf, "# HELP dns_ratelimit_dropped_total Queries refused by the per-subnet rate limiter\n")
		fmt.Fprintf(&buf, "# TYPE dns_ratelimit_dropped_total counter\n")
		fmt.Fprintf(&buf, "dns_ratelimit_dropped_total %d\n", dnsSrv.RateLimitDropped())
		aclDropped, aclRefused, rateBuckets := dnsSrv.ACLStats()
		fmt.Fprintf(&buf, "# HELP dns_acl_dropped_total Queries silently dropped by the DNS deny ACL\n")
		fmt.Fprintf(&buf, "# TYPE dns_acl_dropped_total counter\n")
		fmt.Fprintf(&buf, "dns_acl_dropped_total %d\n", aclDropped)
		fmt.Fprintf(&buf, "# HELP dns_acl_refused_total Queries refused by the DNS allow ACL\n")
		fmt.Fprintf(&buf, "# TYPE dns_acl_refused_total counter\n")
		fmt.Fprintf(&buf, "dns_acl_refused_total %d\n", aclRefused)
		fmt.Fprintf(&buf, "# HELP dns_ratelimit_buckets Active per-subnet rate-limit buckets\n")
		fmt.Fprintf(&buf, "# TYPE dns_ratelimit_buckets gauge\n")
		fmt.Fprintf(&buf, "dns_ratelimit_buckets %d\n", rateBuckets)

		cacheStats := dnsSrv.CacheStats()
		fmt.Fprintf(&buf, "# HELP dns_cache_entries Current cache entries\n# TYPE dns_cache_entries gauge\ndns_cache_entries %d\n", cacheStats.Entries)
		fmt.Fprintf(&buf, "# HELP dns_cache_capacity Maximum cache entries\n# TYPE dns_cache_capacity gauge\ndns_cache_capacity %d\n", cacheStats.Capacity)
		fmt.Fprintf(&buf, "# HELP dns_cache_stale_hits_total Optimistic stale responses served\n# TYPE dns_cache_stale_hits_total counter\ndns_cache_stale_hits_total %d\n", cacheStats.StaleHits)
		fmt.Fprintf(&buf, "# HELP dns_cache_evictions_total LRU cache evictions\n# TYPE dns_cache_evictions_total counter\ndns_cache_evictions_total %d\n", cacheStats.Evictions)
		fmt.Fprintf(&buf, "# HELP dns_cache_cleared_entries_total Entries removed by cache clears\n# TYPE dns_cache_cleared_entries_total counter\ndns_cache_cleared_entries_total %d\n", cacheStats.Cleared)
		fmt.Fprintf(&buf, "# HELP dns_cache_refreshes_total Successful optimistic cache refreshes\n# TYPE dns_cache_refreshes_total counter\ndns_cache_refreshes_total %d\n", cacheStats.Refreshes)

		fmt.Fprintf(&buf, "# HELP blocked_service_hits_total Queries blocked per blocked-service ID\n")
		fmt.Fprintf(&buf, "# TYPE blocked_service_hits_total counter\n")
		for id, count := range dnsSrv.ServiceStats() {
			fmt.Fprintf(&buf, "blocked_service_hits_total{service=\"%s\"} %d\n", escapePrometheusLabel(id), count)
		}
	}

	s.fieldsMu.RLock()
	pool := s.upstreamPool
	fwd := s.forwarder
	s.fieldsMu.RUnlock()
	if pool != nil {
		fmt.Fprintf(&buf, "# HELP dns_upstream_requests_total Upstream requests by result\n# TYPE dns_upstream_requests_total counter\n")
		fmt.Fprintf(&buf, "# HELP dns_upstream_ewma_seconds Upstream latency EWMA\n# TYPE dns_upstream_ewma_seconds gauge\n")
		fmt.Fprintf(&buf, "# HELP dns_upstream_healthy Upstream health state\n# TYPE dns_upstream_healthy gauge\n")
		for _, stat := range pool.StatsSnapshot() {
			label := escapePrometheusLabel(stat.Spec)
			fmt.Fprintf(&buf, "dns_upstream_requests_total{upstream=\"%s\",result=\"success\"} %d\n", label, stat.Successes)
			fmt.Fprintf(&buf, "dns_upstream_requests_total{upstream=\"%s\",result=\"failure\"} %d\n", label, stat.Failures)
			fmt.Fprintf(&buf, "dns_upstream_ewma_seconds{upstream=\"%s\"} %f\n", label, stat.EWMAms/1000)
			healthy := 0
			if stat.Healthy {
				healthy = 1
			}
			fmt.Fprintf(&buf, "dns_upstream_healthy{upstream=\"%s\"} %d\n", label, healthy)
		}
	}
	if fwd != nil {
		backlog, backlogBytes, retries, dropped, sent := fwd.Stats()
		fmt.Fprintf(&buf, "# HELP forwarder_backlog_events Events waiting for controller delivery\n# TYPE forwarder_backlog_events gauge\nforwarder_backlog_events %d\n", backlog)
		fmt.Fprintf(&buf, "# HELP forwarder_backlog_bytes Bytes waiting for controller delivery\n# TYPE forwarder_backlog_bytes gauge\nforwarder_backlog_bytes %d\n", backlogBytes)
		fmt.Fprintf(&buf, "# HELP forwarder_retries_total Controller delivery retries\n# TYPE forwarder_retries_total counter\nforwarder_retries_total %d\n", retries)
		fmt.Fprintf(&buf, "# HELP forwarder_dropped_events_total Events dropped by forwarding limits or permanent errors\n# TYPE forwarder_dropped_events_total counter\nforwarder_dropped_events_total %d\n", dropped)
		fmt.Fprintf(&buf, "# HELP forwarder_sent_events_total Events delivered to the controller\n# TYPE forwarder_sent_events_total counter\nforwarder_sent_events_total %d\n", sent)
	}

	_, _ = buf.WriteTo(w)
}

func escapePrometheusLabel(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, "\n", `\n`)
	return strings.ReplaceAll(value, `"`, `\"`)
}

func (s *Server) internalAuth(next http.Handler) http.Handler {
	if s.cfg.IngestSecret != "" {
		return next
	}
	if s.cfg.WebUsername == "" || s.cfg.WebPassword == "" {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "Internal API authentication is not configured", http.StatusServiceUnavailable)
		})
	}
	return s.authMiddleware(next)
}

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// If no auth is configured, allow all
		if s.cfg.WebUsername == "" && s.cfg.WebPassword == "" {
			next.ServeHTTP(w, r)
			return
		}
		if s.cfg.WebUsername == "" || s.cfg.WebPassword == "" {
			http.Error(w, "Web authentication is misconfigured", http.StatusServiceUnavailable)
			return
		}
		if !s.isHTTPS(r) {
			http.Error(w, "HTTPS is required for web authentication", http.StatusUpgradeRequired)
			return
		}

		// Check for session cookie
		cookie, err := r.Cookie(sessionCookieName)
		if err == nil && s.validSession(cookie.Value) {
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
	if !s.isHTTPS(r) {
		http.Error(w, "HTTPS is required for web authentication", http.StatusUpgradeRequired)
		return
	}

	nonce := ""
	if s.nonceFromCtx != nil {
		nonce = s.nonceFromCtx(r.Context())
	}

	if r.Method == http.MethodGet {
		// Generate CSRF token
		csrfToken, err := generateCSRFToken()
		if err != nil {
			log.Printf("CSRF token generation error: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		http.SetCookie(w, s.newSecureCookie(csrfCookieName, csrfToken, int(sessionLifetime.Seconds())))

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
		ip := s.clientIP(r)
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
			sessionToken, err := s.newSession()
			if err != nil {
				log.Printf("Session token generation error: %v", err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}
			// Successful login — reset rate limiter for this IP
			s.resetRateLimit(ip)

			http.SetCookie(w, s.newSecureCookie(sessionCookieName, sessionToken, int(sessionLifetime.Seconds())))
			http.Redirect(w, r, s.cfg.BaseURL+"/", http.StatusSeeOther)
			return
		}

		// Failed login — record for rate limiting
		s.recordFailedLogin(ip)
		csrfToken, err := generateCSRFToken()
		if err != nil {
			log.Printf("CSRF token generation error: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		http.SetCookie(w, s.newSecureCookie(csrfCookieName, csrfToken, int(sessionLifetime.Seconds())))

		if err := s.tmpl.ExecuteTemplate(w, "login.html", map[string]interface{}{
			"Error":     "Invalid username or password",
			"Nonce":     nonce,
			"CSRFToken": csrfToken,
			"BaseURL":   s.cfg.BaseURL,
		}); err != nil {
			log.Printf("Template execution error: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
	}
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	csrfCookie, err := r.Cookie(csrfCookieName)
	if err != nil || subtle.ConstantTimeCompare([]byte(csrfCookie.Value), []byte(r.FormValue("csrf_token"))) != 1 {
		http.Error(w, apperr.NewErrCSRFMismatch("invalid CSRF token", err).Error(), http.StatusForbidden)
		return
	}
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		s.deleteSession(cookie.Value)
	}
	http.SetCookie(w, s.newSecureCookie(sessionCookieName, "", -1))
	// Also clear the CSRF cookie
	http.SetCookie(w, s.newSecureCookie(csrfCookieName, "", -1))
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

	body, err := readRequestBody(w, r, s.cfg.MaxRequestSize)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
		} else {
			http.Error(w, apperr.NewErrParseFailed("bad request", err).Error(), http.StatusBadRequest)
		}
		return
	}

	// New format: a top-level JSON array of QueryEvent (structured events
	// from dnsserver-based agents). Legacy format: an object with raw dnsmasq
	// log lines parsed via internal/parser.
	if bytes.HasPrefix(bytes.TrimSpace(body), []byte("[")) {
		s.handleIngestEvents(w, r, body)
		return
	}

	var payload struct {
		Node   string             `json:"node"`
		Line   string             `json:"line"`
		Batch  []string           `json:"batch"`
		Health map[string]float64 `json:"health,omitempty"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
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

	// Item 88: Update node status from version headers on ingest, merging the
	// header-derived fields into the existing status so heartbeat-provided
	// values (MemoryMB, Goroutines, DBSizeMB, UpstreamHealth) are preserved.
	if payload.Node != "" {
		status := models.NodeStatus{Name: payload.Node}
		if existing := s.store.GetNodeStatus(payload.Node); existing != nil {
			status = *existing
		}
		if v := r.Header.Get("X-Node-Version"); v != "" {
			status.Version = v
		}
		if v := r.Header.Get("X-Go-Version"); v != "" {
			status.GoVersion = v
		}
		if v := r.Header.Get("X-Node-Build"); v != "" {
			status.BuildInfo = v
		}
		s.store.SetNodeStatus(payload.Node, status)
	}

	w.WriteHeader(http.StatusNoContent)
}

func readRequestBody(w http.ResponseWriter, r *http.Request, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		maxBytes = config.DefaultMaxRequestSize
	}
	compressed := http.MaxBytesReader(w, r.Body, maxBytes)
	var reader io.Reader = compressed
	var gzReader *gzip.Reader
	if strings.EqualFold(strings.TrimSpace(r.Header.Get("Content-Encoding")), "gzip") {
		var err error
		gzReader, err = gzip.NewReader(compressed)
		if err != nil {
			return nil, fmt.Errorf("gzip reader: %w", err)
		}
		defer func() { _ = gzReader.Close() }()
		reader = gzReader
	}
	data, err := io.ReadAll(io.LimitReader(reader, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, &http.MaxBytesError{Limit: maxBytes}
	}
	return data, nil
}

// handleIngestEvents processes the new ingest format: a top-level JSON array
// of models.QueryEvent produced by dnsserver-based agents. Node status is
// updated from the X-Node-* headers as with legacy payloads.
func (s *Server) handleIngestEvents(w http.ResponseWriter, r *http.Request, body []byte) {
	var events []models.QueryEvent
	if err := json.Unmarshal(body, &events); err != nil {
		http.Error(w, apperr.NewErrParseFailed("invalid events payload", err).Error(), http.StatusBadRequest)
		return
	}
	if len(events) > 100 {
		http.Error(w, "Batch too large (max 100)", http.StatusRequestEntityTooLarge)
		return
	}

	node := ""
	now := time.Now()
	maxUnixTime := now.Add(maxIngestFutureSkew).Unix()
	for i := range events {
		if events[i].UnixTime <= 0 || events[i].UnixTime > maxUnixTime {
			events[i].UnixTime = now.Unix()
		}
		if node == "" {
			node = events[i].Node
		}
		s.store.AddEvent(events[i])
		s.BroadcastEvent(events[i])
	}

	// Item 88: Update node status from version headers on ingest, merging the
	// header-derived fields into the existing status so heartbeat-provided
	// values (MemoryMB, Goroutines, DBSizeMB, UpstreamHealth) are preserved.
	if node != "" {
		status := models.NodeStatus{Name: node}
		if existing := s.store.GetNodeStatus(node); existing != nil {
			status = *existing
		}
		if v := r.Header.Get("X-Node-Version"); v != "" {
			status.Version = v
		}
		if v := r.Header.Get("X-Go-Version"); v != "" {
			status.GoVersion = v
		}
		if v := r.Header.Get("X-Node-Build"); v != "" {
			status.BuildInfo = v
		}
		s.store.SetNodeStatus(node, status)
	}

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	nonce := ""
	if s.nonceFromCtx != nil {
		nonce = s.nonceFromCtx(r.Context())
	}

	csrfToken := ""
	if cookie, err := r.Cookie(csrfCookieName); err == nil {
		csrfToken = cookie.Value
	}
	var buf bytes.Buffer
	if err := s.tmpl.ExecuteTemplate(&buf, "index.html", map[string]interface{}{
		"Nonce":     nonce,
		"BaseURL":   s.cfg.BaseURL,
		"Mode":      s.cfg.Mode,
		"CSRFToken": csrfToken,
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
		var err error
		since, err = strconv.ParseInt(sinceStr, 10, 64)
		if err != nil || since < 0 {
			http.Error(w, "invalid since parameter", http.StatusBadRequest)
			return
		}
	}
	cursor := r.URL.Query().Get("cursor")
	if cursor != "" {
		if _, err := strconv.ParseUint(cursor, 10, 64); err != nil {
			http.Error(w, "invalid cursor parameter", http.StatusBadRequest)
			return
		}
	}
	limit := config.DefaultScanLimit
	if rawLimit := r.URL.Query().Get("limit"); rawLimit != "" {
		parsed, err := strconv.Atoi(rawLimit)
		if err != nil || parsed < 1 || parsed > config.DefaultScanLimit {
			http.Error(w, fmt.Sprintf("limit must be between 1 and %d", config.DefaultScanLimit), http.StatusBadRequest)
			return
		}
		limit = parsed
	}
	var result []models.QueryEvent
	if cursor == "" {
		result = s.store.GetRecentEvents(since)
		if len(result) > limit {
			result = result[:limit]
		}
	} else {
		result = s.store.GetEventsAfter(cursor, since, limit)
	}
	if len(result) > 0 {
		maxID := uint64(0)
		for _, event := range result {
			id, _ := strconv.ParseUint(event.ID, 10, 64)
			if id > maxID {
				maxID = id
			}
		}
		w.Header().Set("X-Next-Cursor", strconv.FormatUint(maxID, 10))
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}

func (s *Server) statsResponse() ([]byte, error) {
	s.statsCacheMu.Lock()
	defer s.statsCacheMu.Unlock()

	now := time.Now()
	cacheAge := now.Sub(s.statsCacheAt)
	if len(s.statsCacheBody) > 0 && cacheAge >= 0 && cacheAge < statsResponseTTL {
		return s.statsCacheBody, nil
	}

	body, err := json.Marshal(s.store.GetStats())
	if err != nil {
		return nil, fmt.Errorf("encode stats response: %w", err)
	}
	s.statsCacheBody = body
	s.statsCacheAt = now
	return body, nil
}

func (s *Server) handleStats(w http.ResponseWriter, _ *http.Request) {
	body, err := s.statsResponse()
	if err != nil {
		log.Printf("Stats response error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(body)
}

func (s *Server) handleClientStats(w http.ResponseWriter, r *http.Request) {
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
	if _, ok := dns.IsDomainName(domain); !ok {
		http.Error(w, "invalid domain", http.StatusBadRequest)
		return
	}
	dnsSrv := s.getDNSServer()
	if dnsSrv == nil {
		http.Error(w, "DNS server unavailable", http.StatusServiceUnavailable)
		return
	}
	res := make([]string, 0, 4)
	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		req := new(dns.Msg)
		req.SetQuestion(dns.Fqdn(domain), qtype)
		resp, drop := dnsSrv.Resolve(req, s.clientIP(r))
		if drop || resp == nil || resp.Rcode != dns.RcodeSuccess {
			continue
		}
		for _, answer := range resp.Answer {
			switch record := answer.(type) {
			case *dns.A:
				res = append(res, record.A.String())
			case *dns.AAAA:
				res = append(res, record.AAAA.String())
			}
		}
	}
	if len(res) == 0 {
		w.WriteHeader(http.StatusBadGateway)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "error", "error": "no address records"})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "success", "ips": res})
}

func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	lastID := strings.TrimSpace(r.Header.Get("Last-Event-ID"))
	if lastID != "" {
		if _, err := strconv.ParseUint(lastID, 10, 64); err != nil {
			http.Error(w, "invalid Last-Event-ID", http.StatusBadRequest)
			return
		}
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	// Clear the HTTP server write deadline: SSE is a long-lived response and
	// would otherwise be cut off by the server's WriteTimeout.
	if err := http.NewResponseController(w).SetWriteDeadline(time.Time{}); err != nil {
		log.Printf("[WARN] SSE: unable to clear write deadline: %v", err)
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	_, _ = fmt.Fprint(w, "retry: 3000\n\n")

	ch := s.Subscribe()

	defer func() {
		s.Unsubscribe(ch)
	}()

	if lastID != "" {
		for _, event := range s.store.GetEventsAfter(lastID, 0, config.DefaultScanLimit) {
			data, _ := json.Marshal(event)
			_, _ = fmt.Fprintf(w, "id: %s\ndata: %s\n\n", event.ID, data)
			lastID = event.ID
		}
		flusher.Flush()
	}

	notify := r.Context().Done()
	keepalive := s.cfg.SSEKeepaliveInterval
	if keepalive <= 0 {
		keepalive = config.DefaultSSEKeepaliveInterval
	}
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
			if lastID != "" {
				last, _ := strconv.ParseUint(lastID, 10, 64)
				current, _ := strconv.ParseUint(ev.ID, 10, 64)
				if current <= last {
					continue
				}
			}
			data, _ := json.Marshal(ev)
			_, _ = fmt.Fprintf(w, "id: %s\ndata: %s\n\n", ev.ID, data)
			lastID = ev.ID
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

// ===== Filter Engine Endpoints =====

// handleFilteringStatus reports the filter engine state: enabled/paused,
// per-source rule counts, and last update times.
func (s *Server) handleFilteringStatus(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	eng := s.getFilter()
	if eng == nil {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"enabled": true,
			"sources": []interface{}{},
		})
		return
	}
	blocked, allowed := eng.Stats()
	resp := map[string]interface{}{
		"enabled":              !eng.Paused(),
		"sources":              eng.Sources(),
		"filter_blocked_total": blocked,
		"filter_allowed_total": allowed,
	}
	if until := eng.PausedUntil(); !until.IsZero() {
		resp["paused_until"] = until.Format(time.RFC3339)
	}
	_ = json.NewEncoder(w).Encode(resp)
}

// handleFilteringPause pauses protection for N minutes (POST {"minutes": n});
// minutes <= 0 resumes immediately.
func (s *Server) handleFilteringPause(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireController(w) {
		return
	}
	if !s.checkCSRF(w, r) {
		return
	}
	eng := s.getFilter()
	if eng == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "filter engine is not configured",
		})
		return
	}

	var req struct {
		Minutes int `json:"minutes"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	eng.Pause(req.Minutes)

	resp := map[string]interface{}{"status": "ok", "enabled": !eng.Paused()}
	if until := eng.PausedUntil(); !until.IsZero() {
		resp["paused_until"] = until.Format(time.RFC3339)
	}
	_ = json.NewEncoder(w).Encode(resp)
}

// ===== Typed Rewrites CRUD =====

// handleRewrites dispatches GET (list), POST (add), and DELETE (?id=) for
// typed DNS rewrites. Changes take effect live in the DNS pipeline.
func (s *Server) handleRewrites(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet && !s.requireController(w) {
		return
	}
	s.fieldsMu.RLock()
	store := s.rewritesStore
	s.fieldsMu.RUnlock()
	if store == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "rewrites store is not configured",
		})
		return
	}

	switch r.Method {
	case http.MethodGet:
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":   "ok",
			"rewrites": store.List(),
		})
	case http.MethodPost:
		if !s.checkCSRF(w, r) {
			return
		}
		var req struct {
			Domain      string   `json:"domain"`
			Type        string   `json:"type"`
			Value       string   `json:"value"`
			SourceCIDRs []string `json:"source_cidrs"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		rw, err := store.Add(req.Domain, req.Type, req.Value, req.SourceCIDRs...)
		if err != nil {
			http.Error(w, fmt.Sprintf("Invalid rewrite: %v", err), http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok", "rewrite": rw})
	case http.MethodDelete:
		if !s.checkCSRF(w, r) {
			return
		}
		id := r.URL.Query().Get("id")
		if id == "" {
			http.Error(w, "Missing id parameter", http.StatusBadRequest)
			return
		}
		found, err := store.Delete(id)
		if err != nil {
			http.Error(w, "Failed to delete rewrite", http.StatusInternalServerError)
			return
		}
		if !found {
			http.Error(w, "Rewrite not found", http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok"})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// ===== Per-Client Registry CRUD =====

// handleClients dispatches GET (list), POST (add), PUT (update), and
// DELETE (?name=) for the per-client registry. Changes take effect live.
func (s *Server) handleClients(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet && !s.requireController(w) {
		return
	}
	s.fieldsMu.RLock()
	reg := s.clientsRegistry
	s.fieldsMu.RUnlock()
	if reg == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "clients registry is not configured",
		})
		return
	}

	switch r.Method {
	case http.MethodGet:
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "ok",
			"clients": reg.List(),
		})
	case http.MethodPost, http.MethodPut:
		if !s.checkCSRF(w, r) {
			return
		}
		var c clients.Client
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256*1024)).Decode(&c); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		if strings.TrimSpace(c.Name) == "" || len(c.IDs) == 0 {
			http.Error(w, "Client requires a name and at least one ID (IP or CIDR)", http.StatusBadRequest)
			return
		}
		var err error
		if r.Method == http.MethodPost {
			err = reg.Add(c)
		} else {
			err = reg.Update(c)
		}
		if err != nil {
			http.Error(w, fmt.Sprintf("Invalid client: %v", err), http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok"})
	case http.MethodDelete:
		if !s.checkCSRF(w, r) {
			return
		}
		name := r.URL.Query().Get("name")
		if name == "" {
			http.Error(w, "Missing name parameter", http.StatusBadRequest)
			return
		}
		if !reg.Delete(name) {
			http.Error(w, "Client not found", http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok"})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleServices returns the blocked-service catalog, global enablement, and
// live hit counts for the settings UI.
func (s *Server) handleServices(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	enabled := make(map[string]bool)
	for _, id := range strings.FieldsFunc(s.cfg.BlockedServices, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	}) {
		enabled[strings.ToLower(id)] = true
	}
	hits := make(map[string]int64)
	if dnsSrv := s.getDNSServer(); dnsSrv != nil {
		hits = dnsSrv.ServiceStats()
	}
	type serviceStatus struct {
		ID      string `json:"id"`
		Enabled bool   `json:"enabled"`
		Hits    int64  `json:"hits"`
	}
	services := make([]serviceStatus, 0, len(policy.ServiceIDs()))
	for _, id := range policy.ServiceIDs() {
		services = append(services, serviceStatus{ID: id, Enabled: enabled[id], Hits: hits[id]})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok", "services": services})
}

// ===== Query-Log Block/Unblock Actions =====

// userRulesPath returns the filter user-rules file managed by the
// query-log actions (a plain file source of the filter engine).
func (s *Server) userRulesPath() string {
	return filepath.Join(s.cfg.HistoryDir, "user_rules.txt")
}

// handleQuerylogAction adds a block rule (block=true) or removes it / adds
// an exception (block=false) for a domain, then reloads the user-rules
// source so the change takes effect immediately.
func (s *Server) handleQuerylogAction(w http.ResponseWriter, r *http.Request, block bool) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireController(w) {
		return
	}
	if !s.checkCSRF(w, r) {
		return
	}
	eng := s.getFilter()
	if eng == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "filter engine is not configured",
		})
		return
	}

	var req struct {
		Domain string `json:"domain"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	domain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(req.Domain), "."))
	_, validDomain := dns.IsDomainName(domain)
	invalidCharacter := strings.IndexFunc(domain, func(r rune) bool {
		letter := r >= 'a' && r <= 'z'
		digit := r >= '0' && r <= '9'
		return !letter && !digit && r != '-' && r != '.'
	}) >= 0
	if domain == "" || !strings.Contains(domain, ".") || !validDomain || invalidCharacter {
		http.Error(w, "Invalid domain", http.StatusBadRequest)
		return
	}

	path := s.userRulesPath()
	blockRule := "||" + domain + "^"
	exceptRule := "@@||" + domain + "^"

	userRulesMu.Lock()
	defer userRulesMu.Unlock()

	var action, rule string
	if block {
		// Blocking: drop any stale exception and add the block rule.
		if _, err := modifyUserRuleLocked(path, exceptRule, true); err != nil {
			http.Error(w, "Failed to update user rules: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if _, err := modifyUserRuleLocked(path, blockRule, false); err != nil {
			http.Error(w, "Failed to update user rules: "+err.Error(), http.StatusInternalServerError)
			return
		}
		action, rule = "blocked", blockRule
	} else {
		// Unblocking: remove the user block rule when it came from this
		// file; otherwise add an exception rule.
		removed, err := modifyUserRuleLocked(path, blockRule, true)
		if err != nil {
			http.Error(w, "Failed to update user rules: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if removed {
			action, rule = "unblocked", blockRule
		} else {
			if _, err := modifyUserRuleLocked(path, exceptRule, false); err != nil {
				http.Error(w, "Failed to update user rules: "+err.Error(), http.StatusInternalServerError)
				return
			}
			action, rule = "exception_added", exceptRule
		}
	}
	eng.ReloadSource(path)

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "ok",
		"action": action,
		"rule":   rule,
	})
}

// modifyUserRule adds or removes an exact rule line in the user rules file.
// It returns whether the file changed.
func modifyUserRule(path, ruleLine string, remove bool) (bool, error) {
	userRulesMu.Lock()
	defer userRulesMu.Unlock()
	return modifyUserRuleLocked(path, ruleLine, remove)
}

func modifyUserRuleLocked(path, ruleLine string, remove bool) (bool, error) {
	data, err := os.ReadFile(path) // #nosec G304 G703 -- path derived from trusted HistoryDir config plus a constant filename, not request input
	if err != nil && !os.IsNotExist(err) {
		return false, err
	}

	var out []string
	found := false
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == ruleLine {
			found = true
			if remove {
				continue
			}
		}
		if trimmed == "" && len(out) == 0 {
			continue // skip leading empties
		}
		out = append(out, line)
	}

	changed := false
	switch {
	case remove && found:
		changed = true
	case !remove && !found:
		out = append(out, ruleLine)
		changed = true
	}
	if !changed {
		return false, nil
	}
	content := strings.Join(out, "\n")
	if !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	if err := writeFileAtomic(path, []byte(content), 0o600); err != nil {
		return false, err
	}
	return true, nil
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) (err error) {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".api-*.tmp") // #nosec G304 -- directory is trusted application configuration
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = tmp.Close()
		if err != nil {
			_ = os.Remove(tmpPath)
		}
	}()
	if err = tmp.Chmod(mode); err != nil {
		return err
	}
	if _, err = tmp.Write(data); err != nil {
		return err
	}
	if err = tmp.Sync(); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
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
	_ = json.NewEncoder(w).Encode(s.configuredUpstreams())
}

func (s *Server) handleUpstreamSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"upstreams":         s.configuredUpstreams(),
			"bootstrap_servers": s.configuredBootstrapServers(),
		})
	case http.MethodPost:
		if !s.requireController(w) || !s.checkCSRF(w, r) {
			return
		}
		var request struct {
			Upstreams        []string `json:"upstreams"`
			BootstrapServers []string `json:"bootstrap_servers"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&request); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}
		upstreams, err := validateUpstreamList(request.Upstreams)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		bootstrapServers := compactStrings(request.BootstrapServers)
		if err := upstream.ValidateBootstrapServers(bootstrapServers); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := s.saveUpstreamSettings(upstreams, bootstrapServers); err != nil {
			http.Error(w, "Failed to save upstream settings", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":            "ok",
			"upstreams":         upstreams,
			"bootstrap_servers": bootstrapServers,
		})
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func compactStrings(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			result = append(result, value)
		}
	}
	return result
}

func validateUpstreamList(values []string) ([]string, error) {
	upstreams := compactStrings(values)
	if len(upstreams) == 0 {
		return nil, errors.New("at least one upstream resolver is required")
	}
	for index, address := range upstreams {
		if _, err := upstream.Parse(address); err != nil {
			return nil, fmt.Errorf("upstream resolver %d is invalid: %w", index+1, err)
		}
	}
	return upstreams, nil
}

func (s *Server) saveUpstreamSettings(upstreams, bootstrapServers []string) error {
	path := s.cfg.FullUpstreamsPath()
	if path == "" {
		return errors.New("upstreams file not configured")
	}
	if err := dnsroutes.SaveUpstreamSettings(path, dnsroutes.UpstreamSettings{
		Upstreams:           upstreams,
		BootstrapServers:    bootstrapServers,
		BootstrapConfigured: true,
	}); err != nil {
		return err
	}
	s.fieldsMu.RLock()
	reload := s.upstreamReloadFn
	s.fieldsMu.RUnlock()
	if reload != nil {
		reload()
	}
	return nil
}

func (s *Server) handlePostUpstreams(w http.ResponseWriter, r *http.Request) {
	if !s.requireController(w) {
		return
	}
	if !s.checkCSRF(w, r) {
		return
	}
	var req []struct {
		Address string `json:"address"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&req); err != nil {
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
		if _, err := upstream.Parse(addr); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"error": "Invalid upstream specification",
				"input": addr,
			})
			return
		}
		upstreams = append(upstreams, addr)
	}
	if len(upstreams) == 0 {
		http.Error(w, "At least one upstream resolver is required", http.StatusBadRequest)
		return
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

	// Reload the upstream pool so changes take effect immediately.
	s.fieldsMu.RLock()
	reload := s.upstreamReloadFn
	s.fieldsMu.RUnlock()
	if reload != nil {
		reload()
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "ok",
		"upstreams": upstreams,
	})
}

// ===== Item 63: Cache Clear Endpoint =====
func (s *Server) handleCacheClear(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.checkCSRF(w, r) {
		return
	}
	dnsSrv := s.getDNSServer()
	if dnsSrv == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"message": "DNS server is not configured",
		})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "ok",
		"cleared": dnsSrv.ClearCache(),
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
	if !s.requireController(w) {
		return
	}
	if !s.checkCSRF(w, r) {
		return
	}
	var routesMap map[string]string
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&routesMap); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	for pattern, raw := range routesMap {
		if strings.TrimSpace(pattern) == "" {
			http.Error(w, "DNS route pattern may not be empty", http.StatusBadRequest)
			return
		}
		if _, err := upstream.Parse(raw); err != nil {
			http.Error(w, "DNS route contains an invalid upstream", http.StatusBadRequest)
			return
		}
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
// handleHeartbeat processes heartbeat messages from agent nodes.
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

	body, err := readRequestBody(w, r, s.cfg.MaxRequestSize)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
		} else {
			http.Error(w, "invalid payload", http.StatusBadRequest)
		}
		return
	}
	var hb models.HeartbeatPayload
	if err := json.Unmarshal(body, &hb); err != nil {
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
		ConfigRevision: hb.ConfigRevision,
	}
	s.store.SetNodeStatus(hb.Node, status)

	// Also store upstream health if provided
	if len(hb.Health) > 0 {
		s.store.SetUpstreamHealth(hb.Node, hb.Health)
	}

	log.Printf("[INFO] Heartbeat received from node %s (v%s, %d goroutines, %.1fMB mem)", // #nosec G706 -- CR/LF stripped by sanitizeLogValue; gosec taint analysis cannot see through the helper
		sanitizeLogValue(hb.Node), sanitizeLogValue(hb.Version), hb.Goroutines, hb.MemoryMB)

	w.WriteHeader(http.StatusNoContent)
}

// ===== Item 90: Sync Client Aliases Endpoint =====
// handleSyncAliases returns the current client aliases configuration.
// Agents call this to sync their aliases with the controller.
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

	aliases := s.cfg.GetAllClientAliases()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(aliases)
}

// ===== Item 91: Sync DNS Routes Endpoint =====
// handleSyncDNSRoutes returns the current DNS routes configuration.
// Agents call this to sync their DNS routes with the controller.
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
// Agents call this to sync their upstream health view with the controller.
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

	log.Printf("Starting Advanced Web GUI on %s", server.Addr)
	err = server.Serve(ln)
	if ctx.Err() != nil {
		<-shutdownDone
	}
	return err
}

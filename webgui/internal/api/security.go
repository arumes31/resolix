package api

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"log"
	"math"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	apperr "github.com/arumes31/resolix/webgui/internal/errors"
)

// rateLimitEntry tracks failed login attempts for a single IP.
type rateLimitEntry struct {
	count    int
	lastSeen time.Time
}

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

// checkCSRF validates the CSRF token bound to the caller's live browser
// session. A token planted through a cookie alone is not sufficient: it must
// match the token issued with the session at login. Cross-site browser
// requests are rejected first, which is the only protection when web
// authentication is explicitly disabled and there is no session to bind to.
func (s *Server) checkCSRF(w http.ResponseWriter, r *http.Request) bool {
	if !s.sameOriginRequest(r) {
		http.Error(w, apperr.NewErrCSRFMismatch("cross-site request rejected", nil).Error(), http.StatusForbidden)
		return false
	}
	if !s.webAuthEnabled() {
		return true
	}
	expected := ""
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		expected, _ = s.sessionCSRFToken(cookie.Value)
	}
	if expected == "" {
		http.Error(w, apperr.NewErrCSRFMismatch("missing CSRF session", nil).Error(), http.StatusForbidden)
		return false
	}
	submitted := r.Header.Get("X-CSRF-Token")
	if submitted == "" {
		submitted = r.FormValue("csrf_token")
	}
	if subtle.ConstantTimeCompare([]byte(expected), []byte(submitted)) != 1 {
		http.Error(w, apperr.NewErrCSRFMismatch("invalid CSRF token", nil).Error(), http.StatusForbidden)
		return false
	}
	return true
}

// webAuthEnabled reports whether browser sessions protect the web interface.
func (s *Server) webAuthEnabled() bool {
	return s.cfg.WebUsername != "" || s.cfg.WebPassword != ""
}

// allowedHost reports whether the request's Host (and a trusted proxy's
// X-Forwarded-Host) names this deployment. It defeats DNS rebinding against
// credential-free dashboards: IP literals and localhost cannot be rebound, and
// any other hostname must be listed in WEB_ALLOWED_HOSTS.
func (s *Server) allowedHost(r *http.Request) bool {
	if !s.hostNameAllowed(r.Host) {
		return false
	}
	if s.isTrustedProxy(r) {
		if forwarded := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Host"), ",")[0]); forwarded != "" {
			return s.hostNameAllowed(forwarded)
		}
	}
	return true
}

func (s *Server) hostNameAllowed(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if name, _, err := net.SplitHostPort(host); err == nil {
		host = name
	}
	host = strings.TrimSuffix(strings.Trim(host, "[]"), ".")
	if host == "" {
		return false
	}
	if net.ParseIP(host) != nil || host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	for _, allowed := range s.cfg.AllowedHosts {
		if host == strings.TrimSuffix(allowed, ".") {
			return true
		}
	}
	return false
}

// sameOriginRequest reports whether a state-changing request may have come
// from this application's own pages. Browsers send Sec-Fetch-Site and Origin
// on cross-site requests; non-browser clients that send neither are allowed.
func (s *Server) sameOriginRequest(r *http.Request) bool {
	if site := strings.ToLower(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site"))); site != "" {
		return site == "same-origin" || site == "none"
	}
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return true
	}
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Host == "" {
		return false
	}
	host := r.Host
	if s.isTrustedProxy(r) {
		if forwarded := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Host"), ",")[0]); forwarded != "" {
			host = forwarded
		}
	}
	return strings.EqualFold(parsed.Host, host)
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

func (s *Server) cookiePath() string {
	if s.cfg.BaseURL == "" {
		return "/"
	}
	return s.cfg.BaseURL
}

// sessionEntry tracks the absolute expiry and last activity of a session and
// the CSRF token bound to it.
type sessionEntry struct {
	expires  time.Time
	lastSeen time.Time
	csrf     string
}

func (e sessionEntry) expired(now time.Time) bool {
	return !e.expires.After(now) || now.Sub(e.lastSeen) >= sessionIdleTimeout
}

func (s *Server) newSession() (string, error) {
	tokenBytes := make([]byte, sessionTokenBytes)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", fmt.Errorf("generate session token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)
	csrf, err := generateCSRFToken()
	if err != nil {
		return "", err
	}
	now := time.Now()
	s.sessionMu.Lock()
	for existing, entry := range s.sessions {
		if entry.expired(now) {
			delete(s.sessions, existing)
		}
	}
	// Bound memory: evict the least recently used session when full.
	for len(s.sessions) >= maxSessions {
		oldest := ""
		for existing, entry := range s.sessions {
			if oldest == "" || entry.lastSeen.Before(s.sessions[oldest].lastSeen) {
				oldest = existing
			}
		}
		delete(s.sessions, oldest)
	}
	s.sessions[token] = sessionEntry{expires: now.Add(sessionLifetime), lastSeen: now, csrf: csrf}
	s.sessionMu.Unlock()
	return token, nil
}

// validSession reports whether token names a live session and refreshes its
// idle timer.
func (s *Server) validSession(token string) bool {
	now := time.Now()
	matched := ""
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()
	for existing, entry := range s.sessions {
		if entry.expired(now) {
			delete(s.sessions, existing)
			continue
		}
		if subtle.ConstantTimeCompare([]byte(existing), []byte(token)) == 1 {
			matched = existing
		}
	}
	if matched == "" {
		return false
	}
	entry := s.sessions[matched]
	entry.lastSeen = now
	s.sessions[matched] = entry
	return true
}

// lookupSessionLocked returns the live entry named by token without
// refreshing its idle timer. Callers must hold sessionMu.
func (s *Server) lookupSessionLocked(token string, now time.Time) (sessionEntry, bool) {
	var found sessionEntry
	ok := false
	for existing, entry := range s.sessions {
		if subtle.ConstantTimeCompare([]byte(existing), []byte(token)) == 1 && !entry.expired(now) {
			found, ok = entry, true
		}
	}
	return found, ok
}

// sessionCSRFToken returns the CSRF token bound to a live session.
func (s *Server) sessionCSRFToken(token string) (string, bool) {
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()
	entry, ok := s.lookupSessionLocked(token, time.Now())
	return entry.csrf, ok
}

// sessionAlive reports whether token still names a live session without
// extending its idle or absolute lifetime. Long-lived responses such as the
// event stream use it to stop disclosing data once a session ends.
func (s *Server) sessionAlive(token string) bool {
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()
	_, ok := s.lookupSessionLocked(token, time.Now())
	return ok
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

// deleteAllSessions revokes every active session.
func (s *Server) deleteAllSessions() {
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()
	clear(s.sessions)
}

const (
	// loginBackoffCap bounds the per-IP delay between failed login attempts.
	loginBackoffCap = 5 * time.Minute
	// loginFailureMemory is how long per-IP failures are remembered.
	loginFailureMemory = time.Hour
	// globalLoginFailureWindow and globalLoginFailureLimit form a failure
	// budget shared by all source addresses for the single admin account.
	globalLoginFailureWindow = 15 * time.Minute
	globalLoginFailureLimit  = 50
	// maxRateLimitEntries bounds the per-IP tracking map.
	maxRateLimitEntries = 10000
)

// getRateLimitBackoff returns the required backoff duration for a failure count.
// Exponential backoff: 1 failure = 0s, 2 = 1s, 3 = 2s, 4 = 4s, ... capped at 5m.
func getRateLimitBackoff(count int) time.Duration {
	if count <= 1 {
		return 0
	}
	seconds := math.Pow(2, float64(count-2))
	if seconds > loginBackoffCap.Seconds() {
		return loginBackoffCap
	}
	return time.Duration(seconds) * time.Second
}

// pruneGlobalFailuresLocked drops global failures outside the window.
// Callers must hold rateMu.
func (s *Server) pruneGlobalFailuresLocked(now time.Time) {
	cutoff := now.Add(-globalLoginFailureWindow)
	kept := s.globalFailures[:0]
	for _, at := range s.globalFailures {
		if at.After(cutoff) {
			kept = append(kept, at)
		}
	}
	s.globalFailures = kept
}

// checkRateLimit checks if the given IP is rate-limited. Returns true if the request
// should be rejected (429). It enforces per-IP exponential backoff; an exhausted
// global failure budget escalates that backoff to the maximum for any address
// with recent failures.
func (s *Server) checkRateLimit(ip string) (bool, time.Duration) {
	s.rateMu.Lock()
	defer s.rateMu.Unlock()
	now := time.Now()

	s.pruneGlobalFailuresLocked(now)
	// The shared budget never rejects a request on its own, otherwise any
	// anonymous caller could lock the administrator out. Once it is exhausted,
	// every address that has already failed waits the full cooldown.
	globalOver := len(s.globalFailures) >= globalLoginFailureLimit

	entry, exists := s.rateLimits[ip]
	if !exists || entry.count == 0 {
		return false, 0
	}

	// Forget failures after a long quiet period
	if now.Sub(entry.lastSeen) > loginFailureMemory {
		delete(s.rateLimits, ip)
		return false, 0
	}

	backoff := getRateLimitBackoff(entry.count)
	if globalOver {
		backoff = loginBackoffCap
	}
	elapsed := now.Sub(entry.lastSeen)

	if elapsed < backoff {
		remaining := backoff - elapsed
		return true, remaining
	}

	return false, 0
}

// recordFailedLogin increments the failed login counters for the given IP and
// the global budget.
func (s *Server) recordFailedLogin(ip string) {
	s.rateMu.Lock()
	defer s.rateMu.Unlock()
	now := time.Now()

	s.globalFailures = append(s.globalFailures, now)
	s.pruneGlobalFailuresLocked(now)

	entry, exists := s.rateLimits[ip]
	if !exists {
		if len(s.rateLimits) >= maxRateLimitEntries {
			s.evictOldestRateLimitLocked()
		}
		entry = &rateLimitEntry{}
		s.rateLimits[ip] = entry
	}
	entry.count++
	entry.lastSeen = now
}

// evictOldestRateLimitLocked removes the least recently seen entry.
// Callers must hold rateMu.
func (s *Server) evictOldestRateLimitLocked() {
	oldestIP := ""
	var oldest time.Time
	for ip, entry := range s.rateLimits {
		if oldestIP == "" || entry.lastSeen.Before(oldest) {
			oldestIP, oldest = ip, entry.lastSeen
		}
	}
	delete(s.rateLimits, oldestIP)
}

// resetRateLimit clears the rate limit counter for the given IP (on successful login).
func (s *Server) resetRateLimit(ip string) {
	s.rateMu.Lock()
	defer s.rateMu.Unlock()
	delete(s.rateLimits, ip)
}

// cleanupRateLimits periodically removes stale entries.
func (s *Server) cleanupRateLimits() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		s.rateMu.Lock()
		now := time.Now()
		for ip, entry := range s.rateLimits {
			if now.Sub(entry.lastSeen) > loginFailureMemory {
				delete(s.rateLimits, ip)
			}
		}
		s.pruneGlobalFailuresLocked(now)
		s.rateMu.Unlock()
	}
}

// validIngestAuth reports whether the request carries the shared agent bearer
// secret. It must only be called when IngestSecret is configured.
func (s *Server) validIngestAuth(r *http.Request) bool {
	expected := "Bearer " + s.cfg.IngestSecret
	return subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte(expected)) == 1
}

// internalAuth protects agent-facing endpoints. With an ingest secret the
// bearer token is enforced centrally so no handler can accidentally fail open.
func (s *Server) internalAuth(next http.Handler) http.Handler {
	if s.cfg.IngestSecret != "" {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !s.validIngestAuth(r) {
				http.Error(w, apperr.NewErrAuthFailed("invalid ingest secret", nil).Error(), http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
	if s.cfg.WebUsername == "" || s.cfg.WebPassword == "" {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "Internal API authentication is not configured", http.StatusServiceUnavailable)
		})
	}
	// Without a bearer secret the endpoints fall back to browser sessions,
	// which carry ambient cookies, so unsafe requests also need CSRF proof.
	return s.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead && !s.checkCSRF(w, r) {
			return
		}
		next.ServeHTTP(w, r)
	}))
}

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Without credentials every request is trusted, so only accept Host
		// names that cannot be rebound to an attacker's browser origin.
		if !s.webAuthEnabled() {
			if !s.allowedHost(r) {
				http.Error(w, "Host not allowed; add it to WEB_ALLOWED_HOSTS", http.StatusMisdirectedRequest)
				return
			}
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

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
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

			// Rotate the CSRF cookie to the token bound to the new session so
			// the logout form's double-submit check keeps working.
			sessionCSRF, _ := s.sessionCSRFToken(sessionToken)
			http.SetCookie(w, s.newSecureCookie(sessionCookieName, sessionToken, int(sessionLifetime.Seconds())))
			http.SetCookie(w, s.newSecureCookie(csrfCookieName, sessionCSRF, int(sessionLifetime.Seconds())))
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

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
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
	if r.FormValue("scope") == "all" {
		// Signing out everywhere requires a live session so an anonymous
		// request cannot revoke other administrators' sessions.
		cookie, err := r.Cookie(sessionCookieName)
		if err != nil || !s.validSession(cookie.Value) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		s.deleteAllSessions()
	} else if cookie, err := r.Cookie(sessionCookieName); err == nil {
		s.deleteSession(cookie.Value)
	}
	http.SetCookie(w, s.newSecureCookie(sessionCookieName, "", -1))
	// Also clear the CSRF cookie
	http.SetCookie(w, s.newSecureCookie(csrfCookieName, "", -1))
	http.Redirect(w, r, s.cfg.BaseURL+"/login", http.StatusSeeOther)
}

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

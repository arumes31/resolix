package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/arumes31/resolix/webgui/internal/config"
	"github.com/arumes31/resolix/webgui/internal/magicdns"
	"github.com/arumes31/resolix/webgui/internal/upstream"
)

func TestInternalRoutesRequireIngestSecret(t *testing.T) {
	s := testServer(&config.Config{IngestSecret: "ingest-secret", BaseURL: "/", MaxRequestSize: 1 << 20})
	s.SetMagicDNS(magicdns.NewStore(""), nil)
	mux := s.SetupMux()
	routes := []struct{ method, path string }{
		{http.MethodPost, "/api/ingest"},
		{http.MethodPost, "/api/heartbeat"},
		{http.MethodGet, "/api/sync/aliases"},
		{http.MethodGet, "/api/sync/dns-routes"},
		{http.MethodGet, "/api/sync/upstream-health"},
		{http.MethodGet, "/api/sync/dns-config"},
		{http.MethodGet, "/api/sync/magicdns"},
	}
	for _, route := range routes {
		for _, auth := range []string{"", "Bearer wrong", "ingest-secret"} {
			req := httptest.NewRequest(route.method, route.path, strings.NewReader("{}"))
			if auth != "" {
				req.Header.Set("Authorization", auth)
			}
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("%s %s with Authorization %q: status = %d, want 401", route.method, route.path, auth, rec.Code)
			}
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/api/sync/magicdns", nil)
	req.Header.Set("Authorization", "Bearer ingest-secret")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("authenticated MagicDNS sync status = %d, want 200", rec.Code)
	}
}

func TestSyncMagicDNSHandlerChecksIngestSecret(t *testing.T) {
	s := testServer(&config.Config{IngestSecret: "ingest-secret"})
	s.SetMagicDNS(magicdns.NewStore(""), nil)
	rec := httptest.NewRecorder()
	s.handleSyncMagicDNS(rec, httptest.NewRequest(http.MethodGet, "/api/sync/magicdns", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestCheckCSRFWithoutAuthRejectsCrossSiteRequests(t *testing.T) {
	s := testServer(&config.Config{})
	tests := []struct {
		name    string
		headers map[string]string
		want    bool
	}{
		{name: "non-browser client", want: true},
		{name: "same-origin fetch", headers: map[string]string{"Sec-Fetch-Site": "same-origin", "Origin": "http://resolix.test"}, want: true},
		{name: "cross-site fetch", headers: map[string]string{"Sec-Fetch-Site": "cross-site"}, want: false},
		{name: "same-site fetch", headers: map[string]string{"Sec-Fetch-Site": "same-site"}, want: false},
		{name: "matching origin", headers: map[string]string{"Origin": "http://resolix.test"}, want: true},
		{name: "foreign origin", headers: map[string]string{"Origin": "https://evil.example"}, want: false},
		{name: "opaque origin", headers: map[string]string{"Origin": "null"}, want: false},
	}
	for _, test := range tests {
		req := httptest.NewRequest(http.MethodPost, "http://resolix.test/api/upstreams", strings.NewReader("[]"))
		for key, value := range test.headers {
			req.Header.Set(key, value)
		}
		rec := httptest.NewRecorder()
		if got := s.checkCSRF(rec, req); got != test.want {
			t.Errorf("%s: checkCSRF = %v, want %v (status %d)", test.name, got, test.want, rec.Code)
		}
	}
}

func TestSessionIdleTimeoutAndRevokeAll(t *testing.T) {
	s := testServer(&config.Config{})
	first, err := s.newSession()
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.newSession()
	if err != nil {
		t.Fatal(err)
	}
	if !s.validSession(first) || !s.validSession(second) {
		t.Fatal("new sessions must be valid")
	}

	s.sessionMu.Lock()
	entry := s.sessions[first]
	entry.lastSeen = time.Now().Add(-sessionIdleTimeout - time.Minute)
	s.sessions[first] = entry
	s.sessionMu.Unlock()
	if s.validSession(first) {
		t.Fatal("idle session remained valid")
	}

	s.sessionMu.Lock()
	entry = s.sessions[second]
	entry.expires = time.Now().Add(-time.Second)
	s.sessions[second] = entry
	s.sessionMu.Unlock()
	if s.validSession(second) {
		t.Fatal("expired session remained valid")
	}

	third, _ := s.newSession()
	fourth, _ := s.newSession()
	s.deleteAllSessions()
	if s.validSession(third) || s.validSession(fourth) {
		t.Fatal("revoked sessions remained valid")
	}
}

func TestLogoutAllRequiresSession(t *testing.T) {
	s := testServer(&config.Config{WebUsername: "admin", WebPassword: "configured", BaseURL: "/"})
	token, _ := s.newSession()
	other, _ := s.newSession()

	post := func(session string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/logout", strings.NewReader("csrf_token=csrf&scope=all"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "csrf", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
		if session != "" {
			req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: session, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
		}
		rec := httptest.NewRecorder()
		s.handleLogout(rec, req)
		return rec
	}
	if rec := post(""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous logout-all status = %d, want 401", rec.Code)
	}
	if !s.validSession(other) {
		t.Fatal("anonymous logout-all revoked sessions")
	}
	if rec := post(token); rec.Code != http.StatusSeeOther {
		t.Fatalf("logout-all status = %d, want 303", rec.Code)
	}
	if s.validSession(token) || s.validSession(other) {
		t.Fatal("logout-all left sessions active")
	}
}

func TestLoginGlobalFailureBudgetAndBoundedEntries(t *testing.T) {
	s := testServer(&config.Config{})
	for i := 0; i < globalLoginFailureLimit; i++ {
		s.recordFailedLogin("198.51.100." + string(rune('a'+i%26)))
	}
	if limited, _ := s.checkRateLimit("203.0.113.99"); limited {
		t.Fatal("exhausted global budget must not lock out addresses without failures")
	}
	s.recordFailedLogin("203.0.113.98")
	if limited, remaining := s.checkRateLimit("203.0.113.98"); !limited || remaining <= loginBackoffCap-time.Minute {
		t.Fatalf("exhausted global budget did not escalate backoff: limited=%t remaining=%s", limited, remaining)
	}

	s = testServer(&config.Config{})
	for i := 0; i < maxRateLimitEntries+10; i++ {
		s.rateMu.Lock()
		s.globalFailures = nil
		s.rateMu.Unlock()
		s.recordFailedLogin("ip-" + time.Duration(i).String())
	}
	if got := len(s.rateLimits); got > maxRateLimitEntries {
		t.Fatalf("rate-limit entries = %d, want <= %d", got, maxRateLimitEntries)
	}
}

func TestUpstreamTestBlocksPrivateEndpointsWithoutOptIn(t *testing.T) {
	s := testServer(&config.Config{HealthDomain: "example.com"})
	probe := func(body string) upstream.ProbeReport {
		req := httptest.NewRequest(http.MethodPost, "/api/upstreams/test", strings.NewReader(body))
		rec := httptest.NewRecorder()
		s.handleUpstreamTest(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d body=%q", rec.Code, rec.Body.String())
		}
		var report upstream.ProbeReport
		if err := json.Unmarshal(rec.Body.Bytes(), &report); err != nil {
			t.Fatal(err)
		}
		return report
	}
	report := probe(`{"spec":"tls://127.0.0.1:6379","bootstrap_servers":["9.9.9.9"]}`)
	if !report.PrivateBlocked || report.Failure == nil || report.Failure.Phase != "policy" {
		t.Fatalf("private endpoint report = %+v", report)
	}
	report = probe(`{"spec":"tls://127.0.0.1:1?timeout=300ms","bootstrap_servers":["9.9.9.9"],"allow_private":true}`)
	if report.PrivateBlocked {
		t.Fatalf("allow_private probe was blocked: %+v", report)
	}
}

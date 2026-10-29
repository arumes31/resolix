package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/arumes31/resolix/webgui/internal/config"
	"github.com/arumes31/resolix/webgui/internal/models"
)

func TestCheckCSRFRequiresTokenBoundToLiveSession(t *testing.T) {
	server := testServer(&config.Config{WebUsername: "admin", WebPassword: "password"})
	victim, err := server.newSession()
	if err != nil {
		t.Fatal(err)
	}
	other, err := server.newSession()
	if err != nil {
		t.Fatal(err)
	}
	otherCSRF, _ := server.sessionCSRFToken(other)

	// A planted cookie paired with a matching header is not enough.
	planted := httptest.NewRequest(http.MethodPost, "/api/rewrites", nil)
	planted.AddCookie(server.newSecureCookie(sessionCookieName, victim, 60))
	planted.AddCookie(server.newSecureCookie(csrfCookieName, "attacker", 60))
	planted.Header.Set("X-CSRF-Token", "attacker")
	if rec := httptest.NewRecorder(); server.checkCSRF(rec, planted) || rec.Code != http.StatusForbidden {
		t.Fatalf("planted CSRF pair accepted: %d", rec.Code)
	}

	// Another session's token does not authorize the victim's session.
	crossed := httptest.NewRequest(http.MethodPost, "/api/rewrites", nil)
	crossed.AddCookie(server.newSecureCookie(sessionCookieName, victim, 60))
	crossed.Header.Set("X-CSRF-Token", otherCSRF)
	if rec := httptest.NewRecorder(); server.checkCSRF(rec, crossed) {
		t.Fatal("another session's CSRF token accepted")
	}

	// Cross-site browser requests are rejected even with a valid token.
	crossSite := httptest.NewRequest(http.MethodPost, "/api/rewrites", nil)
	addSessionCSRF(t, server, crossSite)
	crossSite.Header.Set("Sec-Fetch-Site", "same-site")
	if rec := httptest.NewRecorder(); server.checkCSRF(rec, crossSite) {
		t.Fatal("same-site sibling request accepted")
	}

	server.deleteSession(victim)
	victimCSRF := httptest.NewRequest(http.MethodPost, "/api/rewrites", nil)
	victimCSRF.AddCookie(server.newSecureCookie(sessionCookieName, victim, 60))
	victimCSRF.Header.Set("X-CSRF-Token", otherCSRF)
	if rec := httptest.NewRecorder(); server.checkCSRF(rec, victimCSRF) {
		t.Fatal("revoked session passed CSRF validation")
	}
}

func TestSessionAliveDoesNotExtendIdleTimer(t *testing.T) {
	server := testServer(&config.Config{WebUsername: "admin", WebPassword: "password"})
	token, err := server.newSession()
	if err != nil {
		t.Fatal(err)
	}
	entry := server.sessions[token]
	entry.lastSeen = time.Now().Add(-sessionIdleTimeout + time.Minute)
	server.sessions[token] = entry
	if !server.sessionAlive(token) {
		t.Fatal("live session reported dead")
	}
	if !server.sessions[token].lastSeen.Equal(entry.lastSeen) {
		t.Fatal("sessionAlive refreshed the idle timer")
	}
	server.deleteSession(token)
	if server.sessionAlive(token) {
		t.Fatal("revoked session reported alive")
	}
}

func TestStreamEndsWhenSessionIsRevoked(t *testing.T) {
	server := testServer(&config.Config{
		WebUsername:          "admin",
		WebPassword:          "password",
		SSEKeepaliveInterval: 10 * time.Millisecond,
	})
	token, err := server.newSession()
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/api/stream", nil)
	request.AddCookie(server.newSecureCookie(sessionCookieName, token, 60))
	done := make(chan struct{})
	go func() {
		server.handleStream(httptest.NewRecorder(), request)
		close(done)
	}()
	server.deleteSession(token)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("stream kept running after its session was revoked")
	}
}

func TestCredentialFreeDashboardRejectsReboundHosts(t *testing.T) {
	server := testServer(&config.Config{
		BaseURL:        "/",
		AllowedHosts:   []string{"dns.home.arpa"},
		TrustedProxies: []string{"10.0.0.1"},
	})
	handler := server.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	for _, test := range []struct {
		host      string
		forwarded string
		remote    string
		want      int
	}{
		{host: "127.0.0.1:35353", want: http.StatusNoContent},
		{host: "[::1]:35353", want: http.StatusNoContent},
		{host: "localhost:35353", want: http.StatusNoContent},
		{host: "DNS.home.arpa.", want: http.StatusNoContent},
		{host: "rebind.attacker.example:35353", want: http.StatusMisdirectedRequest},
		{host: "127.0.0.1", forwarded: "rebind.attacker.example", remote: "10.0.0.1:1", want: http.StatusMisdirectedRequest},
		{host: "127.0.0.1", forwarded: "rebind.attacker.example", remote: "192.0.2.1:1", want: http.StatusNoContent},
	} {
		request := httptest.NewRequest(http.MethodGet, "/api/stats", nil)
		request.Host = test.host
		if test.remote != "" {
			request.RemoteAddr = test.remote
		}
		if test.forwarded != "" {
			request.Header.Set("X-Forwarded-Host", test.forwarded)
		}
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code != test.want {
			t.Errorf("host=%q forwarded=%q status = %d, want %d", test.host, test.forwarded, recorder.Code, test.want)
		}
	}
}

func TestSessionAuthenticatedIngestRequiresCSRF(t *testing.T) {
	server := testServer(&config.Config{WebUsername: "admin", WebPassword: "password", TrustedProxies: []string{"192.0.2.1"}})
	called := false
	handler := server.internalAuth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}))
	token, err := server.newSession()
	if err != nil {
		t.Fatal(err)
	}
	newRequest := func() *http.Request {
		request := httptest.NewRequest(http.MethodPost, "/api/ingest", strings.NewReader(`[]`))
		request.Header.Set("X-Forwarded-Proto", "https")
		return request
	}

	request := newRequest()
	request.AddCookie(server.newSecureCookie(sessionCookieName, token, 60))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden || called {
		t.Fatalf("ingest without CSRF = %d called=%t", recorder.Code, called)
	}

	request = newRequest()
	addSessionCSRF(t, server, request)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNoContent || !called {
		t.Fatalf("ingest with CSRF = %d %q", recorder.Code, recorder.Body.String())
	}
}

func TestClientIPReadsEveryForwardingField(t *testing.T) {
	server := testServer(&config.Config{TrustedProxies: []string{"10.0.0.0/8"}})
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.RemoteAddr = "10.1.2.3:1234"
	request.Header.Add("X-Forwarded-For", "198.51.100.66")
	request.Header.Add("X-Forwarded-For", "203.0.113.9")
	if got := server.clientIP(request); got != "203.0.113.9" {
		t.Fatalf("multi-field X-Forwarded-For client = %q", got)
	}

	request.Header.Del("X-Forwarded-For")
	request.Header.Add("Forwarded", `for=198.51.100.66`)
	request.Header.Add("Forwarded", `for="[2001:db8::9]:443";proto=https`)
	if got := server.clientIP(request); got != "2001:db8::9" {
		t.Fatalf("multi-field Forwarded client = %q", got)
	}

	request.Header.Del("Forwarded")
	request.Header.Set("X-Forwarded-For", "198.51.100.66, not-an-ip")
	if got := server.clientIP(request); got != "10.1.2.3" {
		t.Fatalf("invalid trailing hop client = %q, want the proxy peer", got)
	}
}

func TestIngestRejectsTombstonedIdentityWithoutNodeName(t *testing.T) {
	server, cleanup := newHistoryTestServer(t)
	defer cleanup()
	server.store.SetNodeStatusIdentity("stable-agent", "agent-one", models.NodeStatus{})
	if removed, err := server.store.DecommissionNode("stable-agent"); err != nil || !removed {
		t.Fatalf("decommission node = %t, %v", removed, err)
	}
	events, err := json.Marshal([]models.QueryEvent{{Domain: "unnamed.test", UnixTime: time.Now().Unix()}})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/ingest", bytes.NewReader(events))
	request.Header.Set("X-Node-ID", "stable-agent")
	recorder := httptest.NewRecorder()
	server.handleIngest(recorder, request)
	if recorder.Code != http.StatusGone {
		t.Fatalf("nameless tombstoned ingest = %d", recorder.Code)
	}
	if got := server.store.GetOrderedEvents(10); len(got) != 0 {
		t.Fatalf("tombstoned ingest stored events: %+v", got)
	}

	legacy := httptest.NewRequest(http.MethodPost, "/api/ingest", strings.NewReader(`{"health":{"1.1.1.1":5}}`))
	legacy.Header.Set("X-Node-ID", "stable-agent")
	recorder = httptest.NewRecorder()
	server.handleIngest(recorder, legacy)
	if recorder.Code != http.StatusGone {
		t.Fatalf("nameless tombstoned legacy ingest = %d", recorder.Code)
	}
}

func TestIngestRejectsOversizedEventDomains(t *testing.T) {
	server, cleanup := newHistoryTestServer(t)
	defer cleanup()
	for _, domain := range []string{
		strings.Repeat("a.", 200) + "test",
		strings.Repeat("a", 64) + ".test",
		"a..test",
	} {
		events, err := json.Marshal([]models.QueryEvent{{Node: "agent", Domain: domain}})
		if err != nil {
			t.Fatal(err)
		}
		recorder := httptest.NewRecorder()
		server.handleIngest(recorder, httptest.NewRequest(http.MethodPost, "/api/ingest", bytes.NewReader(events)))
		if recorder.Code != http.StatusBadRequest {
			t.Errorf("domain len %d status = %d", len(domain), recorder.Code)
		}
	}
	if got := server.store.GetOrderedEvents(10); len(got) != 0 {
		t.Fatalf("invalid domains stored: %+v", got)
	}
}

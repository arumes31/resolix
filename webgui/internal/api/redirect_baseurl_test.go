package api

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/arumes31/resolix/webgui/internal/config"
)

// TestAuthRedirectsStayLocal guards against "/" + "/login" producing the
// protocol-relative URL "//login", which browsers send to the host "login".
func TestAuthRedirectsStayLocal(t *testing.T) {
	for _, tc := range []struct {
		base, path, want string
	}{
		{"/", "/", "/login"},
		{"/dns", "/dns/", "/dns/login"},
	} {
		t.Run(tc.base, func(t *testing.T) {
			s := testServer(&config.Config{BaseURL: tc.base, WebUsername: "admin", WebPassword: "configured"})
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			req.TLS = &tls.ConnectionState{}
			req.Header.Set("Accept", "text/html")
			rec := httptest.NewRecorder()
			s.SetupMux().ServeHTTP(rec, req)
			if rec.Code != http.StatusSeeOther {
				t.Fatalf("status = %d; want %d", rec.Code, http.StatusSeeOther)
			}
			if got := rec.Header().Get("Location"); got != tc.want {
				t.Fatalf("Location = %q; want %q", got, tc.want)
			}
		})
	}
}

func TestAppPath(t *testing.T) {
	for base, want := range map[string]string{"/": "/login", "": "/login", "/dns": "/dns/login"} {
		s := &Server{cfg: &config.Config{BaseURL: base}}
		if got := s.appPath("/login"); got != want {
			t.Errorf("appPath(%q) = %q; want %q", base, got, want)
		}
	}
}

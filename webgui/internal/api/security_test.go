package api

import (
	"compress/gzip"
	"html/template"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/arumes31/resolix/webgui/internal/config"
)

func TestLoginResponseContentType(t *testing.T) {
	for _, test := range []struct {
		name     string
		method   string
		encoding string
	}{
		{name: "form_identity", method: http.MethodGet, encoding: "identity"},
		{name: "form_gzip", method: http.MethodGet, encoding: "gzip"},
		{name: "invalid_credentials_identity", method: http.MethodPost, encoding: "identity"},
		{name: "invalid_credentials_gzip", method: http.MethodPost, encoding: "gzip"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			s := testServer(&config.Config{BaseURL: "/", WebUsername: "admin", WebPassword: "configured", MaxRequestSize: 1 << 20})
			var err error
			s.tmpl, err = template.ParseFiles("../../templates/login.html")
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewTLSServer(s.SetupMux())
			t.Cleanup(server.Close)

			form := url.Values{"username": {"unknown"}, "password": {"wrong"}, "csrf_token": {"test-csrf"}}
			request, err := http.NewRequestWithContext(t.Context(), test.method, server.URL+"/login", strings.NewReader(form.Encode()))
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Accept-Encoding", test.encoding)
			if test.method == http.MethodPost {
				request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				request.AddCookie(s.newSecureCookie(csrfCookieName, "test-csrf", 60))
			}
			response, err := server.Client().Do(request)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = response.Body.Close() })
			if response.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusOK)
			}
			if got := response.Header.Get("Content-Type"); got != "text/html; charset=utf-8" {
				t.Errorf("Content-Type = %q, want text/html; charset=utf-8", got)
			}
			var body io.Reader = response.Body
			if test.encoding == "gzip" {
				if got := response.Header.Get("Content-Encoding"); got != "gzip" {
					t.Fatalf("Content-Encoding = %q, want gzip", got)
				}
				reader, err := gzip.NewReader(response.Body)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = reader.Close() })
				body = reader
			}
			content, err := io.ReadAll(body)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(content), `<title>Login | Resolix</title>`) || !strings.Contains(string(content), `type="password"`) {
				t.Error("response does not contain the login form")
			}
			if test.method == http.MethodPost && !strings.Contains(string(content), "Invalid username or password") {
				t.Error("failed login did not render its error message")
			}
			if len(response.Cookies()) != 1 || response.Cookies()[0].Name != csrfCookieName || !response.Cookies()[0].Secure {
				t.Error("login response did not set the secure CSRF cookie")
			}
		})
	}
}

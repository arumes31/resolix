package api

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"

	"github.com/miekg/dns"
)

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

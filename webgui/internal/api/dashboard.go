package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/arumes31/resolix/webgui/internal/config"
	"github.com/arumes31/resolix/webgui/internal/models"
)

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" || r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	s.renderPage(w, r, "index.html")
}

func (s *Server) handleQueryLogPage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/querylog" || r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	s.renderPage(w, r, "querylog.html")
}

func (s *Server) handleClusterPage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/cluster" || r.Method != http.MethodGet || !s.isController() {
		http.NotFound(w, r)
		return
	}
	s.renderPage(w, r, "cluster.html")
}

func (s *Server) renderPage(w http.ResponseWriter, r *http.Request, name string) {
	var buf bytes.Buffer
	if err := s.tmpl.ExecuteTemplate(&buf, name, s.templateData(r)); err != nil {
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

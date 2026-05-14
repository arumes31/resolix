package api

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"tailscale-dnsrewrite/webgui/internal/config"
	"tailscale-dnsrewrite/webgui/internal/models"
	"tailscale-dnsrewrite/webgui/internal/parser"
	"tailscale-dnsrewrite/webgui/internal/storage"
)

// Server handles HTTP API and Web GUI requests.
type Server struct {
	cfg    *config.Config
	store  *storage.Store
	parser *parser.Parser
	tmpl   *template.Template

	// SSE Broadcaster
	subscribers map[chan models.QueryEvent]int
	subMu       sync.Mutex
}

// NewServer initializes a new API server.
func NewServer(cfg *config.Config, store *storage.Store, prs *parser.Parser, tmpl *template.Template) *Server {
	return &Server{
		cfg:         cfg,
		store:       store,
		parser:      prs,
		tmpl:        tmpl,
		subscribers: make(map[chan models.QueryEvent]int),
	}
}

// Broadcast sends an event to all connected SSE clients.
func (s *Server) Broadcast(e models.QueryEvent) {
	s.subMu.Lock()
	defer s.subMu.Unlock()
	for ch, drops := range s.subscribers {
		select {
		case ch <- e:
			if drops > 0 {
				s.subscribers[ch] = 0
			}
		default:
			s.subscribers[ch]++
			if s.subscribers[ch] > 10 {
				log.Printf("Dropping slow subscriber")
				delete(s.subscribers, ch)
				// removed close(ch) to prevent panic
			}
		}
	}
}

// SetupMux configures the API routes and middleware.
func (s *Server) SetupMux() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/ingest", s.handleIngest)
	mux.HandleFunc("/", s.handleRoot)
	mux.HandleFunc("/api/events", s.handleEvents)
	mux.HandleFunc("/api/stats", s.handleStats)
	mux.HandleFunc("/api/client_stats", s.handleClientStats)
	mux.HandleFunc("/api/simulate", s.handleSimulate)

	handler := s.gzipMiddleware(mux)

	rootMux := http.NewServeMux()
	rootMux.Handle("/", handler)
	rootMux.HandleFunc("/api/stream", s.handleStream) // SSE endpoint bypassed

	return rootMux
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
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
	}

	// 2. Limit Total Payload Size (Improvement 112)
	r.Body = http.MaxBytesReader(w, r.Body, 1*1024*1024) // 1MB limit

	var payload struct {
		Node   string             `json:"node"`
		Line   string             `json:"line"`
		Batch  []string           `json:"batch"`
		Health map[string]float64 `json:"health,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Payload too large or bad request", http.StatusBadRequest)
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
			s.Broadcast(*ev)
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
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleRoot(w http.ResponseWriter, _ *http.Request) {
	currentEvents := s.store.GetOrderedEvents(s.cfg.ScanLimit)
	var buf bytes.Buffer
	if err := s.tmpl.Execute(&buf, map[string]interface{}{
		"Events": currentEvents,
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
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
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

	ch := make(chan models.QueryEvent, 100)
	s.subMu.Lock()
	s.subscribers[ch] = 0
	s.subMu.Unlock()

	defer func() {
		s.subMu.Lock()
		delete(s.subscribers, ch)
		s.subMu.Unlock()
		close(ch)
	}()

	notify := r.Context().Done()
	timer := time.NewTimer(30 * time.Second)
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
			timer.Reset(30 * time.Second)
		case <-timer.C:
			// Keepalive comment
			_, _ = fmt.Fprintf(w, ": keepalive\n\n")
			flusher.Flush()
			timer.Reset(30 * time.Second)
		}
	}
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
func (s *Server) Start(ctx context.Context) error {
	server := &http.Server{
		Addr:              ":" + s.cfg.Port,
		Handler:           s.SetupMux(),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	ln, err := net.Listen("tcp", server.Addr)
	if err != nil {
		return err
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	log.Printf("Starting Advanced Web GUI on %s", server.Addr)
	return server.Serve(ln)
}

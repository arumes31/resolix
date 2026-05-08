package api

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
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

type Server struct {
	cfg    *config.Config
	store  *storage.Store
	parser *parser.Parser
	tmpl   *template.Template

	// SSE Broadcaster (Improvement 78)
	subscribers map[chan models.QueryEvent]bool
	subMu       sync.Mutex
}

func NewServer(cfg *config.Config, store *storage.Store, prs *parser.Parser, tmpl *template.Template) *Server {
	return &Server{
		cfg:         cfg,
		store:       store,
		parser:      prs,
		tmpl:        tmpl,
		subscribers: make(map[chan models.QueryEvent]bool),
	}
}

func (s *Server) Broadcast(e models.QueryEvent) {
	s.subMu.Lock()
	defer s.subMu.Unlock()
	for ch := range s.subscribers {
		select {
		case ch <- e:
		default:
			// Buffer full, skip or drop client
		}
	}
}

func (s *Server) SetupMux() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/ingest", s.handleIngest)
	mux.HandleFunc("/", s.handleRoot)
	mux.HandleFunc("/api/events", s.handleEvents)
	mux.HandleFunc("/api/stats", s.handleStats)
	mux.HandleFunc("/api/simulate", s.handleSimulate)
	mux.HandleFunc("/api/stream", s.handleStream) // SSE endpoint

	return s.gzipMiddleware(mux)
}

func (s *Server) handleIngest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var payload struct {
		Node  string   `json:"node"`
		Line  string   `json:"line"`
		Batch []string `json:"batch"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	
	if payload.Line != "" {
		ev := s.parser.ParseLogBytes([]byte(payload.Line), payload.Node)
		if ev != nil {
			s.Broadcast(*ev)
		}
	}
	for _, l := range payload.Batch {
		ev := s.parser.ParseLogBytes([]byte(l), payload.Node)
		if ev != nil {
			s.Broadcast(*ev)
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleRoot(w http.ResponseWriter, _ *http.Request) {
	currentEvents := s.store.GetOrderedEvents(config.DefaultScanLimit)
	var buf bytes.Buffer
	if err := s.tmpl.Execute(&buf, map[string]interface{}{
		"Events": currentEvents,
	}); err != nil {
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

func (s *Server) handleSimulate(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		http.Error(w, "Missing domain parameter", http.StatusBadRequest)
		return
	}
	ips, err := net.LookupIP(domain)
	if err != nil {
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
	s.subscribers[ch] = true
	s.subMu.Unlock()

	defer func() {
		s.subMu.Lock()
		delete(s.subscribers, ch)
		s.subMu.Unlock()
		close(ch)
	}()

	notify := r.Context().Done()
	for {
		select {
		case <-notify:
			return
		case ev := <-ch:
			data, _ := json.Marshal(ev)
			_, _ = fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		case <-time.After(30 * time.Second):
			// Keepalive comment
			_, _ = fmt.Fprintf(w, ": keepalive\n\n")
			flusher.Flush()
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

func (s *Server) Start() error {
	server := &http.Server{
		Addr:         ":" + s.cfg.Port,
		Handler:      s.SetupMux(),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	ln, err := net.Listen("tcp", server.Addr)
	if err != nil {
		return err
	}

	log.Printf("Starting Advanced Web GUI on %s", server.Addr)
	return server.Serve(ln)
}

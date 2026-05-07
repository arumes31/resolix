package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

//go:embed templates/*
var templates embed.FS

type QueryEvent struct {
	Timestamp string  `json:"timestamp"`
	UnixTime  int64   `json:"unix_time"`
	Type      string  `json:"type"`
	Domain    string  `json:"domain"`
	ClientIP  string  `json:"client_ip"`
	Latency   float64 `json:"latency_ms,omitempty"`
	Upstream  string  `json:"upstream,omitempty"`
}

type StatEntry struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

var (
	maxEvents = 1000
	events    = make([]QueryEvent, maxEvents)
	head      = 0
	count     = 0
	eventsMu  sync.RWMutex

	pendingQueries   = make(map[string]time.Time)
	pendingUpstreams = make(map[string]string)
	pendingMu        sync.Mutex
)

// Gzip middleware
type gzipResponseWriter struct {
	io.Writer
	http.ResponseWriter
}

func (w gzipResponseWriter) Write(b []byte) (int, error) {
	return w.Writer.Write(b)
}

func gzipMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Content-Encoding", "gzip")
		gz := gzip.NewWriter(w)
		defer gz.Close()
		gzw := gzipResponseWriter{Writer: gz, ResponseWriter: w}
		next.ServeHTTP(gzw, r)
	})
}

func parseLogLine(line string) {
	now := time.Now()

	// 1. Handle "query[" lines
	if idx := strings.Index(line, "query["); idx != -1 {
		typeStart := idx + 6
		typeEnd := strings.Index(line[typeStart:], "]")
		if typeEnd == -1 {
			return
		}
		qType := line[typeStart : typeStart+typeEnd]

		domainPart := line[typeStart+typeEnd+2:]
		domainEnd := strings.Index(domainPart, " ")
		if domainEnd == -1 {
			return
		}
		domain := domainPart[:domainEnd]

		fromIdx := strings.Index(domainPart, "from ")
		if fromIdx == -1 {
			return
		}
		clientIP := strings.TrimSpace(domainPart[fromIdx+5:])

		tsStr := now.Format("Jan _2 15:04:05")
		if idx > 16 {
			tsCandidate := line[:15]
			if _, err := time.Parse("Jan _2 15:04:05", tsCandidate); err == nil {
				tsStr = tsCandidate
			}
		}

		event := QueryEvent{
			Timestamp: tsStr,
			UnixTime:  now.Unix(),
			Type:      qType,
			Domain:    domain,
			ClientIP:  clientIP,
		}

		// Store in pending to wait for reply/latency
		pendingMu.Lock()
		pendingQueries[domain] = now
		pendingMu.Unlock()

		eventsMu.Lock()
		events[head] = event
		head = (head + 1) % maxEvents
		if count < maxEvents {
			count++
		}
		eventsMu.Unlock()
		return
	}

	// 2. Handle "forwarded" lines (to track upstream)
	if idx := strings.Index(line, "forwarded "); idx != -1 {
		parts := strings.Fields(line[idx:])
		if len(parts) >= 4 {
			domain := parts[1]
			upstream := parts[3]
			pendingMu.Lock()
			pendingUpstreams[domain] = upstream
			pendingMu.Unlock()
		}
		return
	}

	// 3. Handle "reply" lines (to calculate latency)
	if idx := strings.Index(line, "reply "); idx != -1 {
		parts := strings.Fields(line[idx:])
		if len(parts) >= 2 {
			domain := parts[1]
			pendingMu.Lock()
			startTime, ok := pendingQueries[domain]
			upstream := pendingUpstreams[domain]
			if ok {
				latency := float64(now.Sub(startTime).Microseconds()) / 1000.0
				delete(pendingQueries, domain)
				delete(pendingUpstreams, domain)
				pendingMu.Unlock()

				// Update the latest event for this domain if found
				eventsMu.Lock()
				for i := 0; i < count; i++ {
					idx := (head - 1 - i + maxEvents) % maxEvents
					if events[idx].Domain == domain && events[idx].Latency == 0 {
						events[idx].Latency = latency
						events[idx].Upstream = upstream
						break
					}
				}
				eventsMu.Unlock()
			} else {
				pendingMu.Unlock()
			}
		}
		return
	}
}

func startLogIngestion() {
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := scanner.Text()
		fmt.Println(line)
		parseLogLine(line)
	}
	if err := scanner.Err(); err != nil {
		log.Printf("Scanner error: %v", err)
	}
}

func getOrderedEvents() []QueryEvent {
	eventsMu.RLock()
	defer eventsMu.RUnlock()

	result := make([]QueryEvent, 0, count)
	for i := 0; i < count; i++ {
		idx := (head - 1 - i + maxEvents) % maxEvents
		result = append(result, events[idx])
	}
	return result
}

func main() {
	tmpl, err := template.ParseFS(templates, "templates/index.html")
	if err != nil {
		log.Fatal(err)
	}

	go startLogIngestion()

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		currentEvents := getOrderedEvents()
		var buf bytes.Buffer
		if err := tmpl.Execute(&buf, map[string]interface{}{
			"Events": currentEvents,
		}); err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			log.Printf("Template execution error: %v", err)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if _, err := buf.WriteTo(w); err != nil {
			log.Printf("Error writing response: %v", err)
		}
	})

	mux.HandleFunc("/api/events", func(w http.ResponseWriter, r *http.Request) {
		currentEvents := getOrderedEvents()
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(currentEvents); err != nil {
			log.Printf("JSON encoding error: %v", err)
		}
	})

	mux.HandleFunc("/api/stats", func(w http.ResponseWriter, r *http.Request) {
		currentEvents := getOrderedEvents()
		
		domainCounts := make(map[string]int)
		clientCounts := make(map[string]int)
		
		for _, e := range currentEvents {
			domainCounts[e.Domain]++
			clientCounts[e.ClientIP]++
		}

		toStats := func(m map[string]int) []StatEntry {
			s := make([]StatEntry, 0, len(m))
			for k, v := range m {
				s = append(s, StatEntry{Key: k, Count: v})
			}
			sort.Slice(s, func(i, j int) bool { return s[i].Count > s[j].Count })
			if len(s) > 10 {
				s = s[:10]
			}
			return s
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"top_domains": toStats(domainCounts),
			"top_clients": toStats(clientCounts),
		}); err != nil {
			log.Printf("JSON encoding error: %v", err)
		}
	})

	mux.HandleFunc("/api/simulate", func(w http.ResponseWriter, r *http.Request) {
		domain := r.URL.Query().Get("domain")
		if domain == "" {
			http.Error(w, "Missing domain parameter", http.StatusBadRequest)
			return
		}

		ips, err := net.LookupIP(domain)
		if err != nil {
			if err := json.NewEncoder(w).Encode(map[string]interface{}{
				"status": "error",
				"error":  err.Error(),
			}); err != nil {
				log.Printf("JSON encoding error: %v", err)
			}
			return
		}

		res := make([]string, 0, len(ips))
		for _, ip := range ips {
			res = append(res, ip.String())
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "success",
			"ips":    res,
		}); err != nil {
			log.Printf("JSON encoding error: %v", err)
		}
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "35353"
	}

	server := &http.Server{
		Addr:         ":" + port,
		Handler:      gzipMiddleware(mux),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	log.Printf("Starting Advanced Web GUI on %s", server.Addr) // #nosec G706
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

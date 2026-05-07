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

// Robust parsing using fields
func parseLogLine(line string) {
	now := time.Now()
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return
	}

	// Identify the action (query, forwarded, reply, etc.)
	// We look for the part that contains the action, usually after "dnsmasq[pid]:"
	actionIdx := -1
	for i, p := range parts {
		if strings.HasPrefix(p, "query[") || p == "forwarded" || p == "reply" || p == "config" || p == "cached" {
			actionIdx = i
			break
		}
	}

	if actionIdx == -1 {
		return
	}

	action := parts[actionIdx]

	// 1. Handle Queries
	if strings.HasPrefix(action, "query[") {
		// query[A] domain from IP
		qType := action[6 : len(action)-1]
		if len(parts) < actionIdx+4 {
			return
		}
		domain := parts[actionIdx+1]
		// Skip "from" at actionIdx+2
		clientIP := parts[actionIdx+3]

		// Extract timestamp from the beginning if possible
		tsStr := now.Format("Jan _2 15:04:05")
		if actionIdx >= 3 {
			// Likely syslog format: Mmm DD HH:MM:SS
			tsStr = strings.Join(parts[:3], " ")
		}

		event := QueryEvent{
			Timestamp: tsStr,
			UnixTime:  now.Unix(),
			Type:      qType,
			Domain:    domain,
			ClientIP:  clientIP,
		}

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

	// 2. Handle Forwarded (Track Upstream)
	if action == "forwarded" {
		// forwarded domain to IP
		if len(parts) >= actionIdx+4 {
			domain := parts[actionIdx+1]
			upstream := parts[actionIdx+3]
			pendingMu.Lock()
			pendingUpstreams[domain] = upstream
			pendingMu.Unlock()
		}
		return
	}

	// 3. Handle Replies / Cached / Config (Latency)
	if action == "reply" || action == "cached" || action == "config" {
		// action domain is IP/NODATA/etc
		if len(parts) >= actionIdx+2 {
			domain := parts[actionIdx+1]
			pendingMu.Lock()
			startTime, ok := pendingQueries[domain]
			upstream := ""
			if action == "reply" {
				upstream = pendingUpstreams[domain]
			} else {
				upstream = action // "cached" or "config"
			}

			if ok {
				latency := float64(now.Sub(startTime).Microseconds()) / 1000.0
				delete(pendingQueries, domain)
				delete(pendingUpstreams, domain)
				pendingMu.Unlock()

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
	// Use a larger buffer for the scanner
	scanner := bufio.NewScanner(os.Stdin)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024) // 1MB max line length

	log.Println("Log ingestion started, waiting for dnsmasq input...")
	for scanner.Scan() {
		line := scanner.Text()
		fmt.Println(line) // Still print to stdout for docker logs
		parseLogLine(line)
	}
	if err := scanner.Err(); err != nil {
		log.Printf("Scanner FATAL error: %v", err)
	} else {
		log.Println("Scanner closed normally")
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
			w.Header().Set("Content-Type", "application/json")
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

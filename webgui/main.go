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
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
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
	Node      string  `json:"node,omitempty"`
}

type StatEntry struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

var (
	maxEvents = 100000
	events    = make([]QueryEvent, maxEvents)
	head      = 0
	count     = 0
	eventsMu  sync.RWMutex

	// pending maps: node -> domain -> data
	pendingQueries   = make(map[string]map[string]time.Time)
	pendingUpstreams = make(map[string]map[string]string)
	pendingMu        sync.Mutex

	// Mode config
	mode      = strings.ToLower(os.Getenv("MODE"))       // "master" or "slave"
	masterURL = os.Getenv("MASTER_URL")                  // e.g. http://100.x.y.z:35353
	nodeName  = os.Getenv("NODE_NAME")                   // Identifier
)

func init() {
	if nodeName == "" {
		nodeName, _ = os.Hostname()
	}
	if mode == "" {
		mode = "master"
	}
}

// Periodically clean up stale pending queries (older than 10s)
func startPendingCleanup() {
	ticker := time.NewTicker(10 * time.Second)
	for range ticker.C {
		pendingMu.Lock()
		now := time.Now()
		for node, queries := range pendingQueries {
			for dom, start := range queries {
				if now.Sub(start) > 10*time.Second {
					delete(queries, dom)
					delete(pendingUpstreams[node], dom)
				}
			}
			if len(queries) == 0 {
				delete(pendingQueries, node)
				delete(pendingUpstreams, node)
			}
		}
		pendingMu.Unlock()
	}
}

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
func parseLogLine(line string, node string) {
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
			Node:      node,
		}

		pendingMu.Lock()
		if pendingQueries[node] == nil {
			pendingQueries[node] = make(map[string]time.Time)
		}
		pendingQueries[node][domain] = now
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
			if pendingUpstreams[node] == nil {
				pendingUpstreams[node] = make(map[string]string)
			}
			pendingUpstreams[node][domain] = upstream
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
			startTime, ok := pendingQueries[node][domain]
			upstream := ""
			if action == "reply" {
				upstream = pendingUpstreams[node][domain]
			} else if action == "cached" {
				upstream = "System Cache"
			} else if action == "config" {
				upstream = "Local Override"
			} else {
				upstream = action
			}

			if ok {
				latency := float64(now.Sub(startTime).Microseconds()) / 1000.0
				delete(pendingQueries[node], domain)
				delete(pendingUpstreams[node], domain)
				pendingMu.Unlock()

				eventsMu.Lock()
				// Limit scan to last 1000 events to prevent O(N) bottleneck on high load
				scanLimit := count
				if scanLimit > 1000 {
					scanLimit = 1000
				}
				for i := 0; i < scanLimit; i++ {
					idx := (head - 1 - i + maxEvents) % maxEvents
					if events[idx].Domain == domain && events[idx].Node == node && events[idx].Latency == 0 {
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
	client := &http.Client{Timeout: 2 * time.Second}

	for scanner.Scan() {
		line := scanner.Text()
		fmt.Println(line) // Still print to stdout for docker logs
		
		// In slave mode, forward raw logs to master
		if mode == "slave" && masterURL != "" {
			go func(l string) {
				data, _ := json.Marshal(map[string]string{"node": nodeName, "line": l})
				req, _ := http.NewRequest("POST", masterURL+"/api/ingest", bytes.NewBuffer(data))
				req.Header.Set("Content-Type", "application/json")
				resp, err := client.Do(req)
				if err == nil {
					resp.Body.Close()
				}
			}(line)
		}

		parseLogLine(line, nodeName)
	}
	if err := scanner.Err(); err != nil {
		log.Printf("Scanner FATAL error: %v", err)
		os.Exit(1)
	}
	log.Println("Scanner closed normally (EOF), exiting process...")
	os.Exit(0)
}

func getOrderedEvents(limit int) []QueryEvent {
	eventsMu.RLock()
	defer eventsMu.RUnlock()

	n := count
	if limit > 0 && n > limit {
		n = limit
	}

	result := make([]QueryEvent, 0, n)
	for i := 0; i < n; i++ {
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
	go startPendingCleanup()

	// Handle signals for graceful reload/shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		for sig := range sigChan {
			if sig == syscall.SIGHUP {
				log.Println("Received SIGHUP, ignoring (reload is handled by dnsmasq)")
				continue
			}
			log.Printf("Received signal %v, shutting down", sig)
			os.Exit(0)
		}
	}()

	mux := http.NewServeMux()

	// Slave log ingestion endpoint (Master only)
	mux.HandleFunc("/api/ingest", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var payload struct {
			Node string `json:"node"`
			Line string `json:"line"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}
		if payload.Line != "" {
			parseLogLine(payload.Line, payload.Node)
		}
		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		currentEvents := getOrderedEvents(1000) // Only send last 1000 to template
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
		currentEvents := getOrderedEvents(1000) // Limit to 1000 for efficiency
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(currentEvents); err != nil {
			log.Printf("JSON encoding error: %v", err)
		}
	})

	mux.HandleFunc("/api/stats", func(w http.ResponseWriter, r *http.Request) {
		domainCounts := make(map[string]int)
		clientCounts := make(map[string]int)
		nodeRPM := make(map[string]int)
		nodeRPH := make(map[string]int)
		
		now := time.Now().Unix()
		rpm := 0
		rph := 0
		rpd := 0 // Day
		total := 0

		eventsMu.RLock()
		total = count
		for i := 0; i < count; i++ {
			idx := (head - 1 - i + maxEvents) % maxEvents
			e := events[idx]
			domainCounts[e.Domain]++
			clientCounts[e.ClientIP]++
			
			nodeName := e.Node
			if nodeName == "" { nodeName = "local" }

			if e.UnixTime >= now-60 {
				rpm++
				nodeRPM[nodeName]++
			}
			if e.UnixTime >= now-3600 {
				rph++
				nodeRPH[nodeName]++
			}
			if e.UnixTime >= now-86400 {
				rpd++
			}
		}
		eventsMu.RUnlock()

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

		nodeList := make(map[string]interface{})
		for node := range nodeRPH {
			nodeList[node] = map[string]int{
				"rpm": nodeRPM[node],
				"rph": nodeRPH[node],
			}
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"top_domains": toStats(domainCounts),
			"top_clients": toStats(clientCounts),
			"rpm":         rpm,
			"rph":         rph,
			"rpd":         rpd,
			"total":       total,
			"nodes":       nodeList,
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

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
	"path/filepath"
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

	// History config
	historyDir       = "/var/lib/tailscale-dnsrewrite"
	lastArchivedTime int64

	// Bucketized stats: unix hour -> count
	hourlyStats = make(map[int64]int)
	statsMu     sync.RWMutex

	// Incremental stats for the ring buffer window
	windowDomainCounts = make(map[string]int)
	windowClientCounts = make(map[string]int)
	// (Note: node stats are still calculated from buckets for accuracy)

	// Resilient Forwarding for Slaves
	forwardChan      = make(chan string, 10000) // Buffer for incoming lines
	backlogMu        sync.Mutex
	backlog          []string
	backlogTotalSize int64
	maxBacklogSize   int64 = 10 * 1024 * 1024 // 10MB
)

func init() {
	if nodeName == "" {
		nodeName, _ = os.Hostname()
	}
	if mode == "" {
		mode = "master"
	}
	if err := os.MkdirAll(historyDir, 0750); err != nil {
		log.Printf("Error creating history directory: %v", err)
	}
	loadStatsFromHistory()
}

func loadStatsFromHistory() {
	files, err := os.ReadDir(historyDir)
	if err != nil {
		return
	}
	now := time.Now().Unix()
	cutoff := now - 72*3600

	for _, f := range files {
		if strings.HasPrefix(f.Name(), "history-") && strings.HasSuffix(f.Name(), ".jsonl") {
			path := filepath.Join(historyDir, filepath.Clean(f.Name()))
			file, err := os.Open(path)
			if err != nil {
				continue
			}
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				var e QueryEvent
				if err := json.Unmarshal(scanner.Bytes(), &e); err == nil {
					if e.UnixTime >= cutoff {
						hour := e.UnixTime / 3600
						statsMu.Lock()
						hourlyStats[hour]++
						statsMu.Unlock()
					}
				}
			}
			_ = file.Close()
		}
	}
	log.Printf("Warmed up stats: %d buckets loaded", len(hourlyStats))
}

func startHistoryArchiver() {
	ticker := time.NewTicker(30 * time.Minute)
	// Initial lastArchivedTime to now - 1h so we don't dump the whole initial buffer immediately
	lastArchivedTime = time.Now().Add(-1 * time.Hour).Unix()

	for range ticker.C {
		archiveStep(time.Now())
	}
}

func archiveStep(now time.Time) int {
	cutoff := now.Add(-1 * time.Hour).Unix()
	
	var toArchive []QueryEvent
	eventsMu.RLock()
	for i := 0; i < count; i++ {
		idx := (head - 1 - i + maxEvents) % maxEvents
		e := events[idx]
		if e.UnixTime > lastArchivedTime && e.UnixTime <= cutoff {
			toArchive = append(toArchive, e)
		}
	}
	eventsMu.RUnlock()

	if len(toArchive) > 0 {
		sort.Slice(toArchive, func(i, j int) bool {
			return toArchive[i].UnixTime < toArchive[j].UnixTime
		})

		files := make(map[string][]QueryEvent)
		for _, e := range toArchive {
			dateStr := time.Unix(e.UnixTime, 0).Format("2006-01-02")
			files[dateStr] = append(files[dateStr], e)
		}

		for dateStr, evs := range files {
			path := fmt.Sprintf("%s/history-%s.jsonl", historyDir, dateStr)
			f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600) // #nosec G304
			if err != nil {
				log.Printf("Error opening history file %s: %v", path, err)
				continue
			}
			for _, e := range evs {
				_ = json.NewEncoder(f).Encode(e)
			}
			_ = f.Close()
		}
		lastArchivedTime = cutoff
		log.Printf("Archived %d events to disk", len(toArchive))
	}

	// Cleanup: delete files older than 72h
	files, err := os.ReadDir(historyDir)
	if err == nil {
		for _, f := range files {
			if strings.HasPrefix(f.Name(), "history-") && strings.HasSuffix(f.Name(), ".jsonl") {
				info, err := f.Info()
				if err == nil && now.Sub(info.ModTime()) > 72*time.Hour {
					_ = os.Remove(historyDir + "/" + f.Name())
					log.Printf("Deleted old history file: %s", f.Name())
				}
			}
		}
	}

	// Also cleanup hourly stats older than 72h
	statsMu.Lock()
	cutoffHour := now.Unix()/3600 - 72
	for h := range hourlyStats {
		if h < cutoffHour {
			delete(hourlyStats, h)
		}
	}
	statsMu.Unlock()
	return len(toArchive)
}

// Periodically clean up stale pending queries (older than 10s)
func startPendingCleanup() {
	ticker := time.NewTicker(10 * time.Second)
	for range ticker.C {
		cleanupStep(time.Now())
	}
}

func cleanupStep(now time.Time) int {
	pendingMu.Lock()
	defer pendingMu.Unlock()
	cleaned := 0
	for node, queries := range pendingQueries {
		for dom, start := range queries {
			if now.Sub(start) > 10*time.Second {
				delete(queries, dom)
				delete(pendingUpstreams[node], dom)
				cleaned++
			}
		}
		if len(queries) == 0 {
			delete(pendingQueries, node)
			delete(pendingUpstreams, node)
		}
	}
	return cleaned
}

func sendBatch(client *http.Client, node string, masterURL string, lines []string) error {
	data, err := json.Marshal(map[string]interface{}{"node": node, "batch": lines})
	if err != nil {
		return err
	}
	req, err := http.NewRequest("POST", masterURL+"/api/ingest", bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
	return nil
}

func startForwardWorker() {
	if mode != "slave" || masterURL == "" {
		return
	}
	client := &http.Client{Timeout: 10 * time.Second}
	backoff := 1 * time.Second

	for {
		var lines []string
		backlogMu.Lock()
		if len(backlog) > 0 {
			// Take a batch of up to 100 lines
			batchSize := 100
			if len(backlog) < batchSize {
				batchSize = len(backlog)
			}
			lines = append([]string(nil), backlog[:batchSize]...)
			backlogMu.Unlock()
		} else {
			backlogMu.Unlock()
			// Wait for at least one line
			line, ok := <-forwardChan
			if !ok { return } // Channel closed
			lines = []string{line}
			
			// Try to grab more from chan if available (non-blocking)
			collectMore := true
			for collectMore && len(lines) < 100 {
				select {
				case l := <-forwardChan:
					lines = append(lines, l)
				default:
					collectMore = false
				}
			}

			// Add to backlog for tracking
			backlogMu.Lock()
			for _, l := range lines {
				backlog = append(backlog, l)
				backlogTotalSize += int64(len(l))
			}
			backlogMu.Unlock()
		}

		// Try to send batch
		err := sendBatch(client, nodeName, masterURL, lines)
		if err == nil {
			// Success! Remove batch from backlog
			backlogMu.Lock()
			if len(backlog) >= len(lines) {
				for i := 0; i < len(lines); i++ {
					backlogTotalSize -= int64(len(backlog[i]))
				}
				backlog = backlog[len(lines):]
			}
			backlogMu.Unlock()
			backoff = 1 * time.Second
		} else {
			log.Printf("Error sending batch to master: %v", err)
			time.Sleep(backoff)
			backoff *= 2
			if backoff > 30*time.Second { backoff = 30 * time.Second }
		}
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
		defer func() { _ = gz.Close() }()
		gzw := gzipResponseWriter{Writer: gz, ResponseWriter: w}
		next.ServeHTTP(gzw, r)
	})
}

// Optimized parsing using bytes to avoid allocations
func parseLogBytes(line []byte, node string) {
	now := time.Now()
	parts := bytes.Fields(line)
	if len(parts) < 2 {
		return
	}

	actionIdx := -1
	for i, p := range parts {
		if bytes.HasPrefix(p, []byte("query[")) || 
		   bytes.Equal(p, []byte("forwarded")) || 
		   bytes.Equal(p, []byte("reply")) || 
		   bytes.Equal(p, []byte("config")) || 
		   bytes.Equal(p, []byte("cached")) {
			actionIdx = i
			break
		}
	}

	if actionIdx == -1 {
		return
	}

	action := parts[actionIdx]

	if bytes.HasPrefix(action, []byte("query[")) {
		qType := string(action[6 : len(action)-1])
		if len(parts) < actionIdx+4 {
			return
		}
		domain := string(parts[actionIdx+1])
		clientIP := string(parts[actionIdx+3])

		tsStr := now.Format("Jan _2 15:04:05")
		if actionIdx >= 3 {
			tsStr = string(bytes.Join(parts[:3], []byte(" ")))
		}

		event := QueryEvent{
			Timestamp: tsStr,
			UnixTime:  now.Unix(),
			Type:      qType,
			Domain:    domain,
			ClientIP:  clientIP,
			Node:      node,
		}

		hourBucket := now.Unix() / 3600
		statsMu.Lock()
		hourlyStats[hourBucket]++
		statsMu.Unlock()

		pendingMu.Lock()
		if pendingQueries[node] == nil {
			pendingQueries[node] = make(map[string]time.Time)
		}
		pendingQueries[node][domain] = now
		pendingMu.Unlock()

		eventsMu.Lock()
		if count == maxEvents {
			old := events[head]
			windowDomainCounts[old.Domain]--
			windowClientCounts[old.ClientIP]--
		}
		events[head] = event
		windowDomainCounts[event.Domain]++
		windowClientCounts[event.ClientIP]++
		head = (head + 1) % maxEvents
		if count < maxEvents {
			count++
		}
		eventsMu.Unlock()
		return
	}

	if bytes.Equal(action, []byte("forwarded")) {
		if len(parts) >= actionIdx+4 {
			domain := string(parts[actionIdx+1])
			upstream := string(parts[actionIdx+3])
			pendingMu.Lock()
			if pendingUpstreams[node] == nil {
				pendingUpstreams[node] = make(map[string]string)
			}
			pendingUpstreams[node][domain] = upstream
			pendingMu.Unlock()
		}
		return
	}

	if bytes.Equal(action, []byte("reply")) || bytes.Equal(action, []byte("cached")) || bytes.Equal(action, []byte("config")) {
		if len(parts) >= actionIdx+2 {
			domain := string(parts[actionIdx+1])
			pendingMu.Lock()
			startTime, ok := pendingQueries[node][domain]
			upstream := ""
			switch {
			case bytes.Equal(action, []byte("reply")):
				upstream = pendingUpstreams[node][domain]
			case bytes.Equal(action, []byte("cached")):
				upstream = "System Cache"
			case bytes.Equal(action, []byte("config")):
				upstream = "Local Override"
			default:
				upstream = string(action)
			}

			if ok {
				latency := float64(now.Sub(startTime).Microseconds()) / 1000.0
				delete(pendingQueries[node], domain)
				delete(pendingUpstreams[node], domain)
				pendingMu.Unlock()

				eventsMu.Lock()
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
	ingestReader(os.Stdin)
}

func ingestReader(r io.Reader) {
	scanner := bufio.NewScanner(r)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	log.Println("Log ingestion started with concurrent worker pool...")

	ingestChan := make(chan []byte, 5000)
	for i := 0; i < 4; i++ {
		go func() {
			for b := range ingestChan {
				lineCopy := make([]byte, len(b))
				copy(lineCopy, b)
				
				if mode == "slave" && masterURL != "" {
					lStr := string(lineCopy)
					select {
					case forwardChan <- lStr:
						backlogMu.Lock()
						if backlogTotalSize > maxBacklogSize {
							backlogTotalSize -= int64(len(backlog[0]))
							backlog = backlog[1:]
						}
						backlog = append(backlog, lStr)
						backlogTotalSize += int64(len(lStr))
						backlogMu.Unlock()
					default:
					}
				}
				parseLogBytes(lineCopy, nodeName)
			}
		}()
	}

	for scanner.Scan() {
		b := scanner.Bytes()
		fmt.Println(string(b)) 
		ingestChan <- b
	}
	close(ingestChan)
	if err := scanner.Err(); err != nil {
		log.Printf("Scanner FATAL error: %v", err)
		os.Exit(1)
	}
	log.Println("Ingestion reader closed normally (EOF)")
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

func setupMux() http.Handler {
	tmpl, err := template.ParseFS(templates, "templates/index.html")
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()


	// Slave log ingestion endpoint (Master only)
	mux.HandleFunc("/api/ingest", func(w http.ResponseWriter, r *http.Request) {
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
			parseLogBytes([]byte(payload.Line), payload.Node)
		}
		for _, l := range payload.Batch {
			parseLogBytes([]byte(l), payload.Node)
		}
		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
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
		sinceStr := r.URL.Query().Get("since")
		var since int64
		if sinceStr != "" {
			if _, err := fmt.Sscanf(sinceStr, "%d", &since); err != nil {
				log.Printf("Invalid since parameter %q: %v", sinceStr, err) // #nosec G706
			}
		}

		eventsMu.RLock()
		n := count
		if n > 1000 { n = 1000 }
		
		result := make([]QueryEvent, 0, n)
		for i := 0; i < n; i++ {
			idx := (head - 1 - i + maxEvents) % maxEvents
			e := events[idx]
			if e.UnixTime > since {
				result = append(result, e)
			} else if since > 0 {
				// Since events are ordered by time, we can stop early
				break
			}
		}
		eventsMu.RUnlock()

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(result); err != nil {
			log.Printf("JSON encoding error: %v", err)
		}
	})

	mux.HandleFunc("/api/stats", func(w http.ResponseWriter, _ *http.Request) {
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
		// Using pre-calculated window counts for performance
		for k, v := range windowDomainCounts {
			if v > 0 { domainCounts[k] = v }
		}
		for k, v := range windowClientCounts {
			if v > 0 { clientCounts[k] = v }
		}
		
		// RPM/RPH still require a scan or separate trackers
		// Given we already limited scan to RPM/RPH window, let's keep it optimized
		for i := 0; i < count; i++ {
			idx := (head - 1 - i + maxEvents) % maxEvents
			e := events[idx]
			
			if e.UnixTime < now-3600 { break } // Stop scanning once out of RPH window

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
		}
		eventsMu.RUnlock()

		// Calculate RPD (Day) from bucketed stats for accuracy
		currentHour := now / 3600
		statsMu.RLock()
		for h := currentHour - 23; h <= currentHour; h++ {
			rpd += hourlyStats[h]
		}
		statsMu.RUnlock()

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

	return gzipMiddleware(mux)
}

func main() {
	go startLogIngestion()
	go startPendingCleanup()
	go startHistoryArchiver()
	go startForwardWorker()

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

	handler := setupMux()

	port := os.Getenv("PORT")
	if port == "" {
		port = "35353"
	}

	server := &http.Server{
		Addr:         ":" + port,
		Handler:      handler,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	log.Printf("Starting Advanced Web GUI on %s", server.Addr) // #nosec G706
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}


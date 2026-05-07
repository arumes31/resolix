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
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

//go:embed templates/*
var templates embed.FS

type QueryEvent struct {
	Timestamp string `json:"timestamp"`
	UnixTime  int64  `json:"unix_time"`
	Type      string `json:"type"`
	Domain    string `json:"domain"`
	ClientIP  string `json:"client_ip"`
}

var (
	maxEvents = 1000
	events    = make([]QueryEvent, maxEvents)
	head      = 0 // index for next insertion
	count     = 0 // total items currently in buffer
	eventsMu  sync.RWMutex
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

// Fast parsing without regex
func parseLogLine(line string) *QueryEvent {
	// Look for query marker
	queryIdx := strings.Index(line, "query[")
	if queryIdx == -1 {
		return nil
	}

	// Extract Type
	typeStart := queryIdx + 6
	typeEnd := strings.Index(line[typeStart:], "]")
	if typeEnd == -1 {
		return nil
	}
	qType := line[typeStart : typeStart+typeEnd]

	// Extract Domain
	domainPart := line[typeStart+typeEnd+2:]
	domainEnd := strings.Index(domainPart, " ")
	if domainEnd == -1 {
		return nil
	}
	domain := domainPart[:domainEnd]

	// Extract Client IP
	fromIdx := strings.Index(domainPart, "from ")
	if fromIdx == -1 {
		return nil
	}
	clientIP := strings.TrimSpace(domainPart[fromIdx+5:])

	// Handle Timestamp
	var tsStr string
	now := time.Now()
	if queryIdx > 16 {
		// Potential timestamp at the beginning (e.g., "Jan  1 12:00:00 ")
		tsCandidate := line[:15]
		if _, err := time.Parse("Jan _2 15:04:05", tsCandidate); err == nil {
			tsStr = tsCandidate
		}
	}

	unixTime := now.Unix()
	if tsStr == "" {
		tsStr = now.Format("Jan _2 15:04:05")
	} else {
		t, err := time.Parse("Jan _2 15:04:05", tsStr)
		if err == nil {
			// Syslog doesn't have a year, use current year
			t = t.AddDate(now.Year(), 0, 0)
			unixTime = t.Unix()
		}
	}

	return &QueryEvent{
		Timestamp: tsStr,
		UnixTime:  unixTime,
		Type:      qType,
		Domain:    domain,
		ClientIP:  clientIP,
	}
}

func startLogIngestion() {
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := scanner.Text()
		fmt.Println(line)

		if event := parseLogLine(line); event != nil {
			eventsMu.Lock()
			events[head] = *event
			head = (head + 1) % maxEvents
			if count < maxEvents {
				count++
			}
			eventsMu.Unlock()
		}
	}
	if err := scanner.Err(); err != nil {
		log.Printf("Scanner error: %v", err)
	}
}

// getOrderedEvents returns events from newest to oldest
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

	log.Printf("Starting Web GUI on %s (Extreme Perf Mode)", server.Addr) // #nosec G706
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

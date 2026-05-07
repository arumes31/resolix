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
	"regexp"
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
	events    []QueryEvent
	eventsMu  sync.RWMutex
	maxEvents = 1000
	logRegex  = regexp.MustCompile(`(?:(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+)?dnsmasq\[\d+\]:\s+query\[(\w+)\]\s+([\w\.-]+)\s+from\s+([\d\.:a-fA-F]+)`)
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

func parseLogLine(line string) *QueryEvent {
	matches := logRegex.FindStringSubmatch(line)
	if len(matches) == 5 {
		tsStr := matches[1]
		var unixTime int64
		now := time.Now()

		if tsStr == "" {
			tsStr = now.Format("Jan _2 15:04:05")
			unixTime = now.Unix()
		} else {
			t, err := time.Parse("Jan _2 15:04:05", tsStr)
			if err == nil {
				t = t.AddDate(now.Year(), 0, 0)
				unixTime = t.Unix()
			} else {
				unixTime = now.Unix()
			}
		}

		return &QueryEvent{
			Timestamp: tsStr,
			UnixTime:  unixTime,
			Type:      matches[2],
			Domain:    matches[3],
			ClientIP:  matches[4],
		}
	}
	return nil
}

func startLogIngestion() {
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := scanner.Text()
		fmt.Println(line)

		if event := parseLogLine(line); event != nil {
			eventsMu.Lock()
			events = append([]QueryEvent{*event}, events...)
			if len(events) > maxEvents {
				events = events[:maxEvents]
			}
			eventsMu.Unlock()
		}
	}
	if err := scanner.Err(); err != nil {
		log.Printf("Scanner error: %v", err)
	}
}

func main() {
	tmpl, err := template.ParseFS(templates, "templates/index.html")
	if err != nil {
		log.Fatal(err)
	}

	go startLogIngestion()

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		eventsMu.RLock()
		currentEvents := make([]QueryEvent, len(events))
		copy(currentEvents, events)
		eventsMu.RUnlock()

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
		eventsMu.RLock()
		currentEvents := make([]QueryEvent, len(events))
		copy(currentEvents, events)
		eventsMu.RUnlock()

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

	log.Printf("Starting Web GUI on %s (Memory Mode + Gzip)", server.Addr) // #nosec G706
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

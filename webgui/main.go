package main

import (
	"bufio"
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"regexp"
	"sync"
	"time"
)

//go:embed templates/*
var templates embed.FS

type QueryEvent struct {
	Timestamp string `json:"timestamp"`
	Type      string `json:"type"`
	Domain    string `json:"domain"`
	ClientIP  string `json:"client_ip"`
}

var (
	events    []QueryEvent
	eventsMu  sync.RWMutex
	maxEvents = 1000
	logRegex  = regexp.MustCompile(`^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+dnsmasq\[\d+\]:\s+query\[(\w+)\]\s+([\w\.-]+)\s+from\s+([\d\.:a-fA-F]+)$`)
)

func parseLogLine(line string) *QueryEvent {
	matches := logRegex.FindStringSubmatch(line)
	if len(matches) == 5 {
		return &QueryEvent{
			Timestamp: matches[1],
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
		// Always print to stdout so Docker logs are still available
		fmt.Println(line)

		if event := parseLogLine(line); event != nil {
			eventsMu.Lock()
			events = append([]QueryEvent{*event}, events...) // Newest first
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

	// Start reading logs from stdin in a background goroutine
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
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	log.Printf("Starting Web GUI on %s (Memory Mode)", server.Addr) // #nosec G706
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

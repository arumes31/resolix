package main

import (
	"bufio"
	"bytes"
	"embed"
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
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

var logRegex = regexp.MustCompile(`^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+dnsmasq\[\d+\]:\s+query\[(\w+)\]\s+([\w\.-]+)\s+from\s+([\d\.:a-fA-F]+)$`)

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

func getLastEvents(n string) []QueryEvent {
	logPath := os.Getenv("LOG_PATH")
	if logPath == "" {
		logPath = "/var/log/dnsmasq.log"
	}

	cmd := exec.Command("tail", "-n", n, logPath)
	output, err := cmd.Output()
	if err != nil {
		log.Printf("Error reading log: %v", err)
		return nil
	}

	var events []QueryEvent
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		if event := parseLogLine(scanner.Text()); event != nil {
			events = append(events, *event)
		}
	}

	if err := scanner.Err(); err != nil {
		log.Printf("Scanner error: %v", err)
	}

	// Reverse to show latest first
	for i, j := 0, len(events)-1; i < j; i, j = i+1, j-1 {
		events[i], events[j] = events[j], events[i]
	}

	return events
}

func main() {
	tmpl, err := template.ParseFS(templates, "templates/index.html")
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		events := getLastEvents("2000")
		if len(events) > 1000 {
			events = events[:1000]
		}

		var buf bytes.Buffer
		if err := tmpl.Execute(&buf, map[string]interface{}{
			"Events": events,
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
		events := getLastEvents("2000")
		if len(events) > 1000 {
			events = events[:1000]
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(events); err != nil {
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

	log.Printf("Starting Web GUI on %s", server.Addr)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

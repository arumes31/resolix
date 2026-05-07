package main

import (
	"bufio"
	"embed"
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
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
	cmd := exec.Command("tail", "-n", n, "/var/log/dnsmasq.log")
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

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		events := getLastEvents("2000") // Get more to ensure we have 1000 valid events
		if len(events) > 1000 {
			events = events[:1000]
		}
		if err := tmpl.Execute(w, map[string]interface{}{
			"Events": events,
		}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	http.HandleFunc("/api/events", func(w http.ResponseWriter, r *http.Request) {
		events := getLastEvents("2000")
		if len(events) > 1000 {
			events = events[:1000]
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(events); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "35353"
	}

	log.Printf("Starting Web GUI on :%s", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatal(err)
	}
}

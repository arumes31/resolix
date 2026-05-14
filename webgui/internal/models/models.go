package models

import (
	"encoding/json"
	"fmt"
	"time"
)

// QueryEvent represents a single DNS query and its associated metadata.
type QueryEvent struct {
	UnixTime int64    `json:"unix_time"`
	Type     string   `json:"type"`
	Domain   string   `json:"domain"`
	ClientIP string   `json:"client_ip"`
	Latency  *float64 `json:"latency_ms,omitempty"`
	Upstream string   `json:"upstream,omitempty"`
	Node     string   `json:"node,omitempty"`
	Alias    string   `json:"alias,omitempty"`
	ID       string   `json:"id"`
}

// TimestampFormatted returns a human-readable time string for the template.
func (e QueryEvent) TimestampFormatted() string {
	return time.Unix(e.UnixTime, 0).Format("15:04:05")
}

// LatencyFormatted returns a human-readable latency string for the template.
func (e QueryEvent) LatencyFormatted() string {
	if e.Latency == nil {
		return "-"
	}
	return fmt.Sprintf("%.1fms", *e.Latency)
}

// MarshalJSON provides custom JSON serialization to add human-readable timestamps and latencies.
func (e QueryEvent) MarshalJSON() ([]byte, error) {
	type Alias QueryEvent
	return json.Marshal(&struct {
		Timestamp          string `json:"timestamp"`
		TimestampFormatted string `json:"timestampFormatted"`
		LatencyFormatted   string `json:"latencyFormatted"`
		Alias
	}{
		Timestamp:          time.Unix(e.UnixTime, 0).Format(time.Stamp),
		TimestampFormatted: e.TimestampFormatted(),
		LatencyFormatted:   e.LatencyFormatted(),
		Alias:              (Alias)(e),
	})
}

// StatEntry is a generic key-count pair used for top domains and top clients statistics.
type StatEntry struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
	Trend string `json:"trend,omitempty"`
	Alias string `json:"alias,omitempty"`
}

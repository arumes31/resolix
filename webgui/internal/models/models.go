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
	ID       string   `json:"id"`
}

// MarshalJSON provides custom JSON serialization to add human-readable timestamps and latencies.
func (e QueryEvent) MarshalJSON() ([]byte, error) {
	type Alias QueryEvent
	latencyFormatted := "-"
	if e.Latency != nil {
		latencyFormatted = fmt.Sprintf("%.1fms", *e.Latency)
	}

	return json.Marshal(&struct {
		Timestamp          string `json:"timestamp"`
		TimestampFormatted string `json:"TimestampFormatted"`
		LatencyFormatted   string `json:"LatencyFormatted"`
		Alias
	}{
		Timestamp:          time.Unix(e.UnixTime, 0).Format(time.Stamp),
		TimestampFormatted: time.Unix(e.UnixTime, 0).Format("15:04:05"),
		LatencyFormatted:   latencyFormatted,
		Alias:              (Alias)(e),
	})
}

// StatEntry is a generic key-count pair used for top domains and top clients statistics.
type StatEntry struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

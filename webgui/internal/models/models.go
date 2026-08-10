package models

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// QueryEvent represents a single DNS query and its associated metadata.
type QueryEvent struct {
	UnixTime       int64           `json:"unix_time"`
	Type           string          `json:"type"`
	Domain         string          `json:"domain"`
	ClientIP       string          `json:"client_ip"`
	Latency        sql.NullFloat64 `json:"-"`
	Upstream       string          `json:"upstream,omitempty"`
	Node           string          `json:"node,omitempty"`
	Alias          string          `json:"alias,omitempty"`
	ID             string          `json:"id"`
	DNSSEC         string          `json:"dnssec,omitempty"`          // "secure", "insecure", "bogus", "indeterminate", or empty
	ClientHostname string          `json:"client_hostname,omitempty"` // Reverse DNS lookup result
	Blocked        bool            `json:"blocked,omitempty"`         // True if domain matches blocklist
	ResponseCode   string          `json:"response_code,omitempty"`   // NOERROR, NXDOMAIN, SERVFAIL, REFUSED, TIMEOUT
	LatencyAlert   bool            `json:"latency_alert,omitempty"`   // True if latency exceeds threshold
	MatchedRule    string          `json:"matched_rule,omitempty"`    // Filter rule that matched (when blocked/allowed)
	BlockReason    string          `json:"block_reason,omitempty"`    // Machine-readable block reason (e.g. FilteredByBlocklist)
}

// TimestampFormatted returns a human-readable time string for the template.
func (e QueryEvent) TimestampFormatted() string {
	return time.Unix(e.UnixTime, 0).Format("15:04:05")
}

// LatencyFormatted returns a human-readable latency string for the template.
func (e QueryEvent) LatencyFormatted() string {
	if !e.Latency.Valid {
		return "-"
	}
	return fmt.Sprintf("%.1fms", e.Latency.Float64)
}

// MarshalJSON provides custom JSON serialization to add human-readable timestamps and latencies.
func (e QueryEvent) MarshalJSON() ([]byte, error) {
	type Alias QueryEvent
	var latency *float64
	if e.Latency.Valid {
		latency = &e.Latency.Float64
	}
	return json.Marshal(&struct {
		Timestamp          string   `json:"timestamp"`
		TimestampFormatted string   `json:"timestampFormatted"`
		LatencyFormatted   string   `json:"latencyFormatted"`
		Latency            *float64 `json:"latency_ms,omitempty"`
		Alias
	}{
		Timestamp:          time.Unix(e.UnixTime, 0).Format(time.Stamp),
		TimestampFormatted: e.TimestampFormatted(),
		LatencyFormatted:   e.LatencyFormatted(),
		Latency:            latency,
		Alias:              (Alias)(e),
	})
}

// UnmarshalJSON accepts latency_ms as a JSON number or null.
func (e *QueryEvent) UnmarshalJSON(data []byte) error {
	type Alias QueryEvent
	aux := struct {
		Latency *float64 `json:"latency_ms"`
		*Alias
	}{Alias: (*Alias)(e)}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	if aux.Latency == nil {
		e.Latency = sql.NullFloat64{}
	} else {
		e.Latency = sql.NullFloat64{Float64: *aux.Latency, Valid: true}
	}
	return nil
}

// StatEntry is a generic key-count pair used for top domains and top clients statistics.
type StatEntry struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
	Trend string `json:"trend,omitempty"`
	Alias string `json:"alias,omitempty"`
}

// NodeStatus represents the current status of a node in the distributed cluster (Items 85-94).
type NodeStatus struct {
	Name           string             `json:"name"`
	LastSeen       time.Time          `json:"last_seen"`
	Online         bool               `json:"online"`
	Version        string             `json:"version,omitempty"`
	GoVersion      string             `json:"go_version,omitempty"`
	BuildInfo      string             `json:"build_info,omitempty"`
	MemoryMB       float64            `json:"memory_mb,omitempty"`
	Goroutines     int                `json:"goroutines,omitempty"`
	DBSizeMB       float64            `json:"db_size_mb,omitempty"`
	UpstreamHealth map[string]float64 `json:"upstream_health,omitempty"`
	ConfigRevision string             `json:"config_revision,omitempty"`
}

// IsOnline returns whether the node is considered online based on the offline threshold.
func (n *NodeStatus) IsOnline(threshold time.Duration) bool {
	return time.Since(n.LastSeen) < threshold
}

// HeartbeatPayload represents the heartbeat data sent from slave to master (Item 92).
type HeartbeatPayload struct {
	Node           string             `json:"node"`
	Version        string             `json:"version,omitempty"`
	GoVersion      string             `json:"go_version,omitempty"`
	BuildInfo      string             `json:"build_info,omitempty"`
	MemoryMB       float64            `json:"memory_mb,omitempty"`
	Goroutines     int                `json:"goroutines,omitempty"`
	DBSizeMB       float64            `json:"db_size_mb,omitempty"`
	Health         map[string]float64 `json:"health,omitempty"`
	ConfigRevision string             `json:"config_revision,omitempty"`
}

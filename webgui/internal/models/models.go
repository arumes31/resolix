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
	CacheStatus    string          `json:"cache_status,omitempty"`    // fresh, stale, prefetched, or negative
	CacheTTL       uint32          `json:"cache_ttl,omitempty"`       // remaining cache TTL returned to the client
	NegativeSOA    string          `json:"negative_soa,omitempty"`    // SOA owner used for negative-cache TTL
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
	ID                      string             `json:"id,omitempty"`
	Name                    string             `json:"name"`
	LastSeen                time.Time          `json:"last_seen"`
	Online                  bool               `json:"online"`
	Version                 string             `json:"version,omitempty"`
	GoVersion               string             `json:"go_version,omitempty"`
	BuildInfo               string             `json:"build_info,omitempty"`
	MemoryMB                float64            `json:"memory_mb,omitempty"`
	Goroutines              int                `json:"goroutines,omitempty"`
	DBSizeMB                float64            `json:"db_size_mb,omitempty"`
	UpstreamHealth          map[string]float64 `json:"upstream_health,omitempty"`
	ConfigRevision          string             `json:"config_revision,omitempty"`
	DesiredConfigRevision   string             `json:"desired_config_revision,omitempty"`
	PreviousConfigRevision  string             `json:"previous_config_revision,omitempty"`
	ConfigSchemaVersion     int                `json:"config_schema_version,omitempty"`
	ConfigSchemaCompatible  bool               `json:"config_schema_compatible"`
	ConfigApplyError        string             `json:"config_apply_error,omitempty"`
	ConfigApplyDurationMS   int64              `json:"config_apply_duration_ms"`
	ClockSkewMS             int64              `json:"clock_skew_ms"`
	ForwarderBacklogDepth   int                `json:"forwarder_backlog_depth"`
	ForwarderBacklogBytes   int64              `json:"forwarder_backlog_bytes"`
	ForwarderBacklogOldestS float64            `json:"forwarder_backlog_oldest_seconds"`
	ForwarderEndpointErrors map[string]string  `json:"forwarder_endpoint_errors,omitempty"`
	LastIngestError         string             `json:"last_ingest_error,omitempty"`
	LastHeartbeatError      string             `json:"last_heartbeat_error,omitempty"`
	LastConfigSyncError     string             `json:"last_config_sync_error,omitempty"`
	SourceAddress           string             `json:"source_address,omitempty"`
	DuplicateNameWarning    bool               `json:"duplicate_name_warning,omitempty"`
}

// IsOnline returns whether the node is considered online based on the offline threshold.
func (n *NodeStatus) IsOnline(threshold time.Duration) bool {
	return time.Since(n.LastSeen) < threshold
}

// HeartbeatPayload represents the heartbeat data sent from agent to controller (Item 92).
type HeartbeatPayload struct {
	NodeID                  string             `json:"node_id,omitempty"`
	Node                    string             `json:"node"`
	SentAt                  time.Time          `json:"sent_at,omitempty"`
	Version                 string             `json:"version,omitempty"`
	GoVersion               string             `json:"go_version,omitempty"`
	BuildInfo               string             `json:"build_info,omitempty"`
	MemoryMB                float64            `json:"memory_mb,omitempty"`
	Goroutines              int                `json:"goroutines,omitempty"`
	DBSizeMB                float64            `json:"db_size_mb,omitempty"`
	Health                  map[string]float64 `json:"health,omitempty"`
	ConfigRevision          string             `json:"config_revision,omitempty"`
	DesiredConfigRevision   string             `json:"desired_config_revision,omitempty"`
	PreviousConfigRevision  string             `json:"previous_config_revision,omitempty"`
	ConfigSchemaVersion     int                `json:"config_schema_version,omitempty"`
	ConfigSchemaCompatible  bool               `json:"config_schema_compatible"`
	ConfigApplyError        string             `json:"config_apply_error,omitempty"`
	ConfigApplyDurationMS   int64              `json:"config_apply_duration_ms"`
	ForwarderBacklogDepth   int                `json:"forwarder_backlog_depth"`
	ForwarderBacklogBytes   int64              `json:"forwarder_backlog_bytes"`
	ForwarderBacklogOldestS float64            `json:"forwarder_backlog_oldest_seconds"`
	ForwarderEndpointErrors map[string]string  `json:"forwarder_endpoint_errors,omitempty"`
	LastIngestError         string             `json:"last_ingest_error,omitempty"`
	LastHeartbeatError      string             `json:"last_heartbeat_error,omitempty"`
	LastConfigSyncError     string             `json:"last_config_sync_error,omitempty"`
}

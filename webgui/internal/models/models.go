package models

// QueryEvent represents a single DNS query and its associated metadata.
type QueryEvent struct {
	Timestamp          string   `json:"timestamp"`
	TimestampFormatted string   `json:"TimestampFormatted"`
	UnixTime           int64    `json:"unix_time"`
	Type               string   `json:"type"`
	Domain             string   `json:"domain"`
	ClientIP           string   `json:"client_ip"`
	Latency            *float64 `json:"latency_ms,omitempty"`
	LatencyFormatted   string   `json:"LatencyFormatted"`
	Upstream           string   `json:"upstream,omitempty"`
	Node               string   `json:"node,omitempty"`
	ID                 string   `json:"id"`
}

// StatEntry is a generic key-count pair used for top domains and top clients statistics.
type StatEntry struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

package config

import (
	"os"
	"strings"
	"time"
)

const (
	// DefaultPort is the default listening port for the web GUI.
	DefaultPort = "35353"
	// DefaultHistoryDir is the default directory for JSONL history files.
	DefaultHistoryDir = "/var/lib/tailscale-dnsrewrite"
	// DefaultMaxEvents is the maximum number of events to keep in memory.
	DefaultMaxEvents = 100000
	// DefaultHealthDomain is the domain used for upstream health checks.
	DefaultHealthDomain = "google.com"
	// DefaultCleanupInterval is the interval for cleaning up stale pending queries.
	DefaultCleanupInterval = 10 * time.Second
	// DefaultArchiveInterval is the interval for archiving memory buffer to disk.
	DefaultArchiveInterval = 30 * time.Minute
	// DefaultScanLimit is the limit for scanning the ring buffer for updates.
	DefaultScanLimit = 1000
	// DefaultMaxBacklogSize is the maximum size of the slave backlog before dropping.
	DefaultMaxBacklogSize = 10 * 1024 * 1024 // 10MB
	// DefaultHistoryRetention is the time to keep history files on disk.
	DefaultHistoryRetention = 72 * time.Hour
)

// Config holds the application configuration.
type Config struct {
	Mode             string
	MasterURL        string
	NodeName         string
	Port             string
	HistoryDir       string
	HistoryPassword  string
	MaxEvents        int
	HealthDomain     string
	CleanupInterval  time.Duration
	ArchiveInterval  time.Duration
	HistoryRetention time.Duration
	IngestSecret     string
}

// LoadConfig reads configuration from environment variables.
func LoadConfig() *Config {
	mode := strings.ToLower(os.Getenv("MODE"))
	if mode == "" {
		mode = "master"
	}

	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		nodeName, _ = os.Hostname()
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = DefaultPort
	}

	historyDir := os.Getenv("HISTORY_DIR")
	if historyDir == "" {
		historyDir = DefaultHistoryDir
	}

	healthDomain := os.Getenv("HEALTHCHECK_DOMAIN")
	if healthDomain == "" {
		healthDomain = DefaultHealthDomain
	}

	return &Config{
		Mode:             mode,
		MasterURL:        os.Getenv("MASTER_URL"),
		NodeName:         nodeName,
		Port:             port,
		HistoryDir:       historyDir,
		HistoryPassword:  os.Getenv("HISTORY_PASSWORD"),
		MaxEvents:        DefaultMaxEvents,
		HealthDomain:     healthDomain,
		CleanupInterval:  DefaultCleanupInterval,
		ArchiveInterval:  DefaultArchiveInterval,
		HistoryRetention: DefaultHistoryRetention,
		IngestSecret:     os.Getenv("INGEST_SECRET"),
	}
}

package config

import (
	"os"
	"strings"
	"time"
)

const (
	// DefaultPort is the fallback port if PORT is not set.
	DefaultPort = "35353"
	DefaultHistoryDir       = "/var/lib/tailscale-dnsrewrite"
	DefaultMaxEvents        = 100000
	DefaultHealthDomain     = "google.com"
	DefaultCleanupInterval  = 10 * time.Second
	DefaultArchiveInterval  = 30 * time.Minute
	DefaultScanLimit        = 1000
	DefaultMaxBacklogSize   = 10 * 1024 * 1024 // 10MB
	DefaultHistoryRetention = 72 * time.Hour
)

// Config holds the application configuration.
type Config struct {
	Mode             string
	MasterURL        string
	NodeName         string
	Port             string
	HistoryDir       string
	MaxEvents        int
	HealthDomain     string
	CleanupInterval  time.Duration
	ArchiveInterval  time.Duration
	HistoryRetention time.Duration
}

// LoadConfig initializes configuration from environment variables and defaults.
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
		MaxEvents:        DefaultMaxEvents,
		HealthDomain:     healthDomain,
		CleanupInterval:  DefaultCleanupInterval,
		ArchiveInterval:  DefaultArchiveInterval,
		HistoryRetention: DefaultHistoryRetention,
	}
}

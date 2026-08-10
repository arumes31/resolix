package config

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"maps"
	"net"
	"net/url"
	"os"
	pathpkg "path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

const (
	// ModeController is the authoritative cluster role.
	ModeController = "controller"
	// ModeAgent is the managed resolver role.
	ModeAgent = "agent"
	// DefaultPort is the default listening port for the web GUI.
	DefaultPort = "35353"
	// DefaultWebListenAddr is the default web/API bind address.
	DefaultWebListenAddr = "0.0.0.0"
	// DefaultHistoryDir is the default directory for JSONL history files.
	DefaultHistoryDir = "/var/lib/resolix"
	// DefaultDBPath is the default database file name.
	DefaultDBPath = "dns.db"
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
	// DefaultMaxBacklogSize is the maximum size of the agent backlog before dropping.
	DefaultMaxBacklogSize = 10 * 1024 * 1024 // 10MB
	// DefaultHistoryRetention is the time to keep history files on disk.
	DefaultHistoryRetention = 72 * time.Hour
	// DefaultLogLevel is the default logging level.
	DefaultLogLevel = "INFO"
	// DefaultBaseURL is the default base URL for reverse proxy subpaths.
	DefaultBaseURL = "/"
	// DefaultClientAliasesReloadInterval is how often to reload the aliases file.
	DefaultClientAliasesReloadInterval = 30 * time.Second
	// DefaultBlocklistFile is the default path to the blocklist hosts file.
	DefaultBlocklistFile = ""
	// DefaultUpstreamsFile is the default path to the upstreams JSON file.
	DefaultUpstreamsFile = "upstreams.json"
	// DefaultDNSRoutesFile is the default path to the DNS routes JSON file.
	DefaultDNSRoutesFile = ""
	// DefaultDNSMasqPIDFile is the default path to the dnsmasq PID file.
	//
	// Deprecated: dnsmasq has been replaced by the in-process DNS server.
	DefaultDNSMasqPIDFile = "/run/dnsmasq.pid"
	// DefaultDNSListenAddr is the default DNS server listen address.
	DefaultDNSListenAddr = "0.0.0.0"
	// DefaultDNSListenPort is the default DNS server listen port.
	DefaultDNSListenPort = 53
	// DefaultFilterUpdateInterval is the default filter subscription update interval.
	DefaultFilterUpdateInterval = 24 * time.Hour
	// DefaultBlockingMode is the default blocking response mode.
	DefaultBlockingMode = "nxdomain"
	// DefaultBlockCustomIP4 is the default A answer in custom_ip blocking mode.
	DefaultBlockCustomIP4 = "0.0.0.0"
	// DefaultBlockCustomIP6 is the default AAAA answer in custom_ip blocking mode.
	DefaultBlockCustomIP6 = "::"
	// DefaultRewritesFile is the default DNS rewrites persistence file name.
	DefaultRewritesFile = "rewrites.json"
	// DefaultClientsFile is the default per-client registry file name.
	DefaultClientsFile = "clients.json"
	// DefaultRateLimitQPS is the default per-subnet query rate limit.
	DefaultRateLimitQPS = 20
	// DefaultDoHPath is the default DNS-over-HTTPS endpoint path.
	DefaultDoHPath = "/dns-query"
	// DefaultDoTPort is the default DNS-over-TLS listen port.
	DefaultDoTPort = 853

	// minCacheTTLDefault/maxCacheTTLDefault are the default cache TTL bounds
	// in seconds (dnsmasq local-ttl=60 / max-ttl=600).
	minCacheTTLDefault = 60
	maxCacheTTLDefault = 600
	// DefaultUpstreamLatencyThreshold is the default latency alert threshold in milliseconds.
	DefaultUpstreamLatencyThreshold = 200

	// DefaultSSEKeepaliveInterval is the default interval for SSE keepalive messages.
	DefaultSSEKeepaliveInterval = 30 * time.Second
	// DefaultBatchArchiveInterval is the default interval for batch archiving to SQLite.
	DefaultBatchArchiveInterval = 30 * time.Minute
	// DefaultArchiveQueueCapacity is the maximum number of events waiting for SQLite.
	DefaultArchiveQueueCapacity = 100000
	// DefaultArchiveTriggerSize starts an archive pass before the queue is full.
	DefaultArchiveTriggerSize = 5000
	// DefaultArchiveWriteBatchSize bounds each SQLite transaction.
	DefaultArchiveWriteBatchSize = 5000
	// DefaultCleanupPendingInterval is the default interval for cleaning up stale pending queries.
	DefaultCleanupPendingInterval = 1 * time.Hour
	// DefaultForwarderRetryInterval is the default initial retry interval for the forwarder.
	DefaultForwarderRetryInterval = 5 * time.Second
	// DefaultHTTPReadTimeout is the default HTTP server read timeout.
	DefaultHTTPReadTimeout = 10 * time.Second
	// DefaultHTTPWriteTimeout is the default HTTP server write timeout.
	DefaultHTTPWriteTimeout = 30 * time.Second
	// DefaultHTTPShutdownTimeout is the default HTTP server graceful shutdown timeout.
	DefaultHTTPShutdownTimeout = 10 * time.Second
	// DefaultMaxRequestSize is the default maximum HTTP request body size in bytes (1MB).
	DefaultMaxRequestSize = 1048576
	// DefaultLogFile is the default log file path (empty means stderr only).
	DefaultLogFile = ""

	// Item 85-94: Distributed architecture defaults

	// DefaultMaxRetryAttempts is the maximum number of retry attempts for forwarding.
	DefaultMaxRetryAttempts = 6
	// DefaultHeartbeatInterval is the default interval for agent heartbeats to controller.
	DefaultHeartbeatInterval = 30 * time.Second
	// DefaultSyncAliasesInterval is the default interval for syncing client aliases from controller.
	DefaultSyncAliasesInterval = 5 * time.Minute
	// DefaultSyncDNSRoutesInterval is the default interval for syncing DNS routes from controller.
	DefaultSyncDNSRoutesInterval = 5 * time.Minute
	// DefaultSyncUpstreamHealthInterval is the default interval for syncing upstream health from controller.
	DefaultSyncUpstreamHealthInterval = 1 * time.Minute
	// DefaultNodeOfflineThreshold is the time after which a node is considered offline without heartbeat.
	DefaultNodeOfflineThreshold = 90 * time.Second
)

// Config holds the application configuration.
type Config struct {
	Mode             string
	ControllerURL    string
	NodeName         string
	Port             string
	WebListenAddr    string
	HistoryDir       string
	DBPath           string
	MaxEvents        int
	HealthDomain     string
	CleanupInterval  time.Duration
	ArchiveInterval  time.Duration
	HistoryRetention time.Duration
	IngestSecret     string
	WebUsername      string
	WebPassword      string
	ScanLimit        int
	MaxBacklogSize   int64
	UpstreamDNS      string
	clientAliases    map[string]string
	clientAliasesMu  sync.RWMutex
	TrustedProxies   []string
	Debug            bool
	LogLevel         string
	BaseURL          string

	// ClientAliasesFile is the path to a file with IP=Alias entries.
	ClientAliasesFile string
	// aliasesProvider manages file-based aliases with periodic reload.
	aliasesProvider *clientAliasesProvider

	// BlocklistFile is the path to a hosts-format blocklist file.
	BlocklistFile string
	// UpstreamsFile is the path to the upstream DNS servers JSON file.
	UpstreamsFile string
	// DNSRoutesFile is the path to the domain-specific DNS routes JSON file.
	DNSRoutesFile string
	// DNSMasqPIDFile is retained only to recognize the deprecated setting.
	//
	// Deprecated: kept for backward compatibility; cache clear is in-process.
	DNSMasqPIDFile string
	// DNSListenAddr is the DNS server listen address (DNS_LISTEN_ADDR,
	// falling back to TAILSCALE_IP, then 0.0.0.0).
	DNSListenAddr string
	// DNSListenPort is the DNS server listen port (DNS_LISTEN_PORT, default 53).
	DNSListenPort int
	// Domains holds the raw DOMAINS env value (comma-separated domain:ip
	// static rewrites, same semantics as dnsmasq address=/).
	Domains string
	// BlocklistURLs holds space/comma-separated filter subscription URLs.
	BlocklistURLs string
	// AllowlistURLs holds space/comma-separated exception subscription URLs.
	AllowlistURLs string
	// AllowlistFile is a local exceptions-only filter list path.
	AllowlistFile string
	// FilterUpdateInterval is the subscription refresh interval.
	FilterUpdateInterval time.Duration
	// BlockingMode is the blocked-response mode: nxdomain|null_ip|refused|custom_ip.
	BlockingMode string
	// BlockCustomIP4/IP6 are the answer addresses in custom_ip mode.
	BlockCustomIP4 string
	BlockCustomIP6 string
	// RewritesFile is the typed-rewrites JSON persistence file.
	RewritesFile string
	// SafeSearch lists enabled safe-search engines (comma-separated).
	SafeSearch string
	// BogusNXDOMAIN lists bogus-answer CIDRs/IPs (comma/space-separated).
	BogusNXDOMAIN string
	// AAAADisabled makes AAAA queries return NODATA.
	AAAADisabled bool
	// RefuseANY refuses QTYPE ANY queries (default true).
	RefuseANY bool
	// UpstreamMode selects pool behavior: load_balance (default) | parallel | strict.
	UpstreamMode string
	// FallbackDNS lists fallback upstreams used only when all primaries fail.
	FallbackDNS string
	// BootstrapDNS lists plain UDP resolvers for hostname upstreams.
	BootstrapDNS string
	// ECSClientSubnet is the EDNS0 client subnet attached to upstream queries.
	ECSClientSubnet string
	// DNS64 enables AAAA synthesis; DNS64Prefixes overrides the prefix list.
	DNS64         bool
	DNS64Prefixes string
	// CacheMinTTL/CacheMaxTTL override cache TTL bounds (seconds).
	CacheMinTTL uint32
	CacheMaxTTL uint32
	// CacheOptimistic serves stale entries while refreshing in background.
	CacheOptimistic bool
	// ClientsFile is the per-client registry JSON file.
	ClientsFile string
	// BlockedServices lists globally blocked service IDs (comma-separated).
	BlockedServices string
	// DNSAllowedClients restricts DNS service to these IPs/CIDRs when non-empty.
	DNSAllowedClients string
	// DNSDisallowedClients drops queries from these IPs/CIDRs silently.
	DNSDisallowedClients string
	// RateLimitQPS limits queries per second per subnet (0 = disabled).
	RateLimitQPS int
	// PrivatePTR answers PTR for known private clients locally (default true).
	PrivatePTR bool
	// DNSSEC enables DO-bit passthrough to upstreams (no local validation).
	DNSSEC bool
	// DoHEnabled serves DNS-over-HTTPS on the HTTP mux (DOH_PATH).
	DoHEnabled   bool
	DoHPath      string
	DoHAuthToken string
	// DoTEnabled serves DNS-over-TLS on DoTPort (requires TLS cert/key).
	DoTEnabled bool
	DoTPort    int
	// TLSCertFile/TLSKeyFile are required for DoT.
	TLSCertFile string
	TLSKeyFile  string
	// UpstreamLatencyThreshold is the latency threshold in ms for alerting.
	UpstreamLatencyThreshold int

	// Configurable timeout values (Item 80)
	// SSEKeepaliveInterval is the interval for SSE keepalive messages.
	SSEKeepaliveInterval time.Duration
	// BatchArchiveInterval is the interval for batch archiving events to SQLite.
	BatchArchiveInterval time.Duration
	// ArchiveQueueCapacity bounds events waiting for SQLite persistence.
	ArchiveQueueCapacity int
	// ArchiveTriggerSize starts an archive pass at this many pending events.
	ArchiveTriggerSize int
	// ArchiveWriteBatchSize bounds the number of events in each transaction.
	ArchiveWriteBatchSize int
	// CleanupPendingInterval is the interval for cleaning up stale pending queries.
	CleanupPendingInterval time.Duration
	// ForwarderRetryInterval is the initial retry interval for the log forwarder.
	ForwarderRetryInterval time.Duration
	// HTTPReadTimeout is the HTTP server read timeout.
	HTTPReadTimeout time.Duration
	// HTTPWriteTimeout is the HTTP server write timeout.
	HTTPWriteTimeout time.Duration
	// HTTPShutdownTimeout is the HTTP server graceful shutdown timeout.
	HTTPShutdownTimeout time.Duration
	// MaxRequestSize is the maximum HTTP request body size in bytes.
	MaxRequestSize int64
	// LogFile is the path to an optional log file for file-based logging.
	LogFile string

	// Item 85-94: Distributed architecture configuration
	// MaxRetryAttempts is the maximum number of retry attempts for forwarding with exponential backoff.
	MaxRetryAttempts int
	// HeartbeatInterval is the interval for agent heartbeats to controller.
	HeartbeatInterval time.Duration
	// SyncAliasesInterval is the interval for syncing client aliases from controller.
	SyncAliasesInterval time.Duration
	// SyncDNSRoutesInterval is the interval for syncing DNS routes from controller.
	SyncDNSRoutesInterval time.Duration
	// SyncUpstreamHealthInterval is the interval for syncing upstream health from controller.
	SyncUpstreamHealthInterval time.Duration
	// NodeOfflineThreshold is the time after which a node is considered offline.
	NodeOfflineThreshold time.Duration
}

// clientAliasesProvider manages loading and periodic reloading of client aliases from a file.
type clientAliasesProvider struct {
	path    string
	aliases map[string]string
	mu      sync.RWMutex
}

// newClientAliasesProvider creates a new provider and loads the initial aliases from the file.
func newClientAliasesProvider(path string) *clientAliasesProvider {
	p := &clientAliasesProvider{
		path:    path,
		aliases: make(map[string]string),
	}
	p.load()
	return p
}

// load reads the aliases file and updates the in-memory map.
// File format: one entry per line, IP=Alias (e.g., 192.168.1.1=Gateway).
// Lines starting with # are comments, empty lines are skipped.
func (p *clientAliasesProvider) load() {
	newAliases := make(map[string]string)

	file, err := os.Open(p.path)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("[WARN] Client aliases file not found: %s", p.path)
		} else {
			log.Printf("[ERROR] Failed to open client aliases file: %v", err)
		}
		p.mu.Lock()
		p.aliases = newAliases
		p.mu.Unlock()
		return
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			log.Printf("[WARN] Invalid client alias entry at line %d: %q", lineNum, line)
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		if key == "" || val == "" {
			log.Printf("[WARN] Invalid client alias entry at line %d: %q", lineNum, line)
			continue
		}
		newAliases[key] = val
	}

	if err := scanner.Err(); err != nil {
		log.Printf("[ERROR] Error reading client aliases file: %v", err)
	}

	p.mu.Lock()
	p.aliases = newAliases
	p.mu.Unlock()
	log.Printf("[INFO] Loaded %d client aliases from %s", len(newAliases), p.path)
}

// startReload begins periodic reloading of the aliases file.
func (p *clientAliasesProvider) startReload(ctx context.Context) {
	ticker := time.NewTicker(DefaultClientAliasesReloadInterval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				p.load()
			}
		}
	}()
}

// GetAlias returns the alias for the given IP, or empty string if not found.
func (p *clientAliasesProvider) GetAlias(ip string) string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.aliases[ip]
}

// GetAllAliases returns a copy of all aliases.
func (p *clientAliasesProvider) GetAllAliases() map[string]string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	result := make(map[string]string, len(p.aliases))
	for k, v := range p.aliases {
		result[k] = v
	}
	return result
}

// GetClientAlias returns the alias for a given IP address.
// It checks the file-based aliases first, then falls back to the env var aliases.
func (c *Config) GetClientAlias(ip string) string {
	// Check file-based aliases first (more dynamic)
	if c.aliasesProvider != nil {
		if alias := c.aliasesProvider.GetAlias(ip); alias != "" {
			return alias
		}
	}
	// Fall back to env var aliases
	c.clientAliasesMu.RLock()
	defer c.clientAliasesMu.RUnlock()
	if c.clientAliases != nil {
		return c.clientAliases[ip]
	}
	return ""
}

// StartClientAliasesReload starts the periodic reload of the client aliases file.
func (c *Config) StartClientAliasesReload(ctx context.Context) {
	if c.aliasesProvider != nil {
		c.aliasesProvider.startReload(ctx)
	}
}

// SetClientAliases updates the client aliases map (Item 90).
// This is used by the forwarder sync callback to apply aliases synced from the controller.
func (c *Config) SetClientAliases(aliases map[string]string) {
	if aliases == nil {
		return
	}
	c.clientAliasesMu.Lock()
	defer c.clientAliasesMu.Unlock()
	c.clientAliases = maps.Clone(aliases)
}

// GetAllClientAliases returns a copy of the configured client aliases.
// File-based provider aliases are merged over the env var aliases, matching
// GetClientAlias precedence (provider values override environment aliases).
func (c *Config) GetAllClientAliases() map[string]string {
	c.clientAliasesMu.RLock()
	result := maps.Clone(c.clientAliases)
	c.clientAliasesMu.RUnlock()
	if result == nil {
		result = make(map[string]string)
	}
	if c.aliasesProvider != nil {
		for k, v := range c.aliasesProvider.GetAllAliases() {
			result[k] = v
		}
	}
	return result
}

// sanitizeForLog strips CR/LF characters from an untrusted value before it is
// written to the logs, preventing log injection (gosec G706).
func sanitizeForLog(s string) string {
	return strings.NewReplacer("\r", "", "\n", "").Replace(s)
}

// parseDurationEnv reads an environment variable and parses it as a duration.
// Returns the default value if the variable is empty or cannot be parsed.
func parseDurationEnv(key string, defaultVal time.Duration) time.Duration {
	val := os.Getenv(key)
	if val == "" {
		return defaultVal
	}
	d, err := time.ParseDuration(val)
	if err != nil {
		log.Printf("[WARN] Invalid %s '%s', falling back to %s: %v", key, sanitizeForLog(val), defaultVal, err) // #nosec G706 -- CR/LF stripped by sanitizeForLog; gosec taint analysis cannot see through the helper
		return defaultVal
	}
	if d <= 0 {
		log.Printf("[WARN] Invalid %s '%s', falling back to %s: duration must be positive", key, sanitizeForLog(val), defaultVal) // #nosec G706 -- CR/LF stripped by sanitizeForLog; gosec taint analysis cannot see through the helper
		return defaultVal
	}
	return d
}

// parseInt64Env reads an environment variable and parses it as an int64.
// Returns the default value if the variable is empty or cannot be parsed.
func parseInt64Env(key string, defaultVal int64) int64 {
	val := os.Getenv(key)
	if val == "" {
		return defaultVal
	}
	n, err := strconv.ParseInt(val, 10, 64)
	if err != nil || n < 0 {
		log.Printf("[WARN] Invalid %s '%s', falling back to %d: %v", key, sanitizeForLog(val), defaultVal, err) // #nosec G706 -- CR/LF stripped by sanitizeForLog; gosec taint analysis cannot see through the helper
		return defaultVal
	}
	return n
}

// parseIntEnv reads an environment variable and parses it as an int.
// Returns the default value if the variable is empty or cannot be parsed.
func parseIntEnv(key string, defaultVal int) int {
	val := os.Getenv(key)
	if val == "" {
		return defaultVal
	}
	n, err := strconv.Atoi(val)
	if err != nil || n < 0 {
		log.Printf("[WARN] Invalid %s '%s', falling back to %d: %v", key, sanitizeForLog(val), defaultVal, err) // #nosec G706 -- CR/LF stripped by sanitizeForLog; gosec taint analysis cannot see through the helper
		return defaultVal
	}
	return n
}

func resolveArchiveQueueSettings() (capacity, trigger, writeBatch int) {
	capacity = parseIntEnv("ARCHIVE_QUEUE_CAPACITY", DefaultArchiveQueueCapacity)
	if capacity < 1 {
		log.Printf("[WARN] ARCHIVE_QUEUE_CAPACITY must be positive; using %d", DefaultArchiveQueueCapacity)
		capacity = DefaultArchiveQueueCapacity
	}

	trigger = parseIntEnv("ARCHIVE_TRIGGER_SIZE", DefaultArchiveTriggerSize)
	if trigger < 1 || trigger > capacity {
		fallback := min(DefaultArchiveTriggerSize, max(1, capacity/2))
		log.Printf("[WARN] ARCHIVE_TRIGGER_SIZE must be between 1 and ARCHIVE_QUEUE_CAPACITY; using %d", fallback)
		trigger = fallback
	}

	writeBatch = parseIntEnv("ARCHIVE_WRITE_BATCH_SIZE", DefaultArchiveWriteBatchSize)
	if writeBatch < 1 || writeBatch > capacity {
		fallback := min(DefaultArchiveWriteBatchSize, capacity)
		log.Printf("[WARN] ARCHIVE_WRITE_BATCH_SIZE must be between 1 and ARCHIVE_QUEUE_CAPACITY; using %d", fallback)
		writeBatch = fallback
	}
	return capacity, trigger, writeBatch
}

// parseUint32Env reads a non-negative 32-bit integer environment variable.
func parseUint32Env(key string, defaultVal uint32) uint32 {
	val := os.Getenv(key)
	if val == "" {
		return defaultVal
	}
	n, err := strconv.ParseUint(val, 10, 32)
	if err != nil {
		log.Printf("[WARN] Invalid %s '%s', falling back to %d: %v", key, sanitizeForLog(val), defaultVal, err) // #nosec G706 -- CR/LF stripped by sanitizeForLog; gosec taint analysis cannot see through the helper
		return defaultVal
	}
	return uint32(n)
}

// resolveMode reads MODE and normalizes legacy role names.
func resolveMode() string {
	mode := strings.ToLower(strings.TrimSpace(os.Getenv("MODE")))
	switch mode {
	case "", ModeController:
		return ModeController
	case ModeAgent:
		return ModeAgent
	case "master":
		log.Printf("[WARN] MODE=master is deprecated; use MODE=%s", ModeController)
		return ModeController
	case "slave":
		log.Printf("[WARN] MODE=slave is deprecated; use MODE=%s", ModeAgent)
		return ModeAgent
	default:
		log.Printf("[WARN] Invalid MODE '%s', falling back to %s", sanitizeForLog(mode), ModeController) // #nosec G706 -- CR/LF stripped by sanitizeForLog; gosec taint analysis cannot see through the helper
		return ModeController
	}
}

// resolveNodeName reads NODE_NAME, falling back to the OS hostname.
func resolveNodeName() string {
	nodeName := os.Getenv("NODE_NAME")
	if nodeName != "" {
		return nodeName
	}
	host, err := os.Hostname()
	if err != nil {
		log.Printf("[ERROR] Error getting hostname: %v", err)
		return "unknown-node"
	}
	return host
}

// resolvePort reads and validates the PORT environment variable.
func resolvePort() string {
	port := os.Getenv("PORT")
	if port == "" {
		return DefaultPort
	}
	if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
		log.Printf("[WARN] Invalid PORT '%s', falling back to %s", sanitizeForLog(port), DefaultPort) // #nosec G706 -- CR/LF stripped by sanitizeForLog; gosec taint analysis cannot see through the helper
		return DefaultPort
	}
	return port
}

// validateControllerURL exits fatally when controllerURL is set but invalid.
func validateControllerURL(controllerURL string) {
	if controllerURL == "" {
		return
	}
	if !isValidControllerURL(controllerURL) {
		log.Fatalf("[FATAL] Invalid CONTROLLER_URL: must start with https:// (got: %s)", sanitizeForLog(controllerURL)) // #nosec G706 -- CR/LF stripped by sanitizeForLog; gosec taint analysis cannot see through the helper
	}
	if _, err := url.ParseRequestURI(controllerURL); err != nil {
		log.Fatalf("[FATAL] Invalid CONTROLLER_URL: %v", err)
	}
}

func resolveControllerURL() string {
	controllerURL := os.Getenv("CONTROLLER_URL")
	if controllerURL == "" {
		controllerURL = os.Getenv("MASTER_URL")
		if controllerURL != "" {
			log.Printf("[WARN] MASTER_URL is deprecated; use CONTROLLER_URL")
		}
	}
	return strings.TrimSuffix(controllerURL, "/")
}

// loadEnvAliases parses the CLIENT_ALIASES environment variable
// (comma-separated IP:Alias pairs) into a map.
func loadEnvAliases() map[string]string {
	aliases := make(map[string]string)
	if a := os.Getenv("CLIENT_ALIASES"); a != "" {
		for _, pair := range strings.Split(a, ",") {
			parts := strings.Split(pair, ":")
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				val := strings.TrimSpace(parts[1])
				if key == "" || val == "" {
					log.Printf("[WARN] Invalid CLIENT_ALIASES mapping: %q", sanitizeForLog(pair)) // #nosec G706 -- CR/LF stripped by sanitizeForLog; gosec taint analysis cannot see through the helper
					continue
				}
				aliases[key] = val
			} else {
				log.Printf("[WARN] Invalid CLIENT_ALIASES mapping: %q", sanitizeForLog(pair)) // #nosec G706 -- CR/LF stripped by sanitizeForLog; gosec taint analysis cannot see through the helper
			}
		}
	}
	return aliases
}

// parseTrustedProxies parses the TRUSTED_PROXIES environment variable
// (comma-separated list) into a slice.
func parseTrustedProxies() []string {
	var trustedProxies []string
	for _, proxy := range strings.Split(os.Getenv("TRUSTED_PROXIES"), ",") {
		if proxy = strings.TrimSpace(proxy); proxy != "" {
			trustedProxies = append(trustedProxies, proxy)
		}
	}
	return trustedProxies
}

// normalizeBaseURL reads BASE_URL and reduces it to a local, absolute path.
func normalizeBaseURL() string {
	raw := strings.TrimSpace(os.Getenv("BASE_URL"))
	if raw == "" {
		return DefaultBaseURL
	}
	candidate, err := url.Parse(raw)
	if err != nil || candidate.IsAbs() || candidate.Host != "" || candidate.RawQuery != "" ||
		candidate.Fragment != "" || strings.ContainsAny(raw, "\\\r\n") {
		log.Printf("[WARN] Invalid BASE_URL '%s', falling back to %s", sanitizeForLog(raw), DefaultBaseURL) // #nosec G706 -- CR/LF stripped by sanitizeForLog; gosec taint analysis cannot see through the helper
		return DefaultBaseURL
	}
	if !strings.HasPrefix(raw, "/") {
		raw = "/" + raw
	}
	if len(raw) > 1 && raw[0] == '/' && (raw[1] == '/' || raw[1] == '\\') {
		log.Printf("[WARN] Invalid BASE_URL '%s', falling back to %s", sanitizeForLog(raw), DefaultBaseURL) // #nosec G706 -- CR/LF stripped by sanitizeForLog; gosec taint analysis cannot see through the helper
		return DefaultBaseURL
	}
	parsed, err := url.ParseRequestURI(raw)
	if err != nil || parsed.IsAbs() || parsed.Host != "" || parsed.RawQuery != "" ||
		parsed.Fragment != "" {
		log.Printf("[WARN] Invalid BASE_URL '%s', falling back to %s", sanitizeForLog(raw), DefaultBaseURL) // #nosec G706 -- CR/LF stripped by sanitizeForLog; gosec taint analysis cannot see through the helper
		return DefaultBaseURL
	}
	decodedPath, err := url.PathUnescape(parsed.EscapedPath())
	if err != nil || strings.HasPrefix(decodedPath, "//") || strings.ContainsAny(decodedPath, "\\?#") ||
		strings.IndexFunc(decodedPath, unicode.IsControl) >= 0 {
		log.Printf("[WARN] Invalid BASE_URL '%s', falling back to %s", sanitizeForLog(raw), DefaultBaseURL) // #nosec G706 -- CR/LF stripped by sanitizeForLog; gosec taint analysis cannot see through the helper
		return DefaultBaseURL
	}
	cleaned := pathpkg.Clean("/" + strings.TrimLeft(parsed.Path, "/"))
	if cleaned == "." || cleaned == "" {
		return DefaultBaseURL
	}
	return cleaned
}

// resolveLatencyThreshold reads and validates UPSTREAM_LATENCY_THRESHOLD.
func resolveLatencyThreshold() int {
	if lt := os.Getenv("UPSTREAM_LATENCY_THRESHOLD"); lt != "" {
		if val, err := strconv.Atoi(lt); err == nil && val > 0 {
			return val
		}
		log.Printf("[WARN] Invalid UPSTREAM_LATENCY_THRESHOLD '%s', falling back to %d", sanitizeForLog(lt), DefaultUpstreamLatencyThreshold) // #nosec G706 -- CR/LF stripped by sanitizeForLog; gosec taint analysis cannot see through the helper
	}
	return DefaultUpstreamLatencyThreshold
}

// resolveDoHPath reads DOH_PATH and normalizes it to a safe, non-conflicting
// literal path on the existing HTTP mux.
func resolveDoHPath() string {
	p := strings.TrimSpace(os.Getenv("DOH_PATH"))
	if p == "" {
		return DefaultDoHPath
	}
	if strings.HasPrefix(p, "//") || strings.ContainsAny(p, " \t\r\n?#{}\\") {
		log.Printf("[WARN] Invalid DOH_PATH '%s', falling back to %s", sanitizeForLog(p), DefaultDoHPath) // #nosec G706 -- CR/LF stripped by sanitizeForLog; gosec taint analysis cannot see through the helper
		return DefaultDoHPath
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	if len(p) > 1 && (p[1] == '/' || p[1] == '\\') {
		log.Printf("[WARN] Invalid DOH_PATH '%s', falling back to %s", sanitizeForLog(p), DefaultDoHPath) // #nosec G706 -- CR/LF stripped by sanitizeForLog; gosec taint analysis cannot see through the helper
		return DefaultDoHPath
	}
	p = pathpkg.Clean(p)
	if !validDoHPath(p) {
		log.Printf("[WARN] Conflicting DOH_PATH '%s', falling back to %s", sanitizeForLog(p), DefaultDoHPath) // #nosec G706 -- CR/LF stripped by sanitizeForLog; gosec taint analysis cannot see through the helper
		return DefaultDoHPath
	}
	return p
}

func validDoHPath(p string) bool {
	if p == "" || p == "/" || strings.HasPrefix(p, "//") || strings.ContainsAny(p, " \t\r\n?#{}\\") {
		return false
	}
	if p == "/healthz" || p == "/login" || p == "/logout" || p == "/metrics" {
		return false
	}
	return p != "/api" && !strings.HasPrefix(p, "/api/") &&
		p != "/static" && !strings.HasPrefix(p, "/static/")
}

// resolveBlocking reads and validates BLOCKING_MODE and BLOCK_CUSTOM_IP4/IP6.
func resolveBlocking() (mode, ip4, ip6 string) {
	mode = strings.ToLower(strings.TrimSpace(os.Getenv("BLOCKING_MODE")))
	switch mode {
	case "":
		mode = DefaultBlockingMode
	case "nxdomain", "null_ip", "refused", "custom_ip":
	default:
		log.Printf("[WARN] Invalid BLOCKING_MODE '%s', falling back to %s", sanitizeForLog(mode), DefaultBlockingMode) // #nosec G706 -- CR/LF stripped by sanitizeForLog; gosec taint analysis cannot see through the helper
		mode = DefaultBlockingMode
	}
	ip4 = strings.TrimSpace(os.Getenv("BLOCK_CUSTOM_IP4"))
	if parsed := net.ParseIP(ip4); ip4 == "" || parsed == nil || parsed.To4() == nil {
		if ip4 != "" {
			log.Printf("[WARN] Invalid BLOCK_CUSTOM_IP4 '%s', falling back to %s", sanitizeForLog(ip4), DefaultBlockCustomIP4) // #nosec G706 -- CR/LF stripped by sanitizeForLog; gosec taint analysis cannot see through the helper
		}
		ip4 = DefaultBlockCustomIP4
	}
	ip6 = strings.TrimSpace(os.Getenv("BLOCK_CUSTOM_IP6"))
	if parsed := net.ParseIP(ip6); ip6 == "" || parsed == nil || parsed.To4() != nil {
		if ip6 != "" {
			log.Printf("[WARN] Invalid BLOCK_CUSTOM_IP6 '%s', falling back to %s", sanitizeForLog(ip6), DefaultBlockCustomIP6) // #nosec G706 -- CR/LF stripped by sanitizeForLog; gosec taint analysis cannot see through the helper
		}
		ip6 = DefaultBlockCustomIP6
	}
	return mode, ip4, ip6
}

// LoadConfig reads configuration from environment variables.
//
//nolint:gocyclo // Environment mapping is intentionally centralized so defaults remain auditable in one place.
func LoadConfig() *Config {
	mode := resolveMode()

	nodeName := resolveNodeName()

	port := resolvePort()
	webListenAddr := strings.TrimSpace(os.Getenv("WEB_LISTEN_ADDR"))
	if webListenAddr == "" {
		webListenAddr = DefaultWebListenAddr
	}

	historyDir := os.Getenv("HISTORY_DIR")
	if historyDir == "" {
		historyDir = DefaultHistoryDir
	}

	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		dbPath = DefaultDBPath
	}

	healthDomain := os.Getenv("HEALTHCHECK_DOMAIN")
	if healthDomain == "" {
		healthDomain = DefaultHealthDomain
	}

	controllerURL := resolveControllerURL()
	validateControllerURL(controllerURL)

	// Load client aliases from env var
	aliases := loadEnvAliases()

	trustedProxies := parseTrustedProxies()

	// Load client aliases from file
	clientAliasesFile := os.Getenv("CLIENT_ALIASES_FILE")
	var provider *clientAliasesProvider
	if clientAliasesFile != "" {
		provider = newClientAliasesProvider(clientAliasesFile)
		// Merge file aliases into the env var aliases (file takes precedence)
		fileAliases := provider.GetAllAliases()
		for k, v := range fileAliases {
			aliases[k] = v
		}
	}

	logLevel := strings.ToUpper(strings.TrimSpace(os.Getenv("LOG_LEVEL")))
	if logLevel == "" {
		logLevel = DefaultLogLevel
	}

	baseURL := normalizeBaseURL()

	// Load new configuration values
	blocklistFile := os.Getenv("BLOCKLIST_FILE")
	if blocklistFile == "" {
		blocklistFile = DefaultBlocklistFile
	}

	upstreamsFile := os.Getenv("UPSTREAMS_FILE")
	if upstreamsFile == "" {
		upstreamsFile = DefaultUpstreamsFile
	}

	dnsRoutesFile := os.Getenv("DNS_ROUTES_FILE")
	if dnsRoutesFile == "" {
		dnsRoutesFile = DefaultDNSRoutesFile
	}

	rewritesFile := os.Getenv("REWRITES_FILE")
	if rewritesFile == "" {
		rewritesFile = DefaultRewritesFile
	}

	clientsFile := os.Getenv("CLIENTS_FILE")
	if clientsFile == "" {
		clientsFile = DefaultClientsFile
	}

	dnsmasqPIDFile := os.Getenv("DNSMASQ_PID_FILE")
	if dnsmasqPIDFile == "" {
		dnsmasqPIDFile = DefaultDNSMasqPIDFile
	}

	// DNS server listen settings: explicit DNS_LISTEN_ADDR wins, then the
	// TAILSCALE_IP passed through by entrypoint.sh, then 0.0.0.0.
	dnsListenAddr := os.Getenv("DNS_LISTEN_ADDR")
	if dnsListenAddr == "" {
		dnsListenAddr = os.Getenv("TAILSCALE_IP")
	}
	if dnsListenAddr == "" {
		dnsListenAddr = DefaultDNSListenAddr
	}
	dnsListenPort := parseIntEnv("DNS_LISTEN_PORT", DefaultDNSListenPort)
	if dnsListenPort < 1 || dnsListenPort > 65535 {
		log.Printf("[WARN] DNS_LISTEN_PORT %d out of range, falling back to %d", dnsListenPort, DefaultDNSListenPort)
		dnsListenPort = DefaultDNSListenPort
	}
	dotPort := parseIntEnv("DOT_PORT", DefaultDoTPort)
	if dotPort < 1 || dotPort > 65535 {
		log.Printf("[WARN] DOT_PORT %d out of range, falling back to %d", dotPort, DefaultDoTPort)
		dotPort = DefaultDoTPort
	}

	// Filter engine blocking settings
	blockingMode, blockCustomIP4, blockCustomIP6 := resolveBlocking()

	// Upstream pool settings
	upstreamMode := strings.ToLower(strings.TrimSpace(os.Getenv("UPSTREAM_MODE")))
	switch upstreamMode {
	case "":
		upstreamMode = "load_balance"
	case "load_balance", "parallel", "strict":
	default:
		log.Printf("[WARN] Invalid UPSTREAM_MODE '%s', falling back to load_balance", sanitizeForLog(upstreamMode)) // #nosec G706 -- CR/LF stripped by sanitizeForLog; gosec taint analysis cannot see through the helper
		upstreamMode = "load_balance"
	}
	cacheMinTTL := parseUint32Env("CACHE_MIN_TTL", minCacheTTLDefault)
	cacheMaxTTL := parseUint32Env("CACHE_MAX_TTL", maxCacheTTLDefault)
	if cacheMaxTTL < cacheMinTTL {
		log.Printf("[WARN] CACHE_MAX_TTL %d < CACHE_MIN_TTL %d, using defaults %d/%d", cacheMaxTTL, cacheMinTTL, minCacheTTLDefault, maxCacheTTLDefault)
		cacheMinTTL, cacheMaxTTL = minCacheTTLDefault, maxCacheTTLDefault
	}

	latencyThreshold := resolveLatencyThreshold()

	// Parse configurable timeout values (Item 80)
	sseKeepalive := parseDurationEnv("SSE_KEEPALIVE_INTERVAL", DefaultSSEKeepaliveInterval)
	batchArchive := parseDurationEnv("BATCH_ARCHIVE_INTERVAL", DefaultBatchArchiveInterval)
	archiveCapacity, archiveTrigger, archiveWriteBatch := resolveArchiveQueueSettings()
	cleanupPending := parseDurationEnv("CLEANUP_INTERVAL", DefaultCleanupPendingInterval)
	forwarderRetry := parseDurationEnv("FORWARDER_RETRY_INTERVAL", DefaultForwarderRetryInterval)
	httpReadTimeout := parseDurationEnv("HTTP_READ_TIMEOUT", DefaultHTTPReadTimeout)
	httpWriteTimeout := parseDurationEnv("HTTP_WRITE_TIMEOUT", DefaultHTTPWriteTimeout)
	httpShutdownTimeout := parseDurationEnv("HTTP_SHUTDOWN_TIMEOUT", DefaultHTTPShutdownTimeout)
	maxRequestSize := parseInt64Env("MAX_REQUEST_SIZE", DefaultMaxRequestSize)
	logFile := os.Getenv("LOG_FILE")
	if logFile == "" {
		logFile = DefaultLogFile
	}

	// Parse distributed architecture configuration (Items 85-94)
	maxRetryAttempts := parseIntEnv("MAX_RETRY_ATTEMPTS", DefaultMaxRetryAttempts)
	heartbeatInterval := parseDurationEnv("HEARTBEAT_INTERVAL", DefaultHeartbeatInterval)
	syncAliasesInterval := parseDurationEnv("SYNC_ALIASES_INTERVAL", DefaultSyncAliasesInterval)
	syncDNSRoutesInterval := parseDurationEnv("SYNC_DNSROUTES_INTERVAL", DefaultSyncDNSRoutesInterval)
	syncUpstreamHealthInterval := parseDurationEnv("SYNC_UPSTREAM_HEALTH_INTERVAL", DefaultSyncUpstreamHealthInterval)
	nodeOfflineThreshold := parseDurationEnv("NODE_OFFLINE_THRESHOLD", DefaultNodeOfflineThreshold)

	cfg := &Config{
		Mode:                       mode,
		ControllerURL:              controllerURL,
		NodeName:                   nodeName,
		Port:                       port,
		WebListenAddr:              webListenAddr,
		HistoryDir:                 historyDir,
		DBPath:                     dbPath,
		MaxEvents:                  DefaultMaxEvents,
		HealthDomain:               healthDomain,
		CleanupInterval:            DefaultCleanupInterval,
		ArchiveInterval:            batchArchive,
		HistoryRetention:           DefaultHistoryRetention,
		IngestSecret:               os.Getenv("INGEST_SECRET"),
		WebUsername:                os.Getenv("WEB_USERNAME"),
		WebPassword:                os.Getenv("WEB_PASSWORD"),
		ScanLimit:                  DefaultScanLimit,
		MaxBacklogSize:             DefaultMaxBacklogSize,
		UpstreamDNS:                os.Getenv("UPSTREAM_DNS"),
		clientAliases:              aliases,
		TrustedProxies:             trustedProxies,
		Debug:                      strings.ToLower(os.Getenv("DEBUG")) == "true",
		LogLevel:                   logLevel,
		BaseURL:                    baseURL,
		ClientAliasesFile:          clientAliasesFile,
		aliasesProvider:            provider,
		BlocklistFile:              blocklistFile,
		UpstreamsFile:              upstreamsFile,
		DNSRoutesFile:              dnsRoutesFile,
		DNSMasqPIDFile:             dnsmasqPIDFile,
		DNSListenAddr:              dnsListenAddr,
		DNSListenPort:              dnsListenPort,
		Domains:                    os.Getenv("DOMAINS"),
		BlocklistURLs:              os.Getenv("BLOCKLIST_URLS"),
		AllowlistURLs:              os.Getenv("ALLOWLIST_URLS"),
		AllowlistFile:              os.Getenv("ALLOWLIST_FILE"),
		FilterUpdateInterval:       parseDurationEnv("FILTER_UPDATE_INTERVAL", DefaultFilterUpdateInterval),
		BlockingMode:               blockingMode,
		BlockCustomIP4:             blockCustomIP4,
		BlockCustomIP6:             blockCustomIP6,
		RewritesFile:               rewritesFile,
		SafeSearch:                 os.Getenv("SAFE_SEARCH"),
		BogusNXDOMAIN:              os.Getenv("BOGUS_NXDOMAIN"),
		AAAADisabled:               strings.ToLower(os.Getenv("AAAA_DISABLED")) == "true",
		RefuseANY:                  strings.ToLower(os.Getenv("REFUSE_ANY")) != "false",
		UpstreamMode:               upstreamMode,
		FallbackDNS:                os.Getenv("FALLBACK_DNS"),
		BootstrapDNS:               os.Getenv("BOOTSTRAP_DNS"),
		ECSClientSubnet:            os.Getenv("ECS_CLIENT_SUBNET"),
		DNS64:                      strings.ToLower(os.Getenv("DNS64")) == "true",
		DNS64Prefixes:              os.Getenv("DNS64_PREFIXES"),
		CacheMinTTL:                cacheMinTTL,
		CacheMaxTTL:                cacheMaxTTL,
		CacheOptimistic:            strings.ToLower(os.Getenv("CACHE_OPTIMISTIC")) == "true",
		ClientsFile:                clientsFile,
		BlockedServices:            os.Getenv("BLOCKED_SERVICES"),
		DNSAllowedClients:          os.Getenv("DNS_ALLOWED_CLIENTS"),
		DNSDisallowedClients:       os.Getenv("DNS_DISALLOWED_CLIENTS"),
		RateLimitQPS:               parseIntEnv("RATE_LIMIT_QPS", DefaultRateLimitQPS),
		PrivatePTR:                 strings.ToLower(os.Getenv("PRIVATE_PTR")) != "false",
		DNSSEC:                     strings.ToLower(os.Getenv("DNSSEC")) == "true",
		DoHEnabled:                 strings.ToLower(os.Getenv("DOH_ENABLED")) == "true",
		DoHPath:                    resolveDoHPath(),
		DoHAuthToken:               os.Getenv("DOH_AUTH_TOKEN"),
		DoTEnabled:                 strings.ToLower(os.Getenv("DOT_ENABLED")) == "true",
		DoTPort:                    dotPort,
		TLSCertFile:                os.Getenv("TLS_CERT_FILE"),
		TLSKeyFile:                 os.Getenv("TLS_KEY_FILE"),
		UpstreamLatencyThreshold:   latencyThreshold,
		SSEKeepaliveInterval:       sseKeepalive,
		BatchArchiveInterval:       batchArchive,
		ArchiveQueueCapacity:       archiveCapacity,
		ArchiveTriggerSize:         archiveTrigger,
		ArchiveWriteBatchSize:      archiveWriteBatch,
		CleanupPendingInterval:     cleanupPending,
		ForwarderRetryInterval:     forwarderRetry,
		HTTPReadTimeout:            httpReadTimeout,
		HTTPWriteTimeout:           httpWriteTimeout,
		HTTPShutdownTimeout:        httpShutdownTimeout,
		MaxRequestSize:             maxRequestSize,
		LogFile:                    logFile,
		MaxRetryAttempts:           maxRetryAttempts,
		HeartbeatInterval:          heartbeatInterval,
		SyncAliasesInterval:        syncAliasesInterval,
		SyncDNSRoutesInterval:      syncDNSRoutesInterval,
		SyncUpstreamHealthInterval: syncUpstreamHealthInterval,
		NodeOfflineThreshold:       nodeOfflineThreshold,
	}

	if cfg.Mode == ModeAgent && cfg.ControllerURL == "" {
		log.Fatal("[FATAL] CONTROLLER_URL is required when MODE is agent")
	}

	return cfg
}

// isValidControllerURL checks that the URL uses protected HTTPS transport.
func isValidControllerURL(rawURL string) bool {
	return strings.HasPrefix(rawURL, "https://")
}

// FullDBPath returns the complete database path by joining HistoryDir and DBPath.
// If DBPath is an absolute path, it is returned as-is.
func (c *Config) FullDBPath() string {
	if filepath.IsAbs(c.DBPath) {
		return c.DBPath
	}
	return filepath.Join(c.HistoryDir, c.DBPath)
}

// FullUpstreamsPath returns the complete upstreams file path.
func (c *Config) FullUpstreamsPath() string {
	if c.UpstreamsFile == "" {
		return ""
	}
	if filepath.IsAbs(c.UpstreamsFile) {
		return c.UpstreamsFile
	}
	return filepath.Join(c.HistoryDir, c.UpstreamsFile)
}

// FullDNSRoutesPath returns the complete DNS routes file path.
func (c *Config) FullDNSRoutesPath() string {
	if c.DNSRoutesFile == "" {
		return ""
	}
	if filepath.IsAbs(c.DNSRoutesFile) {
		return c.DNSRoutesFile
	}
	return filepath.Join(c.HistoryDir, c.DNSRoutesFile)
}

// FullRewritesPath returns the complete rewrites file path.
func (c *Config) FullRewritesPath() string {
	if c.RewritesFile == "" {
		return ""
	}
	if filepath.IsAbs(c.RewritesFile) {
		return c.RewritesFile
	}
	return filepath.Join(c.HistoryDir, c.RewritesFile)
}

// FullClientsPath returns the complete clients registry file path.
func (c *Config) FullClientsPath() string {
	if c.ClientsFile == "" {
		return ""
	}
	if filepath.IsAbs(c.ClientsFile) {
		return c.ClientsFile
	}
	return filepath.Join(c.HistoryDir, c.ClientsFile)
}

// FullBlocklistPath returns the complete blocklist file path.
func (c *Config) FullBlocklistPath() string {
	if c.BlocklistFile == "" {
		return ""
	}
	if filepath.IsAbs(c.BlocklistFile) {
		return c.BlocklistFile
	}
	return filepath.Join(c.HistoryDir, c.BlocklistFile)
}

// VerifyConfig checks critical configuration values before the server starts.
// Returns a slice of error messages for critical failures and a slice of warning messages.
//
//nolint:gocyclo // Each independent validation is retained so all startup errors can be reported together.
func (c *Config) VerifyConfig() ([]string, []string) {
	var errs []string
	var warnings []string

	// 1. Database path is writable
	dbDir := filepath.Dir(c.FullDBPath())
	if err := os.MkdirAll(dbDir, 0750); err != nil {
		errs = append(errs, fmt.Sprintf("Cannot create database directory %s: %v", dbDir, err))
	} else {
		// CreateTemp picks a random name inside the trusted config directory,
		// avoiding a predictable-path write (gosec G304).
		if f, err := os.CreateTemp(dbDir, ".write_test*"); err != nil {
			errs = append(errs, fmt.Sprintf("Database directory %s is not writable: %v", dbDir, err))
		} else {
			testFile := f.Name()
			_ = f.Close()
			_ = os.Remove(testFile)
		}
	}

	// 2. CONTROLLER_URL schema validation (if set)
	if c.ControllerURL != "" && !isValidControllerURL(c.ControllerURL) {
		errs = append(errs, fmt.Sprintf("CONTROLLER_URL must start with https:// (got: %s)", c.ControllerURL))
	}

	// 3. Authentication must be either fully configured or explicitly backed
	// by an ingest secret. Internal endpoints must never silently fail open.
	if (c.WebUsername == "") != (c.WebPassword == "") {
		errs = append(errs, "WEB_USERNAME and WEB_PASSWORD must be configured together")
	}
	if c.WebUsername == "" && c.WebPassword == "" && c.IngestSecret == "" {
		errs = append(errs, "configure WEB_USERNAME/WEB_PASSWORD or INGEST_SECRET; internal endpoints may not run without authentication")
	}

	// 4. Port number validation
	if p, err := strconv.Atoi(c.Port); err != nil || p < 1 || p > 65535 {
		errs = append(errs, fmt.Sprintf("Invalid PORT '%s' — must be a number between 1 and 65535", c.Port))
	}
	if strings.ContainsAny(c.WebListenAddr, "\r\n\x00") {
		errs = append(errs, "WEB_LISTEN_ADDR contains invalid characters")
	}

	// 4b. DNSMASQ_PID_FILE deprecation notice (non-critical warning)
	if os.Getenv("DNSMASQ_PID_FILE") != "" {
		warnings = append(warnings, "DNSMASQ_PID_FILE is deprecated and ignored: cache clearing is handled by the in-process DNS server")
	}

	// 4c. DoT requires TLS certificates (critical failure)
	if c.DoTEnabled && (c.TLSCertFile == "" || c.TLSKeyFile == "") {
		errs = append(errs, "DOT_ENABLED requires TLS_CERT_FILE and TLS_KEY_FILE")
	}
	if c.DoTEnabled && (c.DoTPort < 1 || c.DoTPort > 65535) {
		errs = append(errs, "DOT_PORT must be between 1 and 65535")
	}
	if c.DoHEnabled && !validDoHPath(c.DoHPath) {
		errs = append(errs, "DOH_PATH must be a non-conflicting literal HTTP path")
	}

	for _, setting := range []struct {
		name string
		raw  string
	}{
		{name: "DNS_ALLOWED_CLIENTS", raw: c.DNSAllowedClients},
		{name: "DNS_DISALLOWED_CLIENTS", raw: c.DNSDisallowedClients},
	} {
		for _, value := range splitConfigList(setting.raw) {
			if !validIPOrCIDR(value) {
				errs = append(errs, fmt.Sprintf("%s contains an invalid IP or CIDR", setting.name))
				break
			}
		}
	}

	if c.DNS64 {
		for _, value := range splitConfigList(c.DNS64Prefixes) {
			ip, network, err := net.ParseCIDR(value)
			ones, bits := 0, 0
			if err == nil {
				ones, bits = network.Mask.Size()
			}
			if err != nil || ip.To4() != nil || bits != 128 || ones != 96 {
				errs = append(errs, "DNS64_PREFIXES must contain only IPv6 /96 prefixes")
				break
			}
		}
	}

	for _, setting := range []struct {
		name string
		raw  string
	}{
		{name: "BLOCKLIST_URLS", raw: c.BlocklistURLs},
		{name: "ALLOWLIST_URLS", raw: c.AllowlistURLs},
	} {
		for _, value := range splitConfigList(setting.raw) {
			u, err := url.Parse(value)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
				errs = append(errs, fmt.Sprintf("%s contains an invalid URL (only http/https without embedded credentials is allowed)", setting.name))
				break
			}
		}
	}

	// 5. Client aliases file check (non-critical warning)
	if c.ClientAliasesFile != "" {
		if _, err := os.Stat(c.ClientAliasesFile); os.IsNotExist(err) {
			warnings = append(warnings, fmt.Sprintf("CLIENT_ALIASES_FILE '%s' does not exist (will be watched for creation)", c.ClientAliasesFile))
		}
	}

	// 6. Blocklist file check (non-critical warning)
	if c.BlocklistFile != "" {
		if _, err := os.Stat(c.FullBlocklistPath()); os.IsNotExist(err) {
			warnings = append(warnings, fmt.Sprintf("BLOCKLIST_FILE '%s' does not exist (will be watched for creation)", c.FullBlocklistPath()))
		}
	}

	// 7. DNS routes file check (non-critical warning)
	if c.DNSRoutesFile != "" {
		if _, err := os.Stat(c.FullDNSRoutesPath()); os.IsNotExist(err) {
			warnings = append(warnings, fmt.Sprintf("DNS_ROUTES_FILE '%s' does not exist (will be created on first save)", c.FullDNSRoutesPath()))
		}
	}

	return errs, warnings
}

func splitConfigList(raw string) []string {
	return strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	})
}

func validIPOrCIDR(value string) bool {
	if net.ParseIP(value) != nil {
		return true
	}
	_, _, err := net.ParseCIDR(value)
	return err == nil
}

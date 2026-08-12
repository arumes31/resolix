package config

import (
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/arumes31/resolix/webgui/internal/controllertls"
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
	// DefaultConfigDir is the default directory for persistent managed settings.
	DefaultConfigDir = "/var/lib/resolix-config"
	// DefaultTLSStateDir is the default directory for generated controller TLS state.
	DefaultTLSStateDir = "/var/lib/resolix-tls"
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
	DefaultDNSRoutesFile = "dns-routes.json"
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
	// DefaultRateLimitQPS is the default per-IP query limit for public clients.
	DefaultRateLimitQPS = 80
	// DefaultInternalRateLimitQPS is the default per-IP limit for LAN and Tailscale clients.
	DefaultInternalRateLimitQPS = 1000
	// DefaultDoHPath is the default DNS-over-HTTPS endpoint path.
	DefaultDoHPath = "/dns-query"
	// DefaultDoTPort is the default DNS-over-TLS listen port.
	DefaultDoTPort = 853

	// minCacheTTLDefault/maxCacheTTLDefault are the default cache TTL bounds
	// in seconds (dnsmasq local-ttl=60 / max-ttl=600).
	minCacheTTLDefault = 60
	maxCacheTTLDefault = 600
	// DefaultCachePrefetchWindow controls how soon before expiry hot entries are refreshed.
	DefaultCachePrefetchWindow = 30 * time.Second
	// DefaultCachePrefetchHits is the access threshold for prefetching a cache entry.
	DefaultCachePrefetchHits = 3
	// DefaultDNSTCPIdleTimeout limits how long an idle DNS TCP connection remains open.
	DefaultDNSTCPIdleTimeout = 8 * time.Second
	// DefaultDNSTCPMaxQueries limits queries served over one DNS TCP connection.
	DefaultDNSTCPMaxQueries = 128
	// DefaultDNSTCPMaxConnections limits concurrent DNS TCP connections.
	DefaultDNSTCPMaxConnections = 256
	// DefaultUpstreamLatencyThreshold is the default latency alert threshold in milliseconds.
	DefaultUpstreamLatencyThreshold = 200

	// DefaultSSEKeepaliveInterval is the default interval for SSE keepalive messages.
	DefaultSSEKeepaliveInterval = 30 * time.Second
	// DefaultBatchArchiveInterval is the default interval for batch archiving to SQLite.
	DefaultBatchArchiveInterval = 30 * time.Minute
	// DefaultArchiveQueueCapacity is the maximum number of events waiting for SQLite.
	DefaultArchiveQueueCapacity = 1000000
	// DefaultArchiveTriggerSize starts an archive pass before the queue is full.
	DefaultArchiveTriggerSize = 20000
	// DefaultArchiveWriteBatchSize bounds each SQLite transaction.
	DefaultArchiveWriteBatchSize = 20000
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
	Mode          string
	ControllerURL string
	NodeName      string
	// NodeID is the stable, opaque identity used to distinguish cluster nodes
	// that happen to share the same display name. Agents persist one when this
	// value is not configured explicitly.
	NodeID        string
	Port          string
	WebListenAddr string
	HistoryDir    string
	// ConfigDir contains persistent controller-managed DNS configuration.
	ConfigDir        string
	TLSStateDir      string
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
	// WebTLSMode controls direct web HTTPS: off for reverse-proxy termination,
	// or auto for the generated controller CA and rotating leaf certificate.
	WebTLSMode string
	// WebTLSIP is the exact Tailscale IPv4 address placed in the generated leaf.
	WebTLSIP string
	// ControllerTLSTrust selects system roots or tailnet-restricted TOFU.
	ControllerTLSTrust string
	// ControllerTLSPinFile stores the agent's pinned controller CA fingerprint.
	ControllerTLSPinFile string

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
	CacheOptimistic     bool
	CachePrefetch       bool
	CachePrefetchWindow time.Duration
	CachePrefetchHits   uint32
	CacheSERVFAILTTL    time.Duration
	// ClientsFile is the per-client registry JSON file.
	ClientsFile string
	// DNSAllowedClients restricts DNS service to these IPs/CIDRs when non-empty.
	DNSAllowedClients string
	// DNSDisallowedClients drops queries from these IPs/CIDRs silently.
	DNSDisallowedClients string
	// RateLimitQPS limits queries per second per public client IP (0 = disabled).
	RateLimitQPS int
	// InternalRateLimitQPS limits LAN and Tailscale clients per IP (0 = disabled).
	InternalRateLimitQPS int
	// RateLimitEDE returns REFUSED with an Extended DNS Error to EDNS clients
	// instead of silently dropping over-limit queries.
	RateLimitEDE bool
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
	TLSCertFile          string
	TLSKeyFile           string
	DNSTCPIdleTimeout    time.Duration
	DNSTCPMaxQueries     int
	DNSTCPMaxConnections int
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
	configDir := strings.TrimSpace(os.Getenv("CONFIG_DIR"))
	if configDir == "" {
		configDir = DefaultConfigDir
	}
	tlsStateDir := strings.TrimSpace(os.Getenv("TLS_STATE_DIR"))
	if tlsStateDir == "" {
		tlsStateDir = DefaultTLSStateDir
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
	webTLSMode := strings.ToLower(strings.TrimSpace(os.Getenv("WEB_TLS_MODE")))
	if webTLSMode == "" {
		webTLSMode = controllertls.WebTLSOff
	}
	webTLSIP := strings.TrimSpace(os.Getenv("WEB_TLS_IP"))
	if webTLSIP == "" {
		webTLSIP = strings.TrimSpace(os.Getenv("TAILSCALE_IP"))
	}
	controllerTLSTrust := strings.ToLower(strings.TrimSpace(os.Getenv("CONTROLLER_TLS_TRUST")))
	if controllerTLSTrust == "" {
		controllerTLSTrust = controllertls.TrustSystem
	}
	controllerTLSPinFile := strings.TrimSpace(os.Getenv("CONTROLLER_TLS_PIN_FILE"))
	if controllerTLSPinFile == "" {
		controllerTLSPinFile = controllertls.DefaultPinFile
	} else if migratedPinFile, legacy := legacyTLSPinFile(controllerTLSPinFile); legacy {
		log.Printf("[WARN] CONTROLLER_TLS_PIN_FILE=%s is deprecated; the pin is now relative to TLS_STATE_DIR", sanitizeForLog(controllerTLSPinFile)) // #nosec G706 -- CR/LF stripped by sanitizeForLog; gosec taint analysis cannot see through the helper
		controllerTLSPinFile = migratedPinFile
	}

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
	cacheSERVFAILTTL := parseDurationEnv("CACHE_SERVFAIL_TTL", 0)
	if cacheSERVFAILTTL < 0 {
		cacheSERVFAILTTL = 0
	} else if cacheSERVFAILTTL > time.Second {
		log.Printf("[WARN] CACHE_SERVFAIL_TTL exceeds 1s; clamping it to 1s")
		cacheSERVFAILTTL = time.Second
	}
	dnsTCPIdleTimeout := parseDurationEnv("DNS_TCP_IDLE_TIMEOUT", DefaultDNSTCPIdleTimeout)
	if dnsTCPIdleTimeout <= 0 {
		dnsTCPIdleTimeout = DefaultDNSTCPIdleTimeout
	}
	dnsTCPMaxQueries := parseIntEnv("DNS_TCP_MAX_QUERIES", DefaultDNSTCPMaxQueries)
	if dnsTCPMaxQueries <= 0 {
		dnsTCPMaxQueries = DefaultDNSTCPMaxQueries
	}
	dnsTCPMaxConnections := parseIntEnv("DNS_TCP_MAX_CONNECTIONS", DefaultDNSTCPMaxConnections)
	if dnsTCPMaxConnections <= 0 {
		dnsTCPMaxConnections = DefaultDNSTCPMaxConnections
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
		NodeID:                     strings.TrimSpace(os.Getenv("NODE_ID")),
		Port:                       port,
		WebListenAddr:              webListenAddr,
		HistoryDir:                 historyDir,
		ConfigDir:                  configDir,
		TLSStateDir:                tlsStateDir,
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
		WebTLSMode:                 webTLSMode,
		WebTLSIP:                   webTLSIP,
		ControllerTLSTrust:         controllerTLSTrust,
		ControllerTLSPinFile:       controllerTLSPinFile,
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
		CachePrefetch:              strings.ToLower(os.Getenv("CACHE_PREFETCH")) == "true",
		CachePrefetchWindow:        parseDurationEnv("CACHE_PREFETCH_WINDOW", DefaultCachePrefetchWindow),
		CachePrefetchHits:          parseUint32Env("CACHE_PREFETCH_HITS", DefaultCachePrefetchHits),
		CacheSERVFAILTTL:           cacheSERVFAILTTL,
		ClientsFile:                clientsFile,
		DNSAllowedClients:          os.Getenv("DNS_ALLOWED_CLIENTS"),
		DNSDisallowedClients:       os.Getenv("DNS_DISALLOWED_CLIENTS"),
		RateLimitQPS:               parseIntEnv("RATE_LIMIT_QPS", DefaultRateLimitQPS),
		InternalRateLimitQPS:       parseIntEnv("RATE_LIMIT_INTERNAL_QPS", DefaultInternalRateLimitQPS),
		RateLimitEDE:               strings.EqualFold(os.Getenv("RATE_LIMIT_EDE"), "true"),
		PrivatePTR:                 strings.ToLower(os.Getenv("PRIVATE_PTR")) != "false",
		DNSSEC:                     strings.ToLower(os.Getenv("DNSSEC")) == "true",
		DoHEnabled:                 strings.ToLower(os.Getenv("DOH_ENABLED")) == "true",
		DoHPath:                    resolveDoHPath(),
		DoHAuthToken:               os.Getenv("DOH_AUTH_TOKEN"),
		DoTEnabled:                 strings.ToLower(os.Getenv("DOT_ENABLED")) == "true",
		DoTPort:                    dotPort,
		TLSCertFile:                os.Getenv("TLS_CERT_FILE"),
		TLSKeyFile:                 os.Getenv("TLS_KEY_FILE"),
		DNSTCPIdleTimeout:          dnsTCPIdleTimeout,
		DNSTCPMaxQueries:           dnsTCPMaxQueries,
		DNSTCPMaxConnections:       dnsTCPMaxConnections,
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

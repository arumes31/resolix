package config

import (
	"log"
	"net"
	"net/url"
	"os"
	pathpkg "path"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"
)

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

func legacyTLSPinFile(path string) (string, bool) {
	cleanPath := filepath.Clean(path)
	if filepath.IsAbs(cleanPath) {
		return path, false
	}
	relativePath, err := filepath.Rel("tls", cleanPath)
	if err != nil || relativePath == "." || !filepath.IsLocal(relativePath) {
		return path, false
	}
	return relativePath, true
}

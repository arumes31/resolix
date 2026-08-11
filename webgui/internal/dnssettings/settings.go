// Package dnssettings persists controller-managed DNS policy that can be
// applied without rebinding listeners or restarting the process.
package dnssettings

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/arumes31/resolix/webgui/internal/upstream"
)

const (
	defaultCacheSize = 25000
	maxCacheSize     = 1000000
	maxListEntries   = 4096
)

// Settings contains controller-authoritative, live-safe DNS behavior. Socket,
// TLS, credential, and storage settings deliberately remain environment-owned.
type Settings struct {
	UpstreamMode           string   `json:"upstream_mode"`
	FallbackDNS            []string `json:"fallback_dns"`
	ECSClientSubnet        string   `json:"ecs_client_subnet"`
	BlockingMode           string   `json:"blocking_mode"`
	BlockCustomIPv4        string   `json:"block_custom_ipv4"`
	BlockCustomIPv6        string   `json:"block_custom_ipv6"`
	BlockedResponseTTL     uint32   `json:"blocked_response_ttl"`
	SafeSearch             []string `json:"safe_search"`
	BogusNXDOMAIN          []string `json:"bogus_nxdomain"`
	AAAADisabled           bool     `json:"aaaa_disabled"`
	RefuseANY              bool     `json:"refuse_any"`
	DNSSEC                 bool     `json:"dnssec"`
	PrivatePTR             bool     `json:"private_ptr"`
	PrivatePTRUpstreams    []string `json:"private_ptr_upstreams"`
	ResolveClientHostnames bool     `json:"resolve_client_hostnames"`
	AllowedClients         []string `json:"allowed_clients"`
	DisallowedClients      []string `json:"disallowed_clients"`
	RateLimitQPS           int      `json:"rate_limit_qps"`
	InternalRateLimitQPS   int      `json:"internal_rate_limit_qps"`
	RateLimitEDE           bool     `json:"rate_limit_ede"`
	RateLimitIPv4Prefix    int      `json:"rate_limit_ipv4_prefix"`
	RateLimitIPv6Prefix    int      `json:"rate_limit_ipv6_prefix"`
	RateLimitAllowlist     []string `json:"rate_limit_allowlist"`
	CacheSize              int      `json:"cache_size"`
	CacheMinTTL            uint32   `json:"cache_min_ttl"`
	CacheMaxTTL            uint32   `json:"cache_max_ttl"`
	CacheOptimistic        bool     `json:"cache_optimistic"`
	CachePrefetch          bool     `json:"cache_prefetch"`
	CachePrefetchWindowMS  int64    `json:"cache_prefetch_window_ms"`
	CachePrefetchHits      uint32   `json:"cache_prefetch_hits"`
	CacheSERVFAILTTLMS     int64    `json:"cache_servfail_ttl_ms"`
}

// Normalize returns a defensive, canonical copy suitable for hashing and
// persistence. Validation remains separate so callers can report bad input.
func (s Settings) Normalize() Settings {
	s.UpstreamMode = strings.ToLower(strings.TrimSpace(s.UpstreamMode))
	s.FallbackDNS = compact(s.FallbackDNS)
	s.ECSClientSubnet = strings.TrimSpace(s.ECSClientSubnet)
	s.BlockingMode = strings.ToLower(strings.TrimSpace(s.BlockingMode))
	s.BlockCustomIPv4 = strings.TrimSpace(s.BlockCustomIPv4)
	s.BlockCustomIPv6 = strings.TrimSpace(s.BlockCustomIPv6)
	s.SafeSearch = compactLower(s.SafeSearch)
	s.BogusNXDOMAIN = compact(s.BogusNXDOMAIN)
	s.PrivatePTRUpstreams = compact(s.PrivatePTRUpstreams)
	s.AllowedClients = compact(s.AllowedClients)
	s.DisallowedClients = compact(s.DisallowedClients)
	s.RateLimitAllowlist = compact(s.RateLimitAllowlist)
	if s.CacheSize == 0 {
		s.CacheSize = defaultCacheSize
	}
	if s.BlockedResponseTTL == 0 {
		s.BlockedResponseTTL = 60
	}
	if s.CacheMinTTL == 0 {
		s.CacheMinTTL = 60
	}
	if s.CacheMaxTTL == 0 {
		s.CacheMaxTTL = 600
	}
	if s.CachePrefetchWindowMS == 0 {
		s.CachePrefetchWindowMS = 30000
	}
	if s.CachePrefetchHits == 0 {
		s.CachePrefetchHits = 3
	}
	if s.RateLimitIPv4Prefix == 0 {
		s.RateLimitIPv4Prefix = 32
	}
	if s.RateLimitIPv6Prefix == 0 {
		s.RateLimitIPv6Prefix = 128
	}
	return s
}

// Validate rejects settings that could create ambiguous or unsafe runtime
// behavior. It never silently drops request-provided values.
func (s Settings) Validate() error {
	s = s.Normalize()
	for _, validate := range []func(Settings) error{
		validateResolverSettings,
		validateBlockingSettings,
		validateAccessSettings,
		validateCacheSettings,
	} {
		if err := validate(s); err != nil {
			return err
		}
	}
	return nil
}

func validateResolverSettings(s Settings) error {
	switch s.UpstreamMode {
	case upstream.ModeLoadBalance, upstream.ModeParallel, upstream.ModeStrict:
	default:
		return errors.New("upstream_mode must be load_balance, parallel, or strict")
	}
	for index, raw := range s.FallbackDNS {
		if _, err := upstream.Parse(raw); err != nil {
			return fmt.Errorf("fallback_dns entry %d: %w", index+1, err)
		}
	}
	if s.ECSClientSubnet != "" {
		if err := validateIPOrCIDR(s.ECSClientSubnet); err != nil {
			return fmt.Errorf("ecs_client_subnet: %w", err)
		}
	}
	for index, raw := range s.PrivatePTRUpstreams {
		if _, err := upstream.Parse(raw); err != nil {
			return fmt.Errorf("private_ptr_upstreams entry %d: %w", index+1, err)
		}
	}
	return nil
}

func validateBlockingSettings(s Settings) error {
	switch s.BlockingMode {
	case "nxdomain", "null_ip", "refused", "custom_ip":
	default:
		return errors.New("blocking_mode must be nxdomain, null_ip, refused, or custom_ip")
	}
	if s.BlockCustomIPv4 != "" && net.ParseIP(s.BlockCustomIPv4).To4() == nil {
		return errors.New("block_custom_ipv4 must be an IPv4 address")
	}
	if ip := net.ParseIP(s.BlockCustomIPv6); s.BlockCustomIPv6 != "" && (ip == nil || ip.To4() != nil) {
		return errors.New("block_custom_ipv6 must be an IPv6 address")
	}
	if s.BlockedResponseTTL > 86400 {
		return errors.New("blocked_response_ttl must be between 0 and 86400 seconds")
	}
	validEngines := map[string]bool{"google": true, "bing": true, "ddg": true, "youtube": true}
	for _, engine := range s.SafeSearch {
		if !validEngines[engine] {
			return fmt.Errorf("unsupported safe_search engine %q", engine)
		}
	}
	for _, raw := range s.BogusNXDOMAIN {
		if err := validateIPOrCIDR(raw); err != nil {
			return fmt.Errorf("bogus_nxdomain: %w", err)
		}
	}
	return nil
}

func validateAccessSettings(s Settings) error {
	if len(s.AllowedClients) > maxListEntries || len(s.DisallowedClients) > maxListEntries {
		return fmt.Errorf("client access lists may contain at most %d entries", maxListEntries)
	}
	for _, list := range [][]string{s.AllowedClients, s.DisallowedClients, s.RateLimitAllowlist} {
		for _, raw := range list {
			if err := validateIPOrCIDR(raw); err != nil {
				return fmt.Errorf("client access list: %w", err)
			}
		}
	}
	if s.RateLimitQPS < 0 || s.RateLimitQPS > 1000000 ||
		s.InternalRateLimitQPS < 0 || s.InternalRateLimitQPS > 1000000 {
		return errors.New("rate limits must be between 0 and 1000000 queries per second")
	}
	if s.RateLimitIPv4Prefix < 1 || s.RateLimitIPv4Prefix > 32 ||
		s.RateLimitIPv6Prefix < 1 || s.RateLimitIPv6Prefix > 128 {
		return errors.New("rate-limit subnet prefixes must be within IPv4 /1-/32 and IPv6 /1-/128")
	}
	return nil
}

func validateCacheSettings(s Settings) error {
	if s.CacheSize < 1 || s.CacheSize > maxCacheSize {
		return fmt.Errorf("cache_size must be between 1 and %d entries", maxCacheSize)
	}
	if s.CacheMinTTL > 86400 || s.CacheMaxTTL > 86400 ||
		(s.CacheMinTTL > 0 && s.CacheMaxTTL > 0 && s.CacheMinTTL > s.CacheMaxTTL) {
		return errors.New("cache TTLs must be between 0 and 86400 seconds, with minimum not above maximum")
	}
	if s.CachePrefetchWindowMS < 0 || s.CachePrefetchWindowMS > int64((24*time.Hour)/time.Millisecond) {
		return errors.New("cache_prefetch_window_ms must be between 0 and 86400000")
	}
	if s.CachePrefetchHits > 1000000 {
		return errors.New("cache_prefetch_hits must not exceed 1000000")
	}
	if s.CacheSERVFAILTTLMS < 0 || s.CacheSERVFAILTTLMS > 1000 {
		return errors.New("cache_servfail_ttl_ms must be between 0 and 1000")
	}
	return nil
}

func validateIPOrCIDR(raw string) error {
	raw = strings.TrimSpace(raw)
	if ip := net.ParseIP(raw); ip != nil {
		return nil
	}
	if _, _, err := net.ParseCIDR(raw); err != nil {
		return fmt.Errorf("%q is not an IP address or CIDR", raw)
	}
	return nil
}

func compact(values []string) []string {
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func compactLower(values []string) []string {
	lowered := slices.Clone(values)
	for index := range lowered {
		lowered[index] = strings.ToLower(lowered[index])
	}
	return compact(lowered)
}

// Store persists the last-known-good controller settings.
type Store struct {
	mu    sync.RWMutex
	path  string
	items Settings
}

// Load opens path, falling back to defaults only when the file does not yet
// exist. Invalid persisted data fails startup instead of weakening policy.
func Load(path string, defaults Settings) (*Store, error) {
	defaults = defaults.Normalize()
	if err := defaults.Validate(); err != nil {
		return nil, fmt.Errorf("validate DNS setting defaults: %w", err)
	}
	store := &Store{path: path, items: defaults}
	if path == "" {
		return store, nil
	}
	data, err := os.ReadFile(path) // #nosec G304 -- path comes from trusted application configuration
	if errors.Is(err, os.ErrNotExist) {
		return store, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read DNS settings: %w", err)
	}
	var settings Settings
	if err := json.Unmarshal(data, &settings); err != nil {
		return nil, fmt.Errorf("decode DNS settings: %w", err)
	}
	settings = settings.Normalize()
	if err := settings.Validate(); err != nil {
		return nil, fmt.Errorf("validate DNS settings: %w", err)
	}
	store.items = settings
	return store, nil
}

// Get returns a defensive copy of the current settings.
func (s *Store) Get() Settings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return clone(s.items)
}

// Replace persists settings before publishing them to readers.
func (s *Store) Replace(settings Settings) error {
	settings = settings.Normalize()
	if err := settings.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := save(s.path, settings); err != nil {
		return err
	}
	s.items = clone(settings)
	return nil
}

func clone(settings Settings) Settings {
	settings.FallbackDNS = slices.Clone(settings.FallbackDNS)
	settings.SafeSearch = slices.Clone(settings.SafeSearch)
	settings.BogusNXDOMAIN = slices.Clone(settings.BogusNXDOMAIN)
	settings.PrivatePTRUpstreams = slices.Clone(settings.PrivatePTRUpstreams)
	settings.AllowedClients = slices.Clone(settings.AllowedClients)
	settings.DisallowedClients = slices.Clone(settings.DisallowedClients)
	settings.RateLimitAllowlist = slices.Clone(settings.RateLimitAllowlist)
	return settings
}

func save(path string, settings Settings) error {
	if path == "" {
		return nil
	}
	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return fmt.Errorf("encode DNS settings: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("create DNS settings directory: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".dns-settings-*.tmp")
	if err != nil {
		return fmt.Errorf("create DNS settings temporary file: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("secure DNS settings temporary file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write DNS settings temporary file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync DNS settings temporary file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close DNS settings temporary file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("replace DNS settings: %w", err)
	}
	return nil
}

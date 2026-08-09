package dnsroutes

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"tailscale-dnsrewrite/webgui/internal/logger"
)

// Route represents a domain-to-upstream mapping.
type Route struct {
	Pattern  string `json:"pattern"`
	Upstream string `json:"upstream"`
}

// DNSRoutes manages domain-specific DNS routing rules.
type DNSRoutes struct {
	path   string
	routes []Route
	// mu guards routes; writeMu serializes concurrent SetRoutes calls
	// (file persistence + swap) without blocking readers.
	mu      sync.RWMutex
	writeMu sync.Mutex
	cancel  context.CancelFunc
}

// New creates a new DNSRoutes from the given JSON config file path and loads it immediately.
func New(path string) *DNSRoutes {
	dr := &DNSRoutes{
		path:   path,
		routes: make([]Route, 0),
	}
	dr.load()
	return dr
}

// load reads the routes JSON file and updates the in-memory route set.
// Format: { "domain.pattern": "upstream_ip:port", ... }
func (dr *DNSRoutes) load() {
	newRoutes := make([]Route, 0)

	if dr.path == "" {
		dr.mu.Lock()
		dr.routes = newRoutes
		dr.mu.Unlock()
		return
	}

	data, err := os.ReadFile(dr.path)
	if err != nil {
		if os.IsNotExist(err) {
			logger.Info("DNS routes file not found: %s (will be created on first save)", dr.path)
		} else {
			logger.Error("Failed to read DNS routes file: %v", err)
		}
		dr.mu.Lock()
		dr.routes = newRoutes
		dr.mu.Unlock()
		return
	}

	var raw map[string]string
	if err := json.Unmarshal(data, &raw); err != nil {
		logger.Error("Failed to parse DNS routes file: %v", err)
		dr.mu.Lock()
		dr.routes = newRoutes
		dr.mu.Unlock()
		return
	}

	for pattern, upstream := range raw {
		newRoutes = append(newRoutes, Route{
			Pattern:  strings.ToLower(pattern),
			Upstream: upstream,
		})
	}
	sortRoutes(newRoutes)

	dr.mu.Lock()
	dr.routes = newRoutes
	dr.mu.Unlock()

	logger.Info("Loaded %d DNS routes from %s", len(newRoutes), dr.path)
}

// StartReload begins periodic reloading of the routes file (every 60 seconds).
func (dr *DNSRoutes) StartReload(ctx context.Context) {
	if dr.cancel != nil {
		dr.cancel()
	}
	reloadCtx, cancel := context.WithCancel(ctx)
	dr.cancel = cancel
	ticker := time.NewTicker(60 * time.Second)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-reloadCtx.Done():
				return
			case <-ticker.C:
				dr.load()
			}
		}
	}()
}

// Stop cancels the reload goroutine.
func (dr *DNSRoutes) Stop() {
	if dr.cancel != nil {
		dr.cancel()
	}
}

// GetUpstreamForDomain returns the upstream server for a domain if a matching route exists.
// Supports wildcard patterns (e.g., "*.example.com" matches "sub.example.com").
func (dr *DNSRoutes) GetUpstreamForDomain(domain string) string {
	dr.mu.RLock()
	defer dr.mu.RUnlock()

	domain = strings.ToLower(strings.TrimSuffix(domain, "."))

	for _, r := range dr.routes {
		if matchPattern(r.Pattern, domain) {
			return r.Upstream
		}
	}
	return ""
}

// matchPattern checks if a domain matches a pattern with optional wildcard prefix.
func matchPattern(pattern, domain string) bool {
	if pattern == domain {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[2:] // Remove "*."
		// Wildcards match both the suffix apex and any subdomain below it.
		if strings.HasSuffix(domain, "."+suffix) || domain == suffix {
			return true
		}
	}
	return false
}

// GetRoutes returns a copy of all current routes.
func (dr *DNSRoutes) GetRoutes() []Route {
	dr.mu.RLock()
	defer dr.mu.RUnlock()
	result := make([]Route, len(dr.routes))
	copy(result, dr.routes)
	return result
}

// GetRoutesMap returns routes as a map (pattern -> upstream).
func (dr *DNSRoutes) GetRoutesMap() map[string]string {
	dr.mu.RLock()
	defer dr.mu.RUnlock()
	result := make(map[string]string, len(dr.routes))
	for _, r := range dr.routes {
		result[r.Pattern] = r.Upstream
	}
	return result
}

// Count returns the number of currently loaded routes.
func (dr *DNSRoutes) Count() int {
	dr.mu.RLock()
	defer dr.mu.RUnlock()
	return len(dr.routes)
}

// SetRoutes updates the routes and saves them to the file.
// Normalization, serialization, and file persistence happen outside dr.mu
// (serialized by writeMu); dr.mu is only held while swapping dr.routes.
func (dr *DNSRoutes) SetRoutes(routesMap map[string]string) error {
	dr.writeMu.Lock()
	defer dr.writeMu.Unlock()

	newRoutes := make([]Route, 0, len(routesMap))
	for pattern, upstream := range routesMap {
		newRoutes = append(newRoutes, Route{
			Pattern:  strings.ToLower(pattern),
			Upstream: upstream,
		})
	}
	sortRoutes(newRoutes)

	// Save to file first to preserve atomicity
	if dr.path != "" {
		data, err := json.MarshalIndent(routesMap, "", "  ")
		if err != nil {
			return err
		}
		if err := writeFileAtomic(dr.path, data, 0o644); err != nil {
			return err
		}
		logger.Info("Saved %d DNS routes to %s", len(routesMap), dr.path)
	}

	dr.mu.Lock()
	dr.routes = newRoutes
	dr.mu.Unlock()

	return nil
}

func sortRoutes(routes []Route) {
	sort.Slice(routes, func(i, j int) bool {
		iWildcard := strings.HasPrefix(routes[i].Pattern, "*.")
		jWildcard := strings.HasPrefix(routes[j].Pattern, "*.")
		if iWildcard != jWildcard {
			return !iWildcard
		}
		if iWildcard && len(routes[i].Pattern) != len(routes[j].Pattern) {
			return len(routes[i].Pattern) > len(routes[j].Pattern)
		}
		return routes[i].Pattern < routes[j].Pattern
	})
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) (err error) {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".dnsroutes-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = tmp.Close()
		if err != nil {
			_ = os.Remove(tmpPath)
		}
	}()
	if err = tmp.Chmod(mode); err != nil {
		return err
	}
	if _, err = tmp.Write(data); err != nil {
		return err
	}
	if err = tmp.Sync(); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	err = os.Rename(tmpPath, path)
	return err
}

// LoadFromFile loads routes from a specific file (used for initial load from upstreams file).
func LoadFromFile(path string) map[string]string {
	data, err := os.ReadFile(path) // #nosec G304 -- path comes from trusted config (upstreams/routes file settings), not from request input
	if err != nil {
		return nil
	}
	var result map[string]string
	if err := json.Unmarshal(data, &result); err != nil {
		return nil
	}
	return result
}

// SaveUpstreams writes the upstream server list to a JSON file.
func SaveUpstreams(path string, upstreams []string) error {
	data, err := json.MarshalIndent(upstreams, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// LoadUpstreams reads the upstream server list from a JSON file.
func LoadUpstreams(path string) []string {
	data, err := os.ReadFile(path) // #nosec G304 -- path comes from trusted config (upstreams file setting), not from request input
	if err != nil {
		return nil
	}
	var result []string
	if err := json.Unmarshal(data, &result); err != nil {
		// Try map format (legacy)
		var m map[string]string
		if err2 := json.Unmarshal(data, &m); err2 == nil {
			for k := range m {
				result = append(result, k)
			}
		}
		return result
	}
	return result
}

// ReadLines reads a file and returns non-empty, non-comment lines.
func ReadLines(path string) []string {
	file, err := os.Open(path) // #nosec G304 -- path comes from trusted config (blocklist/upstreams file settings), not from request input
	if err != nil {
		return nil
	}
	defer func() { _ = file.Close() }()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines
}

package dnsroutes

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
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
	mu     sync.RWMutex
	cancel context.CancelFunc
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
		// Domain must end with the suffix and have at least one subdomain label
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
func (dr *DNSRoutes) SetRoutes(routesMap map[string]string) error {
	dr.mu.Lock()
	defer dr.mu.Unlock()

	newRoutes := make([]Route, 0, len(routesMap))
	for pattern, upstream := range routesMap {
		newRoutes = append(newRoutes, Route{
			Pattern:  strings.ToLower(pattern),
			Upstream: upstream,
		})
	}

	// Save to file first to preserve atomicity
	if dr.path != "" {
		data, err := json.MarshalIndent(routesMap, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(dr.path, data, 0644); err != nil {
			return err
		}
		logger.Info("Saved %d DNS routes to %s", len(routesMap), dr.path)
	}

	dr.routes = newRoutes

	return nil
}

// LoadFromFile loads routes from a specific file (used for initial load from upstreams file).
func LoadFromFile(path string) map[string]string {
	data, err := os.ReadFile(path)
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
	return os.WriteFile(path, data, 0644)
}

// LoadUpstreams reads the upstream server list from a JSON file.
func LoadUpstreams(path string) []string {
	data, err := os.ReadFile(path)
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
	file, err := os.Open(path)
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

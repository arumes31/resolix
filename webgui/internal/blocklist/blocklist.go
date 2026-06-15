package blocklist

import (
	"bufio"
	"context"
	"os"
	"strings"
	"sync"
	"time"

	"tailscale-dnsrewrite/webgui/internal/logger"
)

// Blocklist manages a set of blocked domains loaded from a hosts-format file.
type Blocklist struct {
	path       string
	domains    map[string]bool
	mu         sync.RWMutex
	lastLoaded time.Time
	cancel     context.CancelFunc
}

// New creates a new Blocklist from the given file path and loads it immediately.
func New(path string) *Blocklist {
	bl := &Blocklist{
		path:    path,
		domains: make(map[string]bool),
	}
	bl.load()
	return bl
}

// load reads the blocklist file and updates the in-memory domain set.
// Supported formats:
//   - Standard hosts format: "0.0.0.0 domain.com" or "127.0.0.1 domain.com"
//   - Simple domain-per-line format (no IP prefix)
//   - Lines starting with # are comments, empty lines are skipped
func (bl *Blocklist) load() {
	newDomains := make(map[string]bool)

	if bl.path == "" {
		bl.mu.Lock()
		bl.domains = newDomains
		bl.lastLoaded = time.Now()
		bl.mu.Unlock()
		return
	}

	file, err := os.Open(bl.path)
	if err != nil {
		if os.IsNotExist(err) {
			logger.Warn("Blocklist file not found: %s", bl.path)
		} else {
			logger.Error("Failed to open blocklist file: %v", err)
		}
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

		// Parse the line: could be "0.0.0.0 domain.com" or just "domain.com"
		fields := strings.Fields(line)
		var domain string
		if len(fields) >= 2 {
			// Hosts format: IP domain
			ip := fields[0]
			if ip == "0.0.0.0" || ip == "127.0.0.1" || ip == "::1" {
				domain = fields[1]
			} else {
				// Not a blocking entry, skip
				continue
			}
		} else if len(fields) == 1 {
			// Simple domain-per-line format
			domain = fields[0]
		} else {
			continue
		}

		domain = strings.ToLower(strings.TrimSuffix(domain, "."))
		if domain != "" {
			newDomains[domain] = true
		}
	}

	if err := scanner.Err(); err != nil {
		logger.Error("Error reading blocklist file: %v", err)
		return
	}

	bl.mu.Lock()
	bl.domains = newDomains
	bl.lastLoaded = time.Now()
	bl.mu.Unlock()

	logger.Info("Loaded %d blocked domains from %s", len(newDomains), bl.path)
}

// StartReload begins periodic reloading of the blocklist file (every 60 seconds).
func (bl *Blocklist) StartReload(ctx context.Context) {
	if bl.cancel != nil {
		bl.cancel()
	}
	reloadCtx, cancel := context.WithCancel(ctx)
	bl.cancel = cancel
	ticker := time.NewTicker(60 * time.Second)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-reloadCtx.Done():
				return
			case <-ticker.C:
				bl.load()
			}
		}
	}()
}

// Stop cancels the reload goroutine.
func (bl *Blocklist) Stop() {
	if bl.cancel != nil {
		bl.cancel()
	}
}

// IsBlocked checks if a domain is in the blocklist.
func (bl *Blocklist) IsBlocked(domain string) bool {
	bl.mu.RLock()
	defer bl.mu.RUnlock()
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	return bl.domains[domain]
}

// Count returns the number of blocked domains.
func (bl *Blocklist) Count() int {
	bl.mu.RLock()
	defer bl.mu.RUnlock()
	return len(bl.domains)
}

// LastLoaded returns the time the blocklist was last loaded.
func (bl *Blocklist) LastLoaded() time.Time {
	bl.mu.RLock()
	defer bl.mu.RUnlock()
	return bl.lastLoaded
}

// Status returns the current blocklist status info.
func (bl *Blocklist) Status() map[string]interface{} {
	return map[string]interface{}{
		"count":       bl.Count(),
		"last_loaded": bl.LastLoaded().Format(time.RFC3339),
		"file":        bl.path,
	}
}

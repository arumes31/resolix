package config

import (
	"bufio"
	"context"
	"log"
	"maps"
	"os"
	"strings"
	"sync"
	"time"
)

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

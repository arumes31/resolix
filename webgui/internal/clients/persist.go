package clients

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
)

// reloadInterval is the hot-reload poll interval (like client aliases).
const reloadInterval = 30 * time.Second

// Load opens the registry file at path. A missing file yields an empty
// registry (persisted on first mutation). An empty path yields an in-memory
// registry.
func Load(path string) (*Registry, error) {
	r := &Registry{path: path}
	if path == "" {
		return r, nil
	}
	data, err := os.ReadFile(path) // #nosec G304 -- clients file path comes from trusted config (env/defaults), not request input
	if err != nil {
		if os.IsNotExist(err) {
			return r, nil
		}
		return nil, fmt.Errorf("read clients file %s: %w", path, err)
	}
	var clients []*Client
	if err := json.Unmarshal(data, &clients); err != nil {
		return nil, fmt.Errorf("parse clients file %s: %w", path, err)
	}
	for _, c := range clients {
		if err := c.compile(); err != nil {
			return nil, fmt.Errorf("clients file %s: %w", path, err)
		}
	}
	r.clients = clients
	return r, nil
}

// StartReload re-reads the registry file every 30s until ctx is canceled
// (hot-reload, like client aliases).
func (r *Registry) StartReload(ctx context.Context) {
	if r.path == "" {
		return
	}
	go func() {
		ticker := time.NewTicker(reloadInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				r.reload()
			}
		}
	}()
}

// reload re-reads the registry file, keeping the current set on errors.
func (r *Registry) reload() {
	fresh, err := Load(r.path)
	if err != nil {
		log.Printf("[WARN] clients: reload failed (keeping current): %v", err)
		return
	}
	r.mu.Lock()
	r.clients = fresh.clients
	r.mu.Unlock()
}

// save persists the registry atomically (temp file + rename).
func (r *Registry) save() (err error) {
	if r.path == "" {
		return nil
	}
	r.mu.RLock()
	data, err := json.MarshalIndent(r.clients, "", "  ")
	r.mu.RUnlock()
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(r.path), ".clients-*.tmp")
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
	if err = tmp.Chmod(0o600); err != nil {
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
	return os.Rename(tmpPath, r.path)
}

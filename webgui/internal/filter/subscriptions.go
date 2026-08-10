package filter

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
)

const maxSubscriptions = 100

// Subscription is a persisted remote filter source managed from /config.
type Subscription struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	URL       string `json:"url"`
	AllowOnly bool   `json:"allow_only"`
	Enabled   bool   `json:"enabled"`
}

// SubscriptionStore persists the master-authoritative subscription list.
type SubscriptionStore struct {
	mu    sync.RWMutex
	path  string
	items []Subscription
}

// LoadSubscriptionStore loads subscriptions or seeds a new store when the
// persistence file does not exist.
func LoadSubscriptionStore(path string, seeds []Subscription) (*SubscriptionStore, error) {
	store := &SubscriptionStore{path: path}
	data, err := os.ReadFile(path) // #nosec G304 -- path is derived from trusted application configuration
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("read filter subscriptions: %w", err)
		}
		store.items = slices.Clone(seeds)
		if err := store.replaceLocked(store.items); err != nil {
			return nil, err
		}
		return store, nil
	}
	if err := json.Unmarshal(data, &store.items); err != nil {
		return nil, fmt.Errorf("decode filter subscriptions: %w", err)
	}
	if err := validateSubscriptions(store.items); err != nil {
		return nil, fmt.Errorf("validate filter subscriptions: %w", err)
	}
	return store, nil
}

// List returns a defensive copy of all subscriptions.
func (s *SubscriptionStore) List() []Subscription {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return slices.Clone(s.items)
}

// Replace validates and persists the complete list.
func (s *SubscriptionStore) Replace(items []Subscription) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.replaceLocked(items)
}

func (s *SubscriptionStore) replaceLocked(items []Subscription) error {
	items = slices.Clone(items)
	for i := range items {
		items[i].Name = strings.TrimSpace(items[i].Name)
		items[i].URL = strings.TrimSpace(items[i].URL)
		if items[i].ID == "" {
			id, err := newSubscriptionID()
			if err != nil {
				return err
			}
			items[i].ID = id
		}
	}
	if err := validateSubscriptions(items); err != nil {
		return err
	}
	data, err := json.MarshalIndent(items, "", "  ")
	if err != nil {
		return fmt.Errorf("encode filter subscriptions: %w", err)
	}
	if err := writeSubscriptionsAtomic(s.path, data); err != nil {
		return fmt.Errorf("save filter subscriptions: %w", err)
	}
	s.items = items
	return nil
}

func validateSubscriptions(items []Subscription) error {
	if len(items) > maxSubscriptions {
		return fmt.Errorf("at most %d filter subscriptions are allowed", maxSubscriptions)
	}
	ids := make(map[string]struct{}, len(items))
	for i, item := range items {
		if len(item.Name) > 120 {
			return fmt.Errorf("subscription %d name exceeds 120 characters", i+1)
		}
		parsed, err := url.Parse(strings.TrimSpace(item.URL))
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil {
			return fmt.Errorf("subscription %d must use an http or https URL without embedded credentials", i+1)
		}
		if _, exists := ids[item.ID]; exists {
			return fmt.Errorf("duplicate subscription id %q", item.ID)
		}
		ids[item.ID] = struct{}{}
	}
	return nil
}

// ValidateSubscriptions validates a candidate list without persisting it.
func ValidateSubscriptions(items []Subscription) error {
	return validateSubscriptions(items)
}

func newSubscriptionID() (string, error) {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate subscription id: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

func writeSubscriptionsAtomic(path string, data []byte) (err error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".subscriptions-*.tmp") // #nosec G304 -- directory is trusted application configuration
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
	return os.Rename(tmpPath, path)
}

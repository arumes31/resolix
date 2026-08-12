package filter

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

func parseRefreshAtUTC(value string) (int, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return -1, nil
	}
	parsed, err := time.Parse("15:04", value)
	if err != nil {
		return 0, errors.New("refresh_at_utc must use HH:MM UTC")
	}
	return parsed.Hour()*60 + parsed.Minute(), nil
}

const (
	// SubscriptionDocumentVersion is the supported list import/export schema.
	SubscriptionDocumentVersion  = 1
	maxSubscriptions             = 100
	defaultSubscriptionTimeout   = 30
	maxSubscriptionTimeout       = 120
	defaultSubscriptionRedirects = 5
	maxSubscriptionRedirects     = 10
)

// ErrSubscriptionNotFound indicates that a requested managed list does not exist.
var ErrSubscriptionNotFound = errors.New("filter subscription not found")

// Subscription is a persisted remote filter source managed from /config.
type Subscription struct {
	ID                string `json:"id"`
	Name              string `json:"name"`
	URL               string `json:"url"`
	RefreshGeneration string `json:"refresh_generation,omitempty"`
	AllowOnly         bool   `json:"allow_only"`
	Enabled           bool   `json:"enabled"`
	AllowPrivate      bool   `json:"allow_private,omitempty"`
	TimeoutSeconds    int    `json:"timeout_seconds,omitempty"`
	RedirectLimit     int    `json:"redirect_limit,omitempty"`
	RefreshAtUTC      string `json:"refresh_at_utc,omitempty"`
}

// SubscriptionDocument is the versioned import/export representation.
type SubscriptionDocument struct {
	Version       int            `json:"version"`
	Subscriptions []Subscription `json:"subscriptions"`
}

// NewSubscriptionDocument returns an export document with a defensive copy.
func NewSubscriptionDocument(items []Subscription) SubscriptionDocument {
	return SubscriptionDocument{Version: SubscriptionDocumentVersion, Subscriptions: slices.Clone(items)}
}

// Validate verifies the document schema and subscription contents.
func (d SubscriptionDocument) Validate() error {
	if d.Version != SubscriptionDocumentVersion {
		return fmt.Errorf("unsupported subscription document version %d", d.Version)
	}
	items := slices.Clone(d.Subscriptions)
	for index := range items {
		if strings.TrimSpace(items[index].ID) == "" {
			items[index].ID = fmt.Sprintf("import-%d", index)
		}
	}
	return validateSubscriptions(items)
}

// SubscriptionStore persists the controller-authoritative subscription list.
type SubscriptionStore struct {
	mu    sync.RWMutex
	path  string
	items []Subscription
}

// HistoryDir returns the state directory used for bounded last-good versions.
func (s *SubscriptionStore) HistoryDir() string {
	if strings.TrimSpace(s.path) == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(s.path), "filter-history")
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

// Bulk applies one validated operation to the selected subscriptions and
// persists the complete result atomically.
func (s *SubscriptionStore) Bulk(action string, ids []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(ids) == 0 {
		return errors.New("at least one subscription id is required")
	}
	selected := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			return errors.New("subscription id may not be empty")
		}
		selected[id] = struct{}{}
	}
	found := make(map[string]struct{}, len(selected))
	items := slices.Clone(s.items)
	refreshGeneration := ""
	if action == "refresh" {
		var err error
		refreshGeneration, err = newSubscriptionID()
		if err != nil {
			return fmt.Errorf("generate subscription refresh generation: %w", err)
		}
	}
	result := make([]Subscription, 0, len(items))
	for _, item := range items {
		if _, ok := selected[item.ID]; !ok {
			result = append(result, item)
			continue
		}
		found[item.ID] = struct{}{}
		switch action {
		case "enable":
			item.Enabled = true
		case "disable":
			item.Enabled = false
		case "refresh":
			item.RefreshGeneration = refreshGeneration
		case "delete":
			continue
		default:
			return fmt.Errorf("unsupported subscription bulk action %q", action)
		}
		result = append(result, item)
	}
	if len(found) != len(selected) {
		return ErrSubscriptionNotFound
	}
	return s.replaceLocked(result)
}

// RequestRefresh persists a new generation so resolver nodes observe a
// configuration revision change and refresh their subscriptions too.
func (s *SubscriptionStore) RequestRefresh() error {
	return s.requestRefresh("")
}

// RequestSourceRefresh persists a new generation for one subscription.
func (s *SubscriptionStore) RequestSourceRefresh(id string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return errors.New("subscription id is required")
	}
	return s.requestRefresh(id)
}

func (s *SubscriptionStore) requestRefresh(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id != "" {
		found := false
		for _, item := range s.items {
			if item.ID == id {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("%w: %s", ErrSubscriptionNotFound, id)
		}
	}
	if len(s.items) == 0 {
		return nil
	}
	generation, err := newSubscriptionID()
	if err != nil {
		return fmt.Errorf("generate subscription refresh generation: %w", err)
	}
	items := slices.Clone(s.items)
	found := false
	for i := range items {
		if id != "" && items[i].ID != id {
			continue
		}
		items[i].RefreshGeneration = generation
		found = true
	}
	if id != "" && !found {
		return fmt.Errorf("%w: %s", ErrSubscriptionNotFound, id)
	}
	return s.replaceLocked(items)
}

func (s *SubscriptionStore) replaceLocked(items []Subscription) error {
	items = slices.Clone(items)
	for i := range items {
		items[i].Name = strings.TrimSpace(items[i].Name)
		normalizedURL, err := normalizeSubscriptionURL(items[i].URL)
		if err != nil {
			return fmt.Errorf("subscription %d: %w", i+1, err)
		}
		items[i].URL = normalizedURL
		items[i].RefreshGeneration = strings.TrimSpace(items[i].RefreshGeneration)
		items[i].RefreshAtUTC = strings.TrimSpace(items[i].RefreshAtUTC)
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
	urls := make(map[string]int, len(items))
	for i, item := range items {
		if len(item.Name) > 120 {
			return fmt.Errorf("subscription %d name exceeds 120 characters", i+1)
		}
		if len(item.RefreshGeneration) > 64 {
			return fmt.Errorf("subscription %d refresh generation exceeds 64 characters", i+1)
		}
		if _, err := parseRefreshAtUTC(item.RefreshAtUTC); err != nil {
			return fmt.Errorf("subscription %d: %w", i+1, err)
		}
		normalizedURL, err := normalizeSubscriptionURL(item.URL)
		if err != nil {
			return fmt.Errorf("subscription %d: %w", i+1, err)
		}
		if previous, exists := urls[normalizedURL]; exists {
			return fmt.Errorf("subscription %d duplicates subscription %d URL %q", i+1, previous+1, normalizedURL)
		}
		urls[normalizedURL] = i
		if item.TimeoutSeconds < 0 || item.TimeoutSeconds > maxSubscriptionTimeout {
			return fmt.Errorf("subscription %d timeout must be zero or between 1 and %d seconds", i+1, maxSubscriptionTimeout)
		}
		if item.RedirectLimit < 0 || item.RedirectLimit > maxSubscriptionRedirects {
			return fmt.Errorf("subscription %d redirect limit must be zero or between 1 and %d", i+1, maxSubscriptionRedirects)
		}
		if _, exists := ids[item.ID]; exists {
			return fmt.Errorf("duplicate subscription id %q", item.ID)
		}
		ids[item.ID] = struct{}{}
	}
	return nil
}

func normalizeSubscriptionURL(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil {
		return "", errors.New("must use an http or https URL without embedded credentials")
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	hostname := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	if hostname == "" {
		return "", errors.New("must include a hostname")
	}
	port := parsed.Port()
	if (parsed.Scheme == "http" && port == "80") || (parsed.Scheme == "https" && port == "443") {
		port = ""
	}
	if port == "" {
		if address, err := netip.ParseAddr(hostname); err == nil && address.Is6() {
			parsed.Host = "[" + hostname + "]"
		} else {
			parsed.Host = hostname
		}
	} else {
		parsed.Host = net.JoinHostPort(hostname, port)
	}
	if parsed.Path == "" {
		parsed.Path = "/"
	}
	parsed.Fragment = ""
	return parsed.String(), nil
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

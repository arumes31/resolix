package magicdns

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

var (
	tailscaleIPv4 = netip.MustParsePrefix("100.64.0.0/10")
	tailscaleIPv6 = netip.MustParsePrefix("fd7a:115c:a1e0::/48")
)

type deviceLister interface {
	ListDevices(context.Context) ([]Device, error)
}

// Status describes synchronization health without exposing credentials.
type Status struct {
	LastAttempt time.Time `json:"last_attempt,omitempty"`
	LastSuccess time.Time `json:"last_success,omitempty"`
	LastError   string    `json:"last_error,omitempty"`
	DeviceCount int       `json:"device_count"`
	RecordCount int       `json:"record_count"`
}

// Syncer periodically reconciles the Tailscale device inventory into Store.
type Syncer struct {
	client   deviceLister
	store    *Store
	tailnet  string
	interval time.Duration
	now      func() time.Time

	syncMu   sync.Mutex
	statusMu sync.RWMutex
	status   Status
}

// NewSyncer creates a serialized, context-aware reconciliation worker.
func NewSyncer(client deviceLister, store *Store, tailnet string, interval time.Duration) (*Syncer, error) {
	if client == nil || store == nil {
		return nil, errors.New("magicdns client and store are required")
	}
	tailnet = strings.TrimSpace(tailnet)
	if tailnet == "" {
		return nil, errors.New("magicdns tailnet is required")
	}
	if interval <= 0 {
		return nil, errors.New("magicdns sync interval must be positive")
	}
	return &Syncer{
		client:   client,
		store:    store,
		tailnet:  tailnet,
		interval: interval,
		now:      time.Now,
	}, nil
}

// Sync performs one atomic reconciliation. A failed fetch leaves Store intact.
func (s *Syncer) Sync(ctx context.Context) error {
	s.syncMu.Lock()
	defer s.syncMu.Unlock()
	attemptedAt := s.now().UTC()
	s.setAttempt(attemptedAt)

	devices, err := s.client.ListDevices(ctx)
	if err != nil {
		s.setError(err)
		return fmt.Errorf("fetch magicdns devices: %w", err)
	}
	records, includedDevices := RecordsFromDevices(devices, attemptedAt)
	if err := s.store.Replace(s.tailnet, records, attemptedAt); err != nil {
		s.setError(err)
		return fmt.Errorf("publish magicdns records: %w", err)
	}
	s.statusMu.Lock()
	s.status.LastSuccess = attemptedAt
	s.status.LastError = ""
	s.status.DeviceCount = includedDevices
	s.status.RecordCount = len(records)
	s.statusMu.Unlock()
	return nil
}

// Run performs an immediate sync and then repeats at the configured interval.
// The callback receives each attempt result and must return promptly.
func (s *Syncer) Run(ctx context.Context, onResult func(error)) {
	run := func() {
		err := s.Sync(ctx)
		if onResult != nil {
			onResult(err)
		}
	}
	run()
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			run()
		}
	}
}

// Status returns a point-in-time defensive value.
func (s *Syncer) Status() Status {
	s.statusMu.RLock()
	defer s.statusMu.RUnlock()
	return s.status
}

// RecordsFromDevices converts authorized, unexpired devices into exact FQDN
// Tailscale A and AAAA records. Offline, external, and ephemeral devices stay
// included because they remain part of the MagicDNS inventory.
func RecordsFromDevices(devices []Device, now time.Time) ([]Record, int) {
	records := make([]Record, 0, len(devices)*2)
	includedDevices := 0
	for _, device := range devices {
		if !device.Authorized || (!device.KeyExpiryDisabled && deviceExpired(device.Expires, now)) {
			continue
		}
		name := normalizeName(device.Name)
		if _, valid := dns.IsDomainName(name); !valid || name == "" {
			continue
		}
		nodeID := strings.TrimSpace(device.NodeID)
		if nodeID == "" {
			nodeID = strings.TrimSpace(device.ID)
		}
		if nodeID == "" {
			continue
		}
		before := len(records)
		for _, rawAddress := range device.Addresses {
			address, err := netip.ParseAddr(strings.TrimSpace(rawAddress))
			if err != nil {
				continue
			}
			switch {
			case address.Is4() && tailscaleIPv4.Contains(address):
				records = append(records, Record{NodeID: nodeID, Name: name, Type: "A", Value: address.String()})
			case address.Is6() && tailscaleIPv6.Contains(address):
				records = append(records, Record{NodeID: nodeID, Name: name, Type: "AAAA", Value: address.String()})
			}
		}
		if len(records) > before {
			includedDevices++
		}
	}
	return records, includedDevices
}

func deviceExpired(raw string, now time.Time) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return false
	}
	expires, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return true
	}
	return !expires.After(now)
}

func (s *Syncer) setAttempt(attemptedAt time.Time) {
	s.statusMu.Lock()
	s.status.LastAttempt = attemptedAt
	s.statusMu.Unlock()
}

func (s *Syncer) setError(err error) {
	s.statusMu.Lock()
	s.status.LastError = err.Error()
	s.statusMu.Unlock()
}

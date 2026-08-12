// Package magicdns imports Tailscale MagicDNS device records and exposes a
// concurrency-safe, persisted snapshot for the DNS server and agent sync.
package magicdns

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	// SnapshotVersion is the wire and persistence schema version.
	SnapshotVersion  = 1
	maxSnapshotBytes = 32 * 1024 * 1024
	maxRecords       = 200000
)

// Record is one generated MagicDNS address record.
type Record struct {
	NodeID string `json:"node_id"`
	Name   string `json:"name"`
	Type   string `json:"type"`
	Value  string `json:"value"`
}

// Snapshot is the atomic unit persisted locally and synchronized to agents.
type Snapshot struct {
	Version    int       `json:"version"`
	Tailnet    string    `json:"tailnet,omitempty"`
	Generation string    `json:"generation"`
	SyncedAt   time.Time `json:"synced_at,omitempty"`
	Records    []Record  `json:"records"`
}

// Store owns the last known good MagicDNS snapshot.
type Store struct {
	mu       sync.RWMutex
	writeMu  sync.Mutex
	path     string
	snapshot Snapshot
	onChange func()
}

// NewStore creates an empty store. An empty path keeps the store in memory.
func NewStore(path string) *Store {
	return &Store{
		path: path,
		snapshot: Snapshot{
			Version: SnapshotVersion,
			Records: make([]Record, 0),
		},
	}
}

// Load reads a persisted last-good snapshot. A missing file produces an empty
// store so first startup does not require Tailscale to be immediately reachable.
func Load(path string) (*Store, error) {
	store := NewStore(path)
	if strings.TrimSpace(path) == "" {
		return store, nil
	}

	file, err := os.Open(path) // #nosec G304 -- path is administrator-owned configuration.
	if errors.Is(err, os.ErrNotExist) {
		return store, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open magicdns snapshot: %w", err)
	}
	defer func() { _ = file.Close() }()

	data, err := io.ReadAll(io.LimitReader(file, maxSnapshotBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read magicdns snapshot: %w", err)
	}
	if len(data) > maxSnapshotBytes {
		return nil, fmt.Errorf("magicdns snapshot exceeds %d bytes", maxSnapshotBytes)
	}

	var snapshot Snapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return nil, fmt.Errorf("decode magicdns snapshot: %w", err)
	}
	normalized, err := normalizeSnapshot(snapshot)
	if err != nil {
		return nil, fmt.Errorf("validate magicdns snapshot: %w", err)
	}
	store.snapshot = normalized
	return store, nil
}

// SetOnChange registers a callback invoked after the record generation changes.
func (s *Store) SetOnChange(fn func()) {
	s.mu.Lock()
	s.onChange = fn
	s.mu.Unlock()
}

// Replace validates and persists records before publishing them to readers.
func (s *Store) Replace(tailnet string, records []Record, syncedAt time.Time) error {
	snapshot := Snapshot{
		Version:  SnapshotVersion,
		Tailnet:  strings.TrimSpace(tailnet),
		SyncedAt: syncedAt.UTC(),
		Records:  records,
	}
	return s.Apply(snapshot)
}

// Apply validates and atomically publishes a controller-provided snapshot.
func (s *Store) Apply(snapshot Snapshot) error {
	normalized, err := normalizeSnapshot(snapshot)
	if err != nil {
		return err
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if err := s.save(normalized); err != nil {
		return fmt.Errorf("persist magicdns snapshot: %w", err)
	}

	s.mu.Lock()
	changed := normalized.Generation != s.snapshot.Generation
	s.snapshot = normalized
	onChange := s.onChange
	s.mu.Unlock()
	if changed && onChange != nil {
		onChange()
	}
	return nil
}

// Snapshot returns a defensive copy of the current last-good snapshot.
func (s *Store) Snapshot() Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneSnapshot(s.snapshot)
}

// Lookup returns exact-name records for the requested A or AAAA type.
func (s *Store) Lookup(name, recordType string) []Record {
	name = normalizeName(name)
	recordType = strings.ToUpper(strings.TrimSpace(recordType))
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]Record, 0, 2)
	for _, record := range s.snapshot.Records {
		if record.Name == name && record.Type == recordType {
			result = append(result, record)
		}
	}
	return result
}

func (s *Store) save(snapshot Snapshot) error {
	if strings.TrimSpace(s.path) == "" {
		return nil
	}
	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return err
	}
	if len(data) > maxSnapshotBytes {
		return fmt.Errorf("magicdns snapshot exceeds %d bytes", maxSnapshotBytes)
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o750); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(s.path), ".magicdns-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryPath)
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, s.path); err != nil {
		return err
	}
	return nil
}

func normalizeSnapshot(snapshot Snapshot) (Snapshot, error) {
	if snapshot.Version == 0 {
		snapshot.Version = SnapshotVersion
	}
	if snapshot.Version != SnapshotVersion {
		return Snapshot{}, fmt.Errorf("unsupported magicdns snapshot version %d", snapshot.Version)
	}
	if len(snapshot.Records) > maxRecords {
		return Snapshot{}, fmt.Errorf("magicdns snapshot exceeds %d records", maxRecords)
	}

	records := make([]Record, 0, len(snapshot.Records))
	seen := make(map[string]struct{}, len(snapshot.Records))
	for _, record := range snapshot.Records {
		normalized, err := normalizeRecord(record)
		if err != nil {
			return Snapshot{}, err
		}
		key := normalized.Name + "\x00" + normalized.Type + "\x00" + normalized.Value
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		records = append(records, normalized)
	}
	sort.Slice(records, func(i, j int) bool {
		left := records[i]
		right := records[j]
		if left.Name != right.Name {
			return left.Name < right.Name
		}
		if left.Type != right.Type {
			return left.Type < right.Type
		}
		if left.Value != right.Value {
			return left.Value < right.Value
		}
		return left.NodeID < right.NodeID
	})

	generation, err := recordGeneration(records)
	if err != nil {
		return Snapshot{}, err
	}
	if snapshot.Generation != "" && snapshot.Generation != generation {
		return Snapshot{}, errors.New("magicdns snapshot generation does not match its records")
	}
	return Snapshot{
		Version:    SnapshotVersion,
		Tailnet:    strings.TrimSpace(snapshot.Tailnet),
		Generation: generation,
		SyncedAt:   snapshot.SyncedAt.UTC(),
		Records:    records,
	}, nil
}

func normalizeRecord(record Record) (Record, error) {
	record.NodeID = strings.TrimSpace(record.NodeID)
	record.Name = normalizeName(record.Name)
	record.Type = strings.ToUpper(strings.TrimSpace(record.Type))
	record.Value = strings.TrimSpace(record.Value)
	if record.NodeID == "" || len(record.NodeID) > 256 || strings.ContainsAny(record.NodeID, "\r\n\x00") {
		return Record{}, errors.New("magicdns record node id is invalid")
	}
	if _, valid := dns.IsDomainName(record.Name); record.Name == "" || !valid || strings.ContainsAny(record.Name, "\r\n\x00") {
		return Record{}, errors.New("magicdns record name is invalid")
	}
	if record.Type != "A" && record.Type != "AAAA" {
		return Record{}, fmt.Errorf("unsupported magicdns record type %q", record.Type)
	}
	address, err := netip.ParseAddr(record.Value)
	if err != nil || (record.Type == "A" && !address.Is4()) || (record.Type == "AAAA" && !address.Is6()) {
		return Record{}, errors.New("magicdns record value is invalid")
	}
	record.Value = address.String()
	return record, nil
}

func recordGeneration(records []Record) (string, error) {
	data, err := json.Marshal(records)
	if err != nil {
		return "", fmt.Errorf("encode magicdns generation: %w", err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func normalizeName(name string) string {
	return strings.ToLower(strings.Trim(strings.TrimSpace(name), "."))
}

func cloneSnapshot(snapshot Snapshot) Snapshot {
	clone := snapshot
	clone.Records = append([]Record{}, snapshot.Records...)
	return clone
}

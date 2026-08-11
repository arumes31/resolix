// Package configsync defines the versioned DNS configuration replicated from
// a controller node to resolver nodes.
package configsync

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"

	"github.com/arumes31/resolix/webgui/internal/clients"
	"github.com/arumes31/resolix/webgui/internal/dnssettings"
	"github.com/arumes31/resolix/webgui/internal/filter"
	"github.com/arumes31/resolix/webgui/internal/rewrites"
)

// CurrentVersion is the supported configuration snapshot schema version.
const CurrentVersion = 5

// ErrIncompatibleVersion identifies snapshots produced by an unsupported
// configuration schema. Callers can surface this separately from a damaged
// content revision.
var ErrIncompatibleVersion = errors.New("incompatible configuration snapshot version")

// snapshotPayload is the revisioned content of a configuration snapshot.
type snapshotPayload struct {
	Version          int                   `json:"version"`
	Upstreams        []string              `json:"upstreams"`
	BootstrapServers []string              `json:"bootstrap_servers"`
	Routes           map[string]string     `json:"routes"`
	Subscriptions    []filter.Subscription `json:"subscriptions"`
	UserRules        string                `json:"user_rules"`
	Rewrites         []rewrites.Rewrite    `json:"rewrites"`
	Clients          []clients.Client      `json:"clients"`
	DNSSettings      *dnssettings.Settings `json:"dns_settings"`
}

// Snapshot is a complete controller-authoritative configuration revision.
type Snapshot struct {
	snapshotPayload
	Revision string `json:"revision"`
}

// NewSnapshot defensively copies values and computes a stable content hash.
func NewSnapshot(
	upstreams []string,
	bootstrapServers []string,
	routes map[string]string,
	subscriptions []filter.Subscription,
	userRules string,
	rewriteItems []rewrites.Rewrite,
	clientItems []clients.Client,
) (Snapshot, error) {
	return NewSnapshotWithDNSSettings(
		upstreams,
		bootstrapServers,
		routes,
		subscriptions,
		userRules,
		rewriteItems,
		clientItems,
		nil,
	)
}

// NewSnapshotWithDNSSettings includes the controller-managed live DNS policy
// in the content revision. A nil settings pointer is retained for callers that
// intentionally construct partial snapshots in tests or migration tooling.
func NewSnapshotWithDNSSettings(
	upstreams []string,
	bootstrapServers []string,
	routes map[string]string,
	subscriptions []filter.Subscription,
	userRules string,
	rewriteItems []rewrites.Rewrite,
	clientItems []clients.Client,
	dnsSettings *dnssettings.Settings,
) (Snapshot, error) {
	snapshot := Snapshot{
		snapshotPayload: snapshotPayload{
			Version:          CurrentVersion,
			Upstreams:        slices.Clone(upstreams),
			BootstrapServers: slices.Clone(bootstrapServers),
			Routes:           maps.Clone(routes),
			Subscriptions:    slices.Clone(subscriptions),
			UserRules:        userRules,
			Rewrites:         cloneRewrites(rewriteItems),
			Clients:          cloneClients(clientItems),
			DNSSettings:      cloneDNSSettings(dnsSettings),
		},
	}
	revision, err := snapshotRevision(snapshot.snapshotPayload)
	if err != nil {
		return Snapshot{}, err
	}
	snapshot.Revision = revision
	return snapshot, nil
}

func cloneDNSSettings(settings *dnssettings.Settings) *dnssettings.Settings {
	if settings == nil {
		return nil
	}
	cloned := settings.Normalize()
	return &cloned
}

func cloneRewrites(items []rewrites.Rewrite) []rewrites.Rewrite {
	cloned := slices.Clone(items)
	for i := range cloned {
		cloned[i].SourceCIDRs = slices.Clone(cloned[i].SourceCIDRs)
	}
	return cloned
}

func cloneClients(items []clients.Client) []clients.Client {
	cloned := slices.Clone(items)
	for i := range cloned {
		cloned[i].IDs = slices.Clone(cloned[i].IDs)
		cloned[i].Tags = slices.Clone(cloned[i].Tags)
		cloned[i].SafeSearchEngines = slices.Clone(cloned[i].SafeSearchEngines)
		cloned[i].Upstreams = slices.Clone(cloned[i].Upstreams)
	}
	return cloned
}

// Clone returns a defensive copy suitable for retaining as the previous
// known-good snapshot.
func (s Snapshot) Clone() Snapshot {
	return Snapshot{
		snapshotPayload: snapshotPayload{
			Version:          s.Version,
			Upstreams:        slices.Clone(s.Upstreams),
			BootstrapServers: slices.Clone(s.BootstrapServers),
			Routes:           maps.Clone(s.Routes),
			Subscriptions:    slices.Clone(s.Subscriptions),
			UserRules:        s.UserRules,
			Rewrites:         cloneRewrites(s.Rewrites),
			Clients:          cloneClients(s.Clients),
			DNSSettings:      cloneDNSSettings(s.DNSSettings),
		},
		Revision: s.Revision,
	}
}

// SchemaCompatible reports whether this process understands the snapshot.
func (s Snapshot) SchemaCompatible() bool {
	return s.Version == CurrentVersion
}

// Validate verifies both schema compatibility and content integrity.
func (s Snapshot) Validate() error {
	if !s.SchemaCompatible() {
		return fmt.Errorf("%w: got %d, support %d", ErrIncompatibleVersion, s.Version, CurrentVersion)
	}
	valid, err := s.ValidRevision()
	if err != nil {
		return err
	}
	if !valid {
		return errors.New("configuration snapshot revision does not match its content")
	}
	return nil
}

// ValidRevision reports whether the snapshot revision matches its content.
func (s Snapshot) ValidRevision() (bool, error) {
	revision, err := snapshotRevision(s.snapshotPayload)
	if err != nil {
		return false, err
	}
	return s.Version == CurrentVersion && s.Revision == revision, nil
}

// FieldDiff is a readable, JSON-safe description of one changed snapshot
// field. User rules are summarized rather than copied into status responses.
type FieldDiff struct {
	Field  string `json:"field"`
	Before any    `json:"before"`
	After  any    `json:"after"`
}

// Diff returns stable field-level changes between two snapshots.
func Diff(before, after Snapshot) []FieldDiff {
	diffs := make([]FieldDiff, 0, 8)
	appendDiff := func(field string, oldValue, newValue any) {
		if !reflect.DeepEqual(oldValue, newValue) {
			diffs = append(diffs, FieldDiff{Field: field, Before: oldValue, After: newValue})
		}
	}
	appendDiff("schema_version", before.Version, after.Version)
	appendDiff("upstreams", before.Upstreams, after.Upstreams)
	appendDiff("bootstrap_servers", before.BootstrapServers, after.BootstrapServers)
	appendDiff("routes", before.Routes, after.Routes)
	appendDiff("subscriptions", before.Subscriptions, after.Subscriptions)
	appendDiff("user_rules", summarizeRules(before.UserRules), summarizeRules(after.UserRules))
	appendDiff("rewrites", before.Rewrites, after.Rewrites)
	appendDiff("clients", before.Clients, after.Clients)
	appendDiff("dns_settings", before.DNSSettings, after.DNSSettings)
	return diffs
}

func summarizeRules(rules string) string {
	trimmed := strings.TrimSpace(rules)
	if trimmed == "" {
		return "empty"
	}
	digest := sha256.Sum256([]byte(rules))
	return fmt.Sprintf("%d lines, sha256:%s", strings.Count(trimmed, "\n")+1, hex.EncodeToString(digest[:6]))
}

func snapshotRevision(payload snapshotPayload) (string, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return "", errors.Join(errors.New("marshal configuration snapshot revision payload"), err)
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:]), nil
}

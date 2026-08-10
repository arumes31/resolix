// Package configsync defines the versioned DNS configuration replicated from
// a master node to resolver nodes.
package configsync

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"maps"
	"slices"

	"tailscale-dnsrewrite/webgui/internal/clients"
	"tailscale-dnsrewrite/webgui/internal/filter"
	"tailscale-dnsrewrite/webgui/internal/rewrites"
)

// CurrentVersion is the supported configuration snapshot schema version.
const CurrentVersion = 1

// Snapshot is a complete master-authoritative configuration revision.
type Snapshot struct {
	Version       int                   `json:"version"`
	Revision      string                `json:"revision"`
	Upstreams     []string              `json:"upstreams"`
	Routes        map[string]string     `json:"routes"`
	Subscriptions []filter.Subscription `json:"subscriptions"`
	UserRules     string                `json:"user_rules"`
	Rewrites      []rewrites.Rewrite    `json:"rewrites"`
	Clients       []clients.Client      `json:"clients"`
}

// NewSnapshot defensively copies values and computes a stable content hash.
func NewSnapshot(
	upstreams []string,
	routes map[string]string,
	subscriptions []filter.Subscription,
	userRules string,
	rewriteItems []rewrites.Rewrite,
	clientItems []clients.Client,
) Snapshot {
	snapshot := Snapshot{
		Version:       CurrentVersion,
		Upstreams:     slices.Clone(upstreams),
		Routes:        maps.Clone(routes),
		Subscriptions: slices.Clone(subscriptions),
		UserRules:     userRules,
		Rewrites:      slices.Clone(rewriteItems),
		Clients:       slices.Clone(clientItems),
	}
	payload, _ := json.Marshal(snapshotPayload(snapshot))
	digest := sha256.Sum256(payload)
	snapshot.Revision = hex.EncodeToString(digest[:])
	return snapshot
}

// ValidRevision reports whether the snapshot revision matches its content.
func (s Snapshot) ValidRevision() bool {
	payload, err := json.Marshal(snapshotPayload(s))
	if err != nil {
		return false
	}
	digest := sha256.Sum256(payload)
	return s.Version == CurrentVersion && s.Revision == hex.EncodeToString(digest[:])
}

func snapshotPayload(snapshot Snapshot) struct {
	Version       int                   `json:"version"`
	Upstreams     []string              `json:"upstreams"`
	Routes        map[string]string     `json:"routes"`
	Subscriptions []filter.Subscription `json:"subscriptions"`
	UserRules     string                `json:"user_rules"`
	Rewrites      []rewrites.Rewrite    `json:"rewrites"`
	Clients       []clients.Client      `json:"clients"`
} {
	return struct {
		Version       int                   `json:"version"`
		Upstreams     []string              `json:"upstreams"`
		Routes        map[string]string     `json:"routes"`
		Subscriptions []filter.Subscription `json:"subscriptions"`
		UserRules     string                `json:"user_rules"`
		Rewrites      []rewrites.Rewrite    `json:"rewrites"`
		Clients       []clients.Client      `json:"clients"`
	}{
		Version:       snapshot.Version,
		Upstreams:     snapshot.Upstreams,
		Routes:        snapshot.Routes,
		Subscriptions: snapshot.Subscriptions,
		UserRules:     snapshot.UserRules,
		Rewrites:      snapshot.Rewrites,
		Clients:       snapshot.Clients,
	}
}

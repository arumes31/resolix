// Package configsync defines the versioned DNS configuration replicated from
// a controller node to resolver nodes.
package configsync

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"maps"
	"slices"

	"github.com/arumes31/resolix/webgui/internal/clients"
	"github.com/arumes31/resolix/webgui/internal/filter"
	"github.com/arumes31/resolix/webgui/internal/rewrites"
)

// CurrentVersion is the supported configuration snapshot schema version.
const CurrentVersion = 2

// snapshotPayload is the revisioned content of a configuration snapshot.
type snapshotPayload struct {
	Version       int                   `json:"version"`
	Upstreams     []string              `json:"upstreams"`
	Routes        map[string]string     `json:"routes"`
	Subscriptions []filter.Subscription `json:"subscriptions"`
	UserRules     string                `json:"user_rules"`
	Rewrites      []rewrites.Rewrite    `json:"rewrites"`
	Clients       []clients.Client      `json:"clients"`
}

// Snapshot is a complete controller-authoritative configuration revision.
type Snapshot struct {
	snapshotPayload
	Revision string `json:"revision"`
}

// NewSnapshot defensively copies values and computes a stable content hash.
func NewSnapshot(
	upstreams []string,
	routes map[string]string,
	subscriptions []filter.Subscription,
	userRules string,
	rewriteItems []rewrites.Rewrite,
	clientItems []clients.Client,
) (Snapshot, error) {
	snapshot := Snapshot{
		snapshotPayload: snapshotPayload{
			Version:       CurrentVersion,
			Upstreams:     slices.Clone(upstreams),
			Routes:        maps.Clone(routes),
			Subscriptions: slices.Clone(subscriptions),
			UserRules:     userRules,
			Rewrites:      cloneRewrites(rewriteItems),
			Clients:       slices.Clone(clientItems),
		},
	}
	revision, err := snapshotRevision(snapshot.snapshotPayload)
	if err != nil {
		return Snapshot{}, err
	}
	snapshot.Revision = revision
	return snapshot, nil
}

func cloneRewrites(items []rewrites.Rewrite) []rewrites.Rewrite {
	cloned := slices.Clone(items)
	for i := range cloned {
		cloned[i].SourceCIDRs = slices.Clone(cloned[i].SourceCIDRs)
	}
	return cloned
}

// ValidRevision reports whether the snapshot revision matches its content.
func (s Snapshot) ValidRevision() (bool, error) {
	revision, err := snapshotRevision(s.snapshotPayload)
	if err != nil {
		return false, err
	}
	return s.Version == CurrentVersion && s.Revision == revision, nil
}

func snapshotRevision(payload snapshotPayload) (string, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return "", errors.Join(errors.New("marshal configuration snapshot revision payload"), err)
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:]), nil
}

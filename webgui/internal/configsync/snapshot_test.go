package configsync

import (
	"testing"

	"github.com/arumes31/resolix/webgui/internal/rewrites"
)

func TestSnapshotRevisionDetectsMutation(t *testing.T) {
	snapshot, err := NewSnapshot(
		[]string{"1.1.1.1"},
		[]string{"9.9.9.9"},
		nil,
		nil,
		"||example.test^\n",
		[]rewrites.Rewrite{{
			ID:          "rewrite-1",
			Domain:      "internal.example",
			Type:        rewrites.TypeA,
			Value:       "192.0.2.10",
			SourceCIDRs: []string{"100.64.0.0/10"},
		}},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	valid, err := snapshot.ValidRevision()
	if err != nil {
		t.Fatal(err)
	}
	if !valid {
		t.Fatal("new snapshot has invalid revision")
	}
	snapshot.Upstreams[0] = "9.9.9.9"
	valid, err = snapshot.ValidRevision()
	if err != nil {
		t.Fatal(err)
	}
	if valid {
		t.Fatal("content mutation did not invalidate revision")
	}
	snapshot, err = NewSnapshot(
		[]string{"1.1.1.1"},
		[]string{"9.9.9.9"},
		nil,
		nil,
		"||example.test^\n",
		[]rewrites.Rewrite{{
			ID:          "rewrite-1",
			Domain:      "internal.example",
			Type:        rewrites.TypeA,
			Value:       "192.0.2.10",
			SourceCIDRs: []string{"100.64.0.0/10"},
		}},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Rewrites[0].SourceCIDRs[0] = "192.168.0.0/16"
	valid, err = snapshot.ValidRevision()
	if err != nil {
		t.Fatal(err)
	}
	if valid {
		t.Fatal("source CIDR mutation did not invalidate revision")
	}
	snapshot, err = NewSnapshot([]string{"1.1.1.1"}, []string{"9.9.9.9"}, nil, nil, "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.BootstrapServers[0] = "8.8.8.8"
	valid, err = snapshot.ValidRevision()
	if err != nil {
		t.Fatal(err)
	}
	if valid {
		t.Fatal("bootstrap resolver mutation did not invalidate revision")
	}
}

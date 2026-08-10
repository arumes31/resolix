package configsync

import "testing"

func TestSnapshotRevisionDetectsMutation(t *testing.T) {
	snapshot := NewSnapshot([]string{"1.1.1.1"}, nil, nil, "||example.test^\n", nil, nil)
	if !snapshot.ValidRevision() {
		t.Fatal("new snapshot has invalid revision")
	}
	snapshot.Upstreams[0] = "9.9.9.9"
	if snapshot.ValidRevision() {
		t.Fatal("content mutation did not invalidate revision")
	}
}

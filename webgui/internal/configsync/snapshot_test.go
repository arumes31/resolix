package configsync

import "testing"

func TestSnapshotRevisionDetectsMutation(t *testing.T) {
	snapshot, err := NewSnapshot([]string{"1.1.1.1"}, nil, nil, "||example.test^\n", nil, nil)
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
}

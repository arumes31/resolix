package storage

import (
	"testing"

	"github.com/arumes31/resolix/webgui/internal/models"
)

func TestStableNodeIdentityPreventsDuplicateNameOverwriteAndTombstones(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()
	if !store.SetNodeStatusIdentity("node-a", "resolver", models.NodeStatus{SourceAddress: "100.64.0.1"}) ||
		!store.SetNodeStatusIdentity("node-b", "resolver", models.NodeStatus{SourceAddress: "100.64.0.2"}) {
		t.Fatal("initial identities were rejected")
	}
	nodes := store.GetNodeStatuses()
	if len(nodes) != 2 || !nodes[0].DuplicateNameWarning || !nodes[1].DuplicateNameWarning {
		t.Fatalf("duplicate-name statuses = %+v", nodes)
	}
	decommissioned, err := store.DecommissionNode("node-a")
	if err != nil || !decommissioned || !store.IsNodeTombstoned("node-a") {
		t.Fatal("node-a was not tombstoned")
	}
	if store.SetNodeStatusIdentity("node-a", "resolver", models.NodeStatus{}) {
		t.Fatal("tombstoned identity silently rejoined")
	}
	restored, err := store.RestoreNode("node-a")
	if err != nil || !restored || !store.SetNodeStatusIdentity("node-a", "resolver", models.NodeStatus{}) {
		t.Fatal("restored identity could not rejoin")
	}
}

func TestDecommissionRequiresStableIDAndPersistsBeforeMutation(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()
	store.SetNodeStatusIdentity("stable-a", "shared-name", models.NodeStatus{})
	store.SetNodeStatusIdentity("stable-b", "shared-name", models.NodeStatus{})
	store.SetUpstreamHealth("stable-a", map[string]float64{"1.1.1.1": 5})

	if removed, err := store.DecommissionNode("shared-name"); err != nil || removed {
		t.Fatalf("name-addressed decommission = %v, %v", removed, err)
	}
	removed, err := store.DecommissionNode("stable-a")
	if err != nil || !removed {
		t.Fatalf("stable-id decommission = %v, %v", removed, err)
	}
	if store.GetNodeStatusByID("stable-a") != nil || store.GetNodeStatusByID("stable-b") == nil {
		t.Fatal("decommission removed the wrong identity")
	}
	if _, exists := store.GetUpstreamHealth()["stable-a"]; exists {
		t.Fatal("decommission retained stable-id health")
	}
	var tombstones int
	if err := store.db.QueryRow("SELECT COUNT(*) FROM node_tombstones WHERE node_id = ?", "stable-a").Scan(&tombstones); err != nil || tombstones != 1 {
		t.Fatalf("persisted tombstones = %d, err = %v", tombstones, err)
	}
}

func TestDecommissionDatabaseFailureLeavesNodePublished(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()
	store.SetNodeStatusIdentity("stable-a", "resolver", models.NodeStatus{})
	if _, err := store.db.Exec("DROP TABLE node_tombstones"); err != nil {
		t.Fatal(err)
	}
	removed, err := store.DecommissionNode("stable-a")
	if err == nil || removed {
		t.Fatalf("decommission after persistence failure = %v, %v", removed, err)
	}
	if store.GetNodeStatusByID("stable-a") == nil || store.IsNodeTombstoned("stable-a") {
		t.Fatal("failed persistence mutated published node state")
	}
}

func TestRestoreDatabaseFailureLeavesTombstonePublished(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()
	store.SetNodeStatusIdentity("stable-a", "resolver", models.NodeStatus{})
	removed, err := store.DecommissionNode("stable-a")
	if err != nil || !removed {
		t.Fatalf("decommission = %v, %v", removed, err)
	}
	if _, err := store.db.Exec("DROP TABLE node_tombstones"); err != nil {
		t.Fatal(err)
	}
	restored, err := store.RestoreNode("stable-a")
	if err == nil || restored {
		t.Fatalf("restore after persistence failure = %v, %v", restored, err)
	}
	if !store.IsNodeTombstoned("stable-a") {
		t.Fatal("failed restoration removed published tombstone")
	}
}

package storage

import (
	"testing"
	"time"

	"github.com/arumes31/resolix/webgui/internal/models"
)

func TestStoreAccessorsAndCursorEvents(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()
	if store.DB() == nil {
		t.Fatal("DB() returned nil after initialization")
	}
	if store.GetConfig() != store.cfg {
		t.Fatal("GetConfig() did not return the store configuration")
	}

	base := time.Now().Unix() - 10
	for index, domain := range []string{"first.test", "second.test", "third.test"} {
		store.AddEvent(models.QueryEvent{UnixTime: base + int64(index), Domain: domain, Type: "A"})
	}
	all := store.GetEventsAfter("", base-1, 10)
	if len(all) != 3 || all[0].Domain != "first.test" || all[2].Domain != "third.test" {
		t.Fatalf("GetEventsAfter(since) = %#v", all)
	}
	afterCursor := store.GetEventsAfter(all[0].ID, 0, 1)
	if len(afterCursor) != 1 || afterCursor[0].Domain != "second.test" {
		t.Fatalf("GetEventsAfter(cursor) = %#v", afterCursor)
	}
	defaultLimit := store.GetEventsAfter("invalid", base-1, 0)
	if len(defaultLimit) != 3 {
		t.Fatalf("GetEventsAfter(default limit) returned %d events", len(defaultLimit))
	}
}

func TestLegacyNodeStatusAndDefensiveCopies(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()
	status := models.NodeStatus{
		UpstreamHealth:          map[string]float64{"192.0.2.53": 12.5},
		ForwarderEndpointErrors: map[string]string{"heartbeat": "timeout"},
	}
	store.SetNodeStatus("resolver-a", status)
	got := store.GetNodeStatus("resolver-a")
	if got == nil || got.ID != "resolver-a" || got.Name != "resolver-a" {
		t.Fatalf("GetNodeStatus() = %+v", got)
	}
	got.UpstreamHealth["192.0.2.53"] = 99
	got.ForwarderEndpointErrors["heartbeat"] = "changed"
	second := store.GetNodeStatus("resolver-a")
	if second.UpstreamHealth["192.0.2.53"] != 12.5 || second.ForwarderEndpointErrors["heartbeat"] != "timeout" {
		t.Fatal("GetNodeStatus returned mutable internal maps")
	}
	if store.GetNodeStatus("missing") != nil {
		t.Fatal("missing node unexpectedly returned a status")
	}
	if cloneFloatMap(nil) != nil || cloneStringMap(nil) != nil {
		t.Fatal("nil maps were not preserved while cloning")
	}
}

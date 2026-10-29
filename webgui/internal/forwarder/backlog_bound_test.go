package forwarder

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/arumes31/resolix/webgui/internal/models"
)

func boundedTestItems(n int) []backlogItem {
	items := make([]backlogItem, n)
	queuedAt := time.Unix(1700000000, 0).UTC()
	for i := range items {
		ev := models.QueryEvent{Domain: fmt.Sprintf("item-%03d.example", i), Node: "agent"}
		items[i] = backlogItem{event: ev, size: backlogItemSize(ev), queuedAt: queuedAt, seq: uint64(i + 1)}
	}
	return items
}

func TestEncodeBoundedBacklogMatchesJSONEncoding(t *testing.T) {
	items := boundedTestItems(5)
	data, trimmed, err := encodeBoundedBacklog(items, 2, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if trimmed != nil {
		t.Fatalf("unexpected trim %v", trimmed)
	}
	persisted := make([]persistedBacklogItem, len(items))
	for i, item := range items {
		persisted[i] = persistedBacklogItem{Event: item.event, QueuedAt: item.queuedAt}
	}
	want, err := json.Marshal(persistedBacklog{Version: backlogStateVersion, Items: persisted})
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != string(want) {
		t.Fatalf("encoded state differs:\n got %s\nwant %s", data, want)
	}
}

func TestEncodeBoundedBacklogTrimsOldestQueuedAndKeepsInFlight(t *testing.T) {
	items := boundedTestItems(50)
	full, _, err := encodeBoundedBacklog(items, 3, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	limit := int64(len(full) / 3)
	data, trimmed, err := encodeBoundedBacklog(items, 3, limit)
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(data)) > limit {
		t.Fatalf("encoded %d bytes, limit %d", len(data), limit)
	}
	restored, err := decodePersistedBacklog(data)
	if err != nil {
		t.Fatalf("decode bounded state: %v", err)
	}
	if len(restored)+len(trimmed) != len(items) {
		t.Fatalf("restored %d + trimmed %d != %d", len(restored), len(trimmed), len(items))
	}
	for i := 0; i < 3; i++ {
		if restored[i].Event.Domain != items[i].event.Domain {
			t.Fatalf("in-flight item %d not kept first: %s", i, restored[i].Event.Domain)
		}
	}
	if restored[len(restored)-1].Event.Domain != items[len(items)-1].event.Domain {
		t.Fatal("newest queued item was trimmed")
	}
	for seq := uint64(4); seq < uint64(4+len(trimmed)); seq++ {
		if _, ok := trimmed[seq]; !ok {
			t.Fatalf("expected oldest queued seq %d to be trimmed", seq)
		}
	}
	if _, _, err := encodeBoundedBacklog(items, len(items), limit); err == nil {
		t.Fatal("expected error when in-flight items alone exceed the limit")
	}
}

func TestDropPersistTrimmedSkipsItemsAlreadyInFlight(t *testing.T) {
	f := &Forwarder{}
	items := boundedTestItems(4)
	// Item 1 moved to in-flight after the snapshot was taken.
	f.inFlight = items[:1]
	f.backlog = append([]backlogItem(nil), items[1:]...)
	for _, item := range f.backlog {
		f.backlogTotalSize += item.size
	}
	f.dropPersistTrimmed(map[uint64]struct{}{1: {}, 2: {}}, 100)
	if len(f.backlog) != 2 || f.backlog[0].seq != 3 {
		t.Fatalf("backlog after trim = %+v", f.backlog)
	}
	if got := f.dropped.Load(); got != 1 {
		t.Fatalf("dropped = %d, want 1", got)
	}
	if f.backlogTotalSize != items[2].size+items[3].size {
		t.Fatalf("backlog size accounting = %d", f.backlogTotalSize)
	}
}

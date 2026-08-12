package forwarder

import (
	"net/http"
	"testing"
	"time"

	"github.com/arumes31/resolix/webgui/internal/config"
	"github.com/arumes31/resolix/webgui/internal/configsync"
	"github.com/arumes31/resolix/webgui/internal/magicdns"
	"github.com/arumes31/resolix/webgui/internal/models"
)

func TestForwarderCallbacksAndSynchronizedSnapshots(t *testing.T) {
	forwarder := NewForwarder(&config.Config{Mode: config.ModeController, HistoryDir: t.TempDir(), NodeID: "node-1"})
	t.Cleanup(forwarder.Stop)
	forwarder.SetDNSRoutesFn(func(map[string]string) {})
	forwarder.SetAliasesFn(func(map[string]string) {})
	forwarder.SetUpstreamHealthFn(func(string, map[string]float64) {})
	forwarder.SetDNSConfigFn(func(configsync.Snapshot) error { return nil })
	forwarder.SetMagicDNSFn(func(magicdns.Snapshot) error { return nil })
	if forwarder.setDNSRoutesFn == nil || forwarder.setAliasesFn == nil ||
		forwarder.setUpstreamHealthFn == nil || forwarder.setDNSConfigFn == nil ||
		forwarder.setMagicDNSFn == nil {
		t.Fatal("one or more synchronization callbacks were not retained")
	}

	forwarder.syncedAliases = map[string]string{"192.0.2.1": "router"}
	forwarder.syncedRoutes = map[string]string{"example.test": "192.0.2.53"}
	forwarder.syncedHealth = map[string]map[string]float64{"node": {"192.0.2.53": 12.5}}
	aliases := forwarder.GetSyncedAliases()
	routes := forwarder.GetSyncedRoutes()
	health := forwarder.GetSyncedUpstreamHealth()
	aliases["192.0.2.1"] = "changed"
	routes["example.test"] = "changed"
	health["node"]["192.0.2.53"] = 99
	if forwarder.syncedAliases["192.0.2.1"] != "router" ||
		forwarder.syncedRoutes["example.test"] != "192.0.2.53" ||
		forwarder.syncedHealth["node"]["192.0.2.53"] != 12.5 {
		t.Fatal("synchronized state getters returned mutable internal maps")
	}
}

func TestForwarderSyncNowTransportBoundaries(t *testing.T) {
	tests := []struct {
		name       string
		cfg        *config.Config
		wantQueued bool
	}{
		{name: "controller disabled", cfg: &config.Config{Mode: config.ModeController, HistoryDir: t.TempDir(), NodeID: "controller"}},
		{name: "agent requires HTTPS", cfg: &config.Config{Mode: config.ModeAgent, ControllerURL: "http://100.64.0.1", HistoryDir: t.TempDir(), NodeID: "agent-http"}},
		{name: "HTTPS agent", cfg: &config.Config{Mode: config.ModeAgent, ControllerURL: "https://100.64.0.1", HistoryDir: t.TempDir(), NodeID: "agent-https"}, wantQueued: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			forwarder := NewForwarder(test.cfg)
			t.Cleanup(forwarder.Stop)
			if got := forwarder.SyncNow(); got != test.wantQueued {
				t.Fatalf("SyncNow() = %v, want %v", got, test.wantQueued)
			}
			if test.wantQueued && !forwarder.SyncNow() {
				t.Fatal("coalesced SyncNow request was rejected")
			}
		})
	}
}

func TestForwarderPreviousSnapshotIsDefensivelyCopied(t *testing.T) {
	forwarder := NewForwarder(&config.Config{HistoryDir: t.TempDir(), NodeID: "node"})
	t.Cleanup(forwarder.Stop)
	if _, ok := forwarder.PreviousConfigSnapshot(); ok {
		t.Fatal("empty forwarder unexpectedly has a previous snapshot")
	}
	snapshot, err := configsync.NewSnapshot([]string{"1.1.1.1"}, nil, map[string]string{"example.test": "9.9.9.9"}, nil, "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	forwarder.previousSnapshot = &snapshot
	got, ok := forwarder.PreviousConfigSnapshot()
	if !ok || got.Revision != snapshot.Revision {
		t.Fatalf("PreviousConfigSnapshot() = %+v, %v", got, ok)
	}
	got.Routes["example.test"] = "changed"
	second, _ := forwarder.PreviousConfigSnapshot()
	if second.Routes["example.test"] != "9.9.9.9" {
		t.Fatal("PreviousConfigSnapshot returned mutable internal data")
	}
}

func TestForwarderStatusAndCounters(t *testing.T) {
	forwarder := NewForwarder(&config.Config{HistoryDir: t.TempDir(), NodeID: "node"})
	t.Cleanup(forwarder.Stop)
	now := time.Now()
	forwarder.backlog = []backlogItem{{event: models.QueryEvent{Domain: "queued.test"}, size: 25, queuedAt: now.Add(-2 * time.Second)}}
	forwarder.inFlight = []backlogItem{{event: models.QueryEvent{Domain: "sending.test"}, size: 15, queuedAt: now.Add(-time.Second)}}
	forwarder.backlogTotalSize = 40
	forwarder.retries.Store(2)
	forwarder.dropped.Store(3)
	forwarder.sent.Store(4)
	forwarder.desiredRevision = "desired"
	forwarder.configRevision = "applied"
	forwarder.previousSnapshot = &configsync.Snapshot{Revision: "previous"}
	forwarder.endpointStatus["heartbeat"] = EndpointStatus{LastError: "failure"}

	status := forwarder.SnapshotStatus(now)
	if status.BacklogDepth != 2 || status.BacklogBytes != 40 || status.BacklogOldestAge < time.Second ||
		status.Retries != 2 || status.Dropped != 3 || status.Sent != 4 ||
		status.DesiredRevision != "desired" || status.AppliedRevision != "applied" || status.PreviousRevision != "previous" {
		t.Fatalf("SnapshotStatus() = %+v", status)
	}
	status.Endpoints["heartbeat"] = EndpointStatus{}
	if forwarder.endpointStatus["heartbeat"].LastError != "failure" {
		t.Fatal("SnapshotStatus returned mutable endpoint state")
	}
	depth, bytes, retries, dropped, sent := forwarder.Stats()
	if depth != 2 || bytes != 40 || retries != 2 || dropped != 3 || sent != 4 {
		t.Fatalf("Stats() = %d, %d, %d, %d, %d", depth, bytes, retries, dropped, sent)
	}
}

func TestRecordControllerDate(t *testing.T) {
	forwarder := NewForwarder(&config.Config{HistoryDir: t.TempDir(), NodeID: "node"})
	t.Cleanup(forwarder.Stop)
	forwarder.recordControllerDate(http.Header{}, time.Now())
	if got := forwarder.clockSkewNanos.Load(); got != 0 {
		t.Fatalf("invalid Date changed clock skew to %d", got)
	}
	serverTime := time.Now().UTC().Truncate(time.Second)
	receivedAt := serverTime.Add(1500 * time.Millisecond)
	header := http.Header{"Date": []string{serverTime.Format(http.TimeFormat)}}
	forwarder.recordControllerDate(header, receivedAt)
	if got := time.Duration(forwarder.clockSkewNanos.Load()); got != 1500*time.Millisecond {
		t.Fatalf("clock skew = %s", got)
	}
}

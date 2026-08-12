package configsync

import (
	"errors"
	"testing"

	"github.com/arumes31/resolix/webgui/internal/dnssettings"
	"github.com/arumes31/resolix/webgui/internal/filter"
	"github.com/arumes31/resolix/webgui/internal/rewrites"
)

func TestSnapshotCloneDiffAndCompatibility(t *testing.T) {
	before, err := NewSnapshot(
		[]string{"1.1.1.1"}, nil, map[string]string{"internal.example": "9.9.9.9"},
		nil, "||old.example^\n", nil, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	after := before.Clone()
	after.Upstreams[0] = "8.8.8.8"
	after.Routes["internal.example"] = "8.8.4.4"
	after.UserRules = "||new.example^\n"
	diffs := Diff(before, after)
	if len(diffs) != 3 || diffs[0].Field != "upstreams" ||
		diffs[1].Field != "routes" || diffs[2].Field != "user_rules" {
		t.Fatalf("diffs = %+v", diffs)
	}
	if before.Upstreams[0] != "1.1.1.1" || before.Routes["internal.example"] != "9.9.9.9" {
		t.Fatal("Clone allowed mutation of the retained snapshot")
	}
	if diffs[2].Before == before.UserRules || diffs[2].After == after.UserRules {
		t.Fatal("user-rule diff exposed raw rule content")
	}

	incompatible := before.Clone()
	incompatible.Version++
	if incompatible.SchemaCompatible() || !errors.Is(incompatible.Validate(), ErrIncompatibleVersion) {
		t.Fatalf("incompatible snapshot validation = %v", incompatible.Validate())
	}
}

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
	snapshot, err = NewSnapshot(
		[]string{"1.1.1.1"},
		[]string{"9.9.9.9"},
		nil,
		[]filter.Subscription{{
			ID: "trusted", URL: "https://allow.example/list.txt", AllowOnly: true, Enabled: true,
		}},
		"",
		nil,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Subscriptions[0].AllowOnly = false
	valid, err = snapshot.ValidRevision()
	if err != nil {
		t.Fatal(err)
	}
	if valid {
		t.Fatal("allowlist type mutation did not invalidate revision")
	}
	snapshot, err = NewSnapshot(
		[]string{"1.1.1.1"},
		[]string{"9.9.9.9"},
		nil,
		[]filter.Subscription{{
			ID: "block", URL: "https://block.example/list.txt", Enabled: true,
		}},
		"",
		nil,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Subscriptions[0].RefreshGeneration = "next"
	valid, err = snapshot.ValidRevision()
	if err != nil {
		t.Fatal(err)
	}
	if valid {
		t.Fatal("refresh generation mutation did not invalidate revision")
	}
}

func TestSnapshotRevisionIncludesDNSSettings(t *testing.T) {
	t.Parallel()
	settings := dnssettings.Settings{
		UpstreamMode: "load_balance", BlockingMode: "nxdomain", BlockCustomIPv4: "0.0.0.0",
		BlockCustomIPv6: "::", RefuseANY: true, PrivatePTR: true,
	}.Normalize()
	snapshot, err := NewSnapshotWithDNSSettings(
		[]string{"1.1.1.1"}, nil, nil, nil, "", nil, nil, &settings,
	)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.DNSSettings.DNSSEC = true
	valid, err := snapshot.ValidRevision()
	if err != nil {
		t.Fatal(err)
	}
	if valid {
		t.Fatal("DNS settings mutation did not invalidate snapshot revision")
	}
}

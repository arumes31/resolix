package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/arumes31/resolix/webgui/internal/config"
	"github.com/arumes31/resolix/webgui/internal/magicdns"
)

type magicDNSLister struct {
	devices []magicdns.Device
}

func (l *magicDNSLister) ListDevices(context.Context) ([]magicdns.Device, error) {
	return l.devices, nil
}

func TestMagicDNSStatusAndSyncEndpoints(t *testing.T) {
	cfg := &config.Config{
		Mode:                 config.ModeController,
		MagicDNSEnabled:      true,
		MagicDNSTailnet:      "tailnet-id",
		MagicDNSClientID:     "configured",
		MagicDNSClientSecret: "hidden",
		MagicDNSSyncInterval: 4 * time.Hour,
		MagicDNSTTL:          60,
	}
	server := testServer(cfg)
	store := magicdns.NewStore("")
	syncer, err := magicdns.NewSyncer(&magicDNSLister{devices: []magicdns.Device{{
		NodeID: "node-1", Name: "host.tailnet.ts.net", Addresses: []string{"100.64.0.10"}, Authorized: true,
	}}}, store, cfg.MagicDNSTailnet, cfg.MagicDNSSyncInterval)
	if err != nil {
		t.Fatalf("NewSyncer: %v", err)
	}
	server.SetMagicDNS(store, syncer)

	syncResponse := httptest.NewRecorder()
	server.handleMagicDNSSync(syncResponse, httptest.NewRequest(http.MethodPost, "/api/magicdns/sync", nil))
	if syncResponse.Code != http.StatusOK {
		t.Fatalf("sync status = %d body=%q", syncResponse.Code, syncResponse.Body.String())
	}
	var status map[string]interface{}
	if err := json.Unmarshal(syncResponse.Body.Bytes(), &status); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	if status["credentials_configured"] != true {
		t.Fatalf("status = %#v", status)
	}
	if _, exposed := status["client_secret"]; exposed {
		t.Fatal("status exposed the OAuth client secret")
	}

	internal := httptest.NewRecorder()
	server.handleSyncMagicDNS(internal, httptest.NewRequest(http.MethodGet, "/api/sync/magicdns", nil))
	if internal.Code != http.StatusOK {
		t.Fatalf("internal sync status = %d", internal.Code)
	}
	var snapshot magicdns.Snapshot
	if err := json.Unmarshal(internal.Body.Bytes(), &snapshot); err != nil {
		t.Fatalf("decode snapshot: %v", err)
	}
	if len(snapshot.Records) != 1 || snapshot.Records[0].Value != "100.64.0.10" {
		t.Fatalf("snapshot = %#v", snapshot)
	}
}

func TestMagicDNSSyncIsControllerOwned(t *testing.T) {
	server := testServer(&config.Config{Mode: config.ModeAgent, MagicDNSEnabled: true})
	response := httptest.NewRecorder()
	server.handleMagicDNSSync(response, httptest.NewRequest(http.MethodPost, "/api/magicdns/sync", nil))
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusForbidden)
	}
}

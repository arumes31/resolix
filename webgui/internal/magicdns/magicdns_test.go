package magicdns

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestClient_ListDevices(t *testing.T) {
	var tokenRequests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v2/oauth/token":
			tokenRequests.Add(1)
			if err := r.ParseForm(); err != nil {
				t.Errorf("parse token form: %v", err)
				http.Error(w, "invalid token request", http.StatusBadRequest)
				return
			}
			if r.Form.Get("client_id") != "client" || r.Form.Get("client_secret") != "secret" {
				t.Errorf("OAuth credentials were not submitted")
				http.Error(w, "invalid OAuth credentials", http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "access",
				"token_type":   "Bearer",
				"expires_in":   3600,
			})
		case "/api/v2/tailnet/tailnet-id/devices":
			if r.Header.Get("Authorization") != "Bearer access" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"devices": []Device{{NodeID: "node-1", Name: "host.example.ts.net", Authorized: true}},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := newClient("client", "secret", "tailnet-id", server.URL, server.Client())
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}
	for range 2 {
		devices, err := client.ListDevices(t.Context())
		if err != nil {
			t.Fatalf("ListDevices: %v", err)
		}
		if len(devices) != 1 || devices[0].NodeID != "node-1" {
			t.Fatalf("devices = %#v", devices)
		}
	}
	if tokenRequests.Load() != 1 {
		t.Fatalf("token requests = %d, want 1", tokenRequests.Load())
	}
}

func TestClient_RejectsRedirects(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Errorf("redirect target received credentials")
		http.Error(w, "unexpected redirect", http.StatusInternalServerError)
	}))
	defer target.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer server.Close()

	client, err := newClient("client", "secret", "tailnet", server.URL, server.Client())
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}
	_, err = client.ListDevices(t.Context())
	if err == nil {
		t.Fatal("ListDevices unexpectedly followed a redirect")
	}
}

func TestClient_RepeatedUnauthorizedFails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v2/oauth/token" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "access",
				"expires_in":   3600,
			})
			return
		}
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer server.Close()
	client, err := newClient("client", "secret", "tailnet", server.URL, server.Client())
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}
	if _, err := client.ListDevices(t.Context()); err == nil {
		t.Fatal("ListDevices accepted a second unauthorized response")
	}
}

func TestRecordsFromDevices(t *testing.T) {
	now := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
	devices := []Device{
		{
			NodeID:     "node-1",
			Name:       "Alpha.Tailnet.ts.net.",
			Addresses:  []string{"100.64.0.10", "fd7a:115c:a1e0::10", "192.0.2.1"},
			Authorized: true,
		},
		{NodeID: "node-2", Name: "unauthorized.ts.net", Addresses: []string{"100.64.0.11"}},
		{
			NodeID:     "node-3",
			Name:       "expired.ts.net",
			Addresses:  []string{"100.64.0.12"},
			Authorized: true,
			Expires:    now.Add(-time.Minute).Format(time.RFC3339),
		},
	}
	records, devicesIncluded := RecordsFromDevices(devices, now)
	if devicesIncluded != 1 || len(records) != 2 {
		t.Fatalf("included devices/records = %d/%d, want 1/2", devicesIncluded, len(records))
	}
	if records[0].Name != "alpha.tailnet.ts.net" || records[0].Type != "A" || records[1].Type != "AAAA" {
		t.Fatalf("records = %#v", records)
	}
}

func TestStore_PersistsAndValidatesSnapshots(t *testing.T) {
	path := filepath.Join(t.TempDir(), "magicdns.json")
	store := NewStore(path)
	var changes atomic.Int32
	store.SetOnChange(func() { changes.Add(1) })
	records := []Record{{NodeID: "node-1", Name: "host.ts.net", Type: "A", Value: "100.64.0.10"}}
	if err := store.Replace("tailnet", records, time.Now()); err != nil {
		t.Fatalf("Replace: %v", err)
	}
	if err := store.Replace("tailnet", records, time.Now()); err != nil {
		t.Fatalf("Replace unchanged: %v", err)
	}
	if changes.Load() != 1 {
		t.Fatalf("change callbacks = %d, want 1", changes.Load())
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	lookup := loaded.Lookup("HOST.TS.NET.", "A")
	if len(lookup) != 1 || lookup[0].Value != "100.64.0.10" {
		t.Fatalf("lookup = %#v", lookup)
	}
	bad := loaded.Snapshot()
	bad.Generation = "tampered"
	if err := loaded.Apply(bad); err == nil {
		t.Fatal("Apply accepted a mismatched generation")
	}
	bad = loaded.Snapshot()
	bad.Generation = ""
	bad.Records[0].Value = "not-an-address"
	if err := loaded.Apply(bad); err == nil {
		t.Fatal("Apply accepted an invalid address")
	}
}

type scriptedLister struct {
	devices []Device
	err     error
}

func (l *scriptedLister) ListDevices(context.Context) ([]Device, error) {
	return l.devices, l.err
}

func TestSyncer_FailurePreservesLastGoodSnapshot(t *testing.T) {
	store := NewStore("")
	lister := &scriptedLister{devices: []Device{{
		NodeID: "node-1", Name: "host.ts.net", Addresses: []string{"100.64.0.10"}, Authorized: true,
	}}}
	syncer, err := NewSyncer(lister, store, "tailnet", 4*time.Hour)
	if err != nil {
		t.Fatalf("NewSyncer: %v", err)
	}
	if err := syncer.Sync(t.Context()); err != nil {
		t.Fatalf("first Sync: %v", err)
	}
	before := store.Snapshot()
	lister.err = errors.New("temporary outage")
	if err := syncer.Sync(t.Context()); err == nil {
		t.Fatal("second Sync unexpectedly succeeded")
	}
	after := store.Snapshot()
	if before.Generation != after.Generation || len(after.Records) != 1 {
		t.Fatalf("snapshot changed after failure: before=%#v after=%#v", before, after)
	}
	if syncer.Status().LastError == "" {
		t.Fatal("sync error was not recorded")
	}
}

func TestNewClient_RequiresCredentials(t *testing.T) {
	tests := []struct {
		name     string
		clientID string
		secret   string
		tailnet  string
	}{
		{name: "missing client id", secret: "secret", tailnet: "tailnet"},
		{name: "missing secret", clientID: "client", tailnet: "tailnet"},
		{name: "missing tailnet", clientID: "client", secret: "secret"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewClient(test.clientID, test.secret, test.tailnet)
			if err == nil {
				t.Fatal("NewClient unexpectedly succeeded")
			}
		})
	}
}

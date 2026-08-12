//go:build integration

package magicdns

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestClient_LiveDeviceInventory(t *testing.T) {
	clientID := os.Getenv("MAGICDNS_CLIENT_ID")
	clientSecret := os.Getenv("MAGICDNS_CLIENT_SECRET")
	tailnet := os.Getenv("MAGICDNS_TAILNET")
	if clientID == "" || clientSecret == "" || tailnet == "" {
		t.Skip("live MagicDNS credentials are not configured")
	}
	client, err := NewClient(clientID, clientSecret, tailnet)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	devices, err := client.ListDevices(ctx)
	if err != nil {
		t.Fatalf("ListDevices: %v", err)
	}
	if len(devices) == 0 {
		t.Fatal("Tailscale returned an empty device inventory")
	}
	records, includedDevices := RecordsFromDevices(devices, time.Now())
	if len(records) == 0 {
		t.Fatal("Tailscale inventory produced no authorized MagicDNS records")
	}
	t.Logf("validated %d API devices, %d eligible devices, and %d address records", len(devices), includedDevices, len(records))
}

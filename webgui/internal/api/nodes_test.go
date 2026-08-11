package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/arumes31/resolix/webgui/internal/config"
	"github.com/arumes31/resolix/webgui/internal/models"
)

func TestDecommissionNodeRequiresStableIdentity(t *testing.T) {
	server, cleanup := newHistoryTestServer(t)
	defer cleanup()
	server.cfg.Mode = config.ModeController
	server.store.SetNodeStatusIdentity("stable-a", "shared-name", models.NodeStatus{})
	status := server.store.GetNodeStatusByID("stable-a")
	status.LastSeen = time.Now().Add(-2 * server.cfg.NodeOfflineThreshold)
	server.store.SetNodeStatusIdentity("stable-a", "shared-name", *status)
	server.cfg.NodeOfflineThreshold = -time.Second

	request := httptest.NewRequest(http.MethodDelete, "/api/nodes?name=shared-name", nil)
	recorder := httptest.NewRecorder()
	server.handleNodes(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("name-addressed status = %d", recorder.Code)
	}

	request = httptest.NewRequest(http.MethodDelete, "/api/nodes?id=stable-a", nil)
	recorder = httptest.NewRecorder()
	server.handleNodes(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("stable-id status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if server.store.GetNodeStatusByID("stable-a") != nil || !server.store.IsNodeTombstoned("stable-a") {
		t.Fatal("stable identity was not decommissioned")
	}
}

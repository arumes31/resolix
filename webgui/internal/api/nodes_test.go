package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
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
	if status == nil {
		t.Fatal("seeded node status was not found")
	}
	status.LastSeen = time.Now().Add(-time.Hour)
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

func TestNodeIdentityLengthBoundIsConsistent(t *testing.T) {
	valid := strings.Repeat("a", maxNodeIdentityLength)
	invalid := valid + "a"
	if got := normalizeNodeIdentity("", valid); got != valid {
		t.Fatalf("maximum-length fallback identity = %q", got)
	}
	if got := normalizeNodeIdentity("", invalid); got != "" {
		t.Fatalf("overlong fallback identity = %q, want rejected", got)
	}

	server, cleanup := newHistoryTestServer(t)
	defer cleanup()
	server.cfg.Mode = config.ModeController
	for _, test := range []struct {
		method string
		path   string
	}{
		{method: http.MethodDelete, path: "/api/nodes?id=" + invalid},
		{method: http.MethodPost, path: "/api/nodes?action=restore&id=" + invalid},
	} {
		recorder := httptest.NewRecorder()
		server.handleNodes(recorder, httptest.NewRequest(test.method, test.path, nil))
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("%s overlong identity status = %d", test.method, recorder.Code)
		}
	}
}

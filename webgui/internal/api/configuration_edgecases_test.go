package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/arumes31/resolix/webgui/internal/config"
	"github.com/arumes31/resolix/webgui/internal/configsync"
	"github.com/arumes31/resolix/webgui/internal/filter"
	"github.com/arumes31/resolix/webgui/internal/models"
)

func newConfigurationCoverageServer(t *testing.T) *Server {
	t.Helper()
	server := newAPIStateTestServer(t)
	server.cfg.UpstreamDNS = "1.1.1.1"
	server.cfg.UpstreamsFile = "upstreams.json"
	server.cfg.DNSRoutesFile = "dnsroutes.json"
	server.nodeSyncGenerations = make(map[string]uint64)

	engine := filter.New()
	engine.AddFileSource(server.cfg.FullUserRulesPath(), false)
	server.SetFilter(engine)
	store, err := filter.LoadSubscriptionStore(server.cfg.FullFilterSubscriptionsPath(), []filter.Subscription{{
		ID: "primary", Name: "Primary", URL: "https://filters.example/list.txt", Enabled: true,
	}})
	if err != nil {
		t.Fatal(err)
	}
	server.SetSubscriptionStore(store)
	return server
}

func TestConfigurationStatusSnapshotDiffAndSyncScheduling(t *testing.T) {
	server := newConfigurationCoverageServer(t)

	statusRecorder := httptest.NewRecorder()
	server.handleConfigStatus(statusRecorder, httptest.NewRequest(http.MethodGet, "/api/config/status", nil))
	if statusRecorder.Code != http.StatusOK || !strings.Contains(statusRecorder.Body.String(), `"editable":true`) {
		t.Fatalf("config status = %d %q", statusRecorder.Code, statusRecorder.Body.String())
	}

	snapshotRecorder := httptest.NewRecorder()
	server.handleConfigSnapshot(snapshotRecorder, httptest.NewRequest(http.MethodGet, "/api/config/snapshot", nil))
	if snapshotRecorder.Code != http.StatusOK || !strings.Contains(snapshotRecorder.Body.String(), `"revision":`) {
		t.Fatalf("config snapshot = %d %q", snapshotRecorder.Code, snapshotRecorder.Body.String())
	}
	var current configsync.Snapshot
	if err := json.Unmarshal(snapshotRecorder.Body.Bytes(), &current); err != nil {
		t.Fatal(err)
	}
	if err := server.savePreviousConfigSnapshot(current); err != nil {
		t.Fatal(err)
	}
	loaded, err := server.loadPreviousConfigSnapshot()
	if err != nil || loaded.Revision != current.Revision {
		t.Fatalf("loaded previous snapshot=%+v err=%v", loaded, err)
	}

	candidate, err := configsync.NewSnapshotWithDNSSettings(
		[]string{"9.9.9.9"}, current.BootstrapServers, current.Routes, current.Subscriptions,
		current.UserRules, current.Rewrites, current.Clients, current.DNSSettings,
	)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(candidate)
	if err != nil {
		t.Fatal(err)
	}
	diffRecorder := httptest.NewRecorder()
	server.handleConfigDiff(diffRecorder, httptest.NewRequest(http.MethodPost, "/api/config/diff", bytes.NewReader(body)))
	if diffRecorder.Code != http.StatusOK || !strings.Contains(diffRecorder.Body.String(), `"changed":true`) {
		t.Fatalf("config diff = %d %q", diffRecorder.Code, diffRecorder.Body.String())
	}

	syncAll := httptest.NewRecorder()
	server.handleConfigSyncNow(syncAll, httptest.NewRequest(http.MethodPost, "/api/config/sync", nil))
	if syncAll.Code != http.StatusAccepted || server.syncGenerationFor("agent") != "1:0" {
		t.Fatalf("sync all = %d %q generation=%q", syncAll.Code, syncAll.Body.String(), server.syncGenerationFor("agent"))
	}
	server.store.SetNodeStatusIdentity("stable-agent", "agent", models.NodeStatus{})
	syncNode := httptest.NewRecorder()
	server.handleConfigSyncNow(syncNode, httptest.NewRequest(http.MethodPost, "/api/config/sync?node=agent", nil))
	if syncNode.Code != http.StatusAccepted || server.syncGenerationFor("stable-agent") != "1:1" {
		t.Fatalf("sync node = %d %q generation=%q", syncNode.Code, syncNode.Body.String(), server.syncGenerationFor("stable-agent"))
	}
}

func TestFilterSubscriptionManagementEndpoints(t *testing.T) {
	server := newConfigurationCoverageServer(t)

	get := httptest.NewRecorder()
	server.handleFilterSubscriptions(get, httptest.NewRequest(http.MethodGet, "/api/filter-subscriptions", nil))
	if get.Code != http.StatusOK || !strings.Contains(get.Body.String(), "primary") {
		t.Fatalf("subscriptions GET = %d %q", get.Code, get.Body.String())
	}

	putBody := `{"subscriptions":[{"id":"primary","name":"Primary updated","url":"https://filters.example/list.txt","enabled":true},{"id":"allow","name":"Allow","url":"https://filters.example/allow.txt","enabled":true,"allow_only":true}]}`
	put := httptest.NewRecorder()
	server.handleFilterSubscriptions(put, httptest.NewRequest(http.MethodPut, "/api/filter-subscriptions", strings.NewReader(putBody)))
	if put.Code != http.StatusOK || !strings.Contains(put.Body.String(), "Primary updated") {
		t.Fatalf("subscriptions PUT = %d %q", put.Code, put.Body.String())
	}

	exported := httptest.NewRecorder()
	server.handleFilterSubscriptionsExport(exported, httptest.NewRequest(http.MethodGet, "/api/filter-subscriptions/export", nil))
	if exported.Code != http.StatusOK || !strings.Contains(exported.Header().Get("Content-Disposition"), "resolix-subscriptions") {
		t.Fatalf("subscriptions export = %d headers=%v body=%q", exported.Code, exported.Header(), exported.Body.String())
	}

	document := filter.NewSubscriptionDocument([]filter.Subscription{{
		ID: "imported", Name: "Imported", URL: "https://filters.example/imported.txt", Enabled: true,
	}})
	documentBody, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	imported := httptest.NewRecorder()
	server.handleFilterSubscriptionsImport(imported, httptest.NewRequest(http.MethodPost, "/api/filter-subscriptions/import", bytes.NewReader(documentBody)))
	if imported.Code != http.StatusOK || !strings.Contains(imported.Body.String(), "imported") {
		t.Fatalf("subscriptions import = %d %q", imported.Code, imported.Body.String())
	}

	for _, action := range []string{"disable", "enable", "refresh"} {
		recorder := httptest.NewRecorder()
		body := `{"action":"` + action + `","ids":["imported"]}`
		server.handleFilterSubscriptionsBulk(recorder, httptest.NewRequest(http.MethodPost, "/api/filter-subscriptions/bulk", strings.NewReader(body)))
		if recorder.Code != http.StatusOK {
			t.Fatalf("bulk %s = %d %q", action, recorder.Code, recorder.Body.String())
		}
	}

	refresh := httptest.NewRecorder()
	server.handleFilteringUpdate(refresh, httptest.NewRequest(http.MethodPost, "/api/filtering/update?id=imported", nil))
	if refresh.Code != http.StatusAccepted {
		t.Fatalf("source refresh = %d %q", refresh.Code, refresh.Body.String())
	}
	missing := httptest.NewRecorder()
	server.handleFilteringUpdate(missing, httptest.NewRequest(http.MethodPost, "/api/filtering/update?id=missing", nil))
	if missing.Code != http.StatusNotFound {
		t.Fatalf("missing source refresh = %d %q", missing.Code, missing.Body.String())
	}

	deleted := httptest.NewRecorder()
	server.handleFilterSubscriptionsBulk(deleted, httptest.NewRequest(http.MethodPost, "/api/filter-subscriptions/bulk", strings.NewReader(`{"action":"delete","ids":["imported"]}`)))
	if deleted.Code != http.StatusOK || strings.Contains(deleted.Body.String(), `"id":"imported"`) {
		t.Fatalf("bulk delete = %d %q", deleted.Code, deleted.Body.String())
	}
}

func TestFilterValidationRollbackAndUserRules(t *testing.T) {
	server := newConfigurationCoverageServer(t)

	validate := httptest.NewRecorder()
	server.handleFilteringValidate(validate, httptest.NewRequest(http.MethodPost, "/api/filtering/validate", strings.NewReader(`{"rules":"||blocked.example^\n@@||allowed.example^"}`)))
	if validate.Code != http.StatusOK || !strings.Contains(validate.Body.String(), `"accepted":2`) {
		t.Fatalf("filter validation = %d %q", validate.Code, validate.Body.String())
	}

	put := httptest.NewRecorder()
	server.handleUserRules(put, httptest.NewRequest(http.MethodPut, "/api/user-rules", strings.NewReader(`{"rules":"||blocked.example^"}`)))
	if put.Code != http.StatusOK {
		t.Fatalf("user rules PUT = %d %q", put.Code, put.Body.String())
	}
	data, err := os.ReadFile(server.cfg.FullUserRulesPath())
	if err != nil || string(data) != "||blocked.example^\n" {
		t.Fatalf("persisted user rules=%q err=%v", data, err)
	}
	get := httptest.NewRecorder()
	server.handleUserRules(get, httptest.NewRequest(http.MethodGet, "/api/user-rules", nil))
	if get.Code != http.StatusOK || !strings.Contains(get.Body.String(), "blocked.example") {
		t.Fatalf("user rules GET = %d %q", get.Code, get.Body.String())
	}

	rollback := httptest.NewRecorder()
	server.handleFilteringRollback(rollback, httptest.NewRequest(http.MethodPost, "/api/filtering/rollback", strings.NewReader(`{"id":"missing"}`)))
	if rollback.Code != http.StatusConflict {
		t.Fatalf("rollback missing source = %d %q", rollback.Code, rollback.Body.String())
	}
}

func TestConfigurationEndpointFailurePaths(t *testing.T) {
	server := newConfigurationCoverageServer(t)

	tests := []struct {
		name    string
		handler http.HandlerFunc
		method  string
		body    string
		want    int
	}{
		{name: "status method", handler: server.handleConfigStatus, method: http.MethodPost, want: http.StatusMethodNotAllowed},
		{name: "snapshot method", handler: server.handleConfigSnapshot, method: http.MethodPost, want: http.StatusMethodNotAllowed},
		{name: "diff malformed", handler: server.handleConfigDiff, method: http.MethodPost, body: "{", want: http.StatusBadRequest},
		{name: "sync missing node", handler: server.handleConfigSyncNow, method: http.MethodPost, want: http.StatusAccepted},
		{name: "subscriptions method", handler: server.handleFilterSubscriptions, method: http.MethodDelete, want: http.StatusMethodNotAllowed},
		{name: "export method", handler: server.handleFilterSubscriptionsExport, method: http.MethodPost, want: http.StatusMethodNotAllowed},
		{name: "import malformed", handler: server.handleFilterSubscriptionsImport, method: http.MethodPost, body: "{", want: http.StatusBadRequest},
		{name: "bulk missing ids", handler: server.handleFilterSubscriptionsBulk, method: http.MethodPost, body: `{"action":"enable"}`, want: http.StatusBadRequest},
		{name: "validate method", handler: server.handleFilteringValidate, method: http.MethodGet, want: http.StatusMethodNotAllowed},
		{name: "rollback malformed", handler: server.handleFilteringRollback, method: http.MethodPost, body: "{", want: http.StatusBadRequest},
		{name: "rules method", handler: server.handleUserRules, method: http.MethodDelete, want: http.StatusMethodNotAllowed},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(test.method, "/api/test", strings.NewReader(test.body))
			test.handler(recorder, request)
			if recorder.Code != test.want {
				t.Fatalf("status = %d, want %d; body=%q", recorder.Code, test.want, recorder.Body.String())
			}
		})
	}

	invalidPrevious := filepath.Join(server.cfg.FullConfigDir(), "previous-config-snapshot.json")
	if err := os.WriteFile(invalidPrevious, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := server.loadPreviousConfigSnapshot(); err == nil {
		t.Fatal("invalid previous snapshot unexpectedly loaded")
	}
}

func TestAgentConfigurationSyncGuards(t *testing.T) {
	server := newConfigurationCoverageServer(t)
	server.cfg.Mode = config.ModeAgent
	server.cfg.NodeName = "agent-one"

	tests := []struct {
		name   string
		target string
		want   int
	}{
		{name: "different node", target: "/api/config/sync?node=agent-two", want: http.StatusBadRequest},
		{name: "synchronizer unavailable", target: "/api/config/sync?node=agent-one", want: http.StatusServiceUnavailable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			server.handleConfigSyncNow(recorder, httptest.NewRequest(http.MethodPost, test.target, nil))
			if recorder.Code != test.want {
				t.Fatalf("status = %d, want %d; body=%q", recorder.Code, test.want, recorder.Body.String())
			}
		})
	}
}

func TestConfigurationMutationInputFailures(t *testing.T) {
	server := newConfigurationCoverageServer(t)

	tests := []struct {
		name    string
		handler http.HandlerFunc
		method  string
		body    string
		want    int
	}{
		{name: "upstream settings malformed", handler: server.handleUpstreamSettings, method: http.MethodPost, body: "{", want: http.StatusBadRequest},
		{name: "upstream hostname without bootstrap", handler: server.handleUpstreamSettings, method: http.MethodPost, body: `{"upstreams":["tls://dns.example"]}`, want: http.StatusBadRequest},
		{name: "upstream settings method", handler: server.handleUpstreamSettings, method: http.MethodDelete, want: http.StatusMethodNotAllowed},
		{name: "routes malformed", handler: server.handlePostDNSRoutes, method: http.MethodPost, body: "{", want: http.StatusBadRequest},
		{name: "routes empty pattern", handler: server.handlePostDNSRoutes, method: http.MethodPost, body: `{"":"1.1.1.1"}`, want: http.StatusBadRequest},
		{name: "routes invalid upstream", handler: server.handlePostDNSRoutes, method: http.MethodPost, body: `{"example.test":"bad://resolver"}`, want: http.StatusBadRequest},
		{name: "routes unavailable", handler: server.handlePostDNSRoutes, method: http.MethodPost, body: `{"example.test":"1.1.1.1"}`, want: http.StatusInternalServerError},
		{name: "user rules malformed", handler: server.handleUserRules, method: http.MethodPut, body: "{", want: http.StatusBadRequest},
		{name: "rollback unavailable", handler: server.handleFilteringRollback, method: http.MethodPost, body: `{"id":"missing"}`, want: http.StatusServiceUnavailable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.name == "rollback unavailable" {
				server.SetFilter(nil)
			}
			recorder := httptest.NewRecorder()
			test.handler(recorder, httptest.NewRequest(test.method, "/api/test", strings.NewReader(test.body)))
			if recorder.Code != test.want {
				t.Fatalf("status = %d, want %d; body=%q", recorder.Code, test.want, recorder.Body.String())
			}
		})
	}

	if err := server.replaceUserRules(strings.Repeat("x", maxUserRulesBytes+1)); err == nil {
		t.Fatal("oversized user rules were accepted")
	}
}

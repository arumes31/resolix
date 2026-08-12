package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/arumes31/resolix/webgui/internal/config"
	"github.com/arumes31/resolix/webgui/internal/filter"
	"github.com/arumes31/resolix/webgui/internal/models"
	"github.com/arumes31/resolix/webgui/internal/storage"
)

func TestHandleDashboardV1Stats(t *testing.T) {
	server := newDashboardTestServer(t)
	now := time.Now().Unix()
	server.store.AddEvent(models.QueryEvent{
		UnixTime:     now - 120,
		Domain:       "blocked.example",
		ClientIP:     "192.0.2.1",
		Type:         "A",
		Blocked:      true,
		ResponseCode: "NXDOMAIN",
	})
	server.store.AddEvent(models.QueryEvent{
		UnixTime:     now - 60,
		Domain:       "failed.example",
		ClientIP:     "192.0.2.2",
		Type:         "AAAA",
		Node:         "edge-a",
		Upstream:     "1.1.1.1",
		ResponseCode: "SERVFAIL",
	})
	server.store.AddEvent(models.QueryEvent{
		UnixTime:     now - int64((90 * time.Minute).Seconds()),
		Domain:       "previous.example",
		ClientIP:     "192.0.2.3",
		Type:         "A",
		Upstream:     "9.9.9.9",
		ResponseCode: "NOERROR",
	})
	server.SetFilter(filter.New())
	server.SetBuildInfo("2.5.0", "test")
	server.store.SetNodeStatus("edge-a", models.NodeStatus{ID: "edge-a", Version: "2.5.0"})
	server.store.SetNodeStatus("edge-b", models.NodeStatus{ID: "edge-b", Version: "2.4.9"})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/dashboard/v1/stats?range=1h", nil)
	server.handleDashboardV1Stats(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if got := recorder.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q", got)
	}

	var response dashboardV1Response
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if response.SchemaVersion != dashboardSchemaVersion {
		t.Fatalf("schema version = %d", response.SchemaVersion)
	}
	if response.Range.Key != "1h" || response.Range.BucketSeconds != int64((5*time.Minute).Seconds()) {
		t.Fatalf("range = %+v", response.Range)
	}
	if response.Summary.Queries != 2 || response.Summary.Blocked != 1 || response.Summary.Errors != 1 {
		t.Fatalf("summary = %+v", response.Summary)
	}
	if !response.Comparison.Available || response.Comparison.Summary == nil || response.Comparison.Summary.Queries != 1 {
		t.Fatalf("comparison = %+v", response.Comparison)
	}
	if response.Runtime.Version != "2.5.0" || response.Runtime.Role != config.ModeController || response.Runtime.OnlineNodes != 2 || response.Runtime.TotalNodes != 2 {
		t.Fatalf("runtime = %+v", response.Runtime)
	}
	if !response.Runtime.VersionSkew || len(response.Runtime.SkewedNodes) != 1 || response.Runtime.SkewedNodes[0] != "edge-b" {
		t.Fatalf("version skew = %+v", response.Runtime)
	}
	if len(response.Breakdowns.TopBlockedDomains) != 1 || response.Breakdowns.TopBlockedDomains[0].Key != "blocked.example" {
		t.Fatalf("top blocked domains = %+v", response.Breakdowns.TopBlockedDomains)
	}
	if !response.Filtering.Configured || !response.Filtering.Enabled || response.Filtering.State != "active" {
		t.Fatalf("filtering = %+v", response.Filtering)
	}
	if len(response.Series) == 0 {
		t.Fatal("server-generated series is empty")
	}
}

func TestHandleDashboardV1StatsValidatesMethodAndRange(t *testing.T) {
	server := newDashboardTestServer(t)
	tests := []struct {
		name        string
		method      string
		target      string
		expected    int
		expectAllow bool
	}{
		{name: "unsupported method", method: http.MethodPost, target: "/api/dashboard/v1/stats", expected: http.StatusMethodNotAllowed, expectAllow: true},
		{name: "unknown range", method: http.MethodGet, target: "/api/dashboard/v1/stats?range=2h", expected: http.StatusBadRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(test.method, test.target, nil)
			server.handleDashboardV1Stats(recorder, request)
			if recorder.Code != test.expected {
				t.Fatalf("status = %d, want %d", recorder.Code, test.expected)
			}
			if test.expectAllow && recorder.Header().Get("Allow") != http.MethodGet {
				t.Fatalf("Allow = %q", recorder.Header().Get("Allow"))
			}
		})
	}
}

func TestDashboardV1CacheIsScopedByRange(t *testing.T) {
	server := newDashboardTestServer(t)
	now := time.Now()
	server.store.AddEvent(models.QueryEvent{UnixTime: now.Unix(), Domain: "first.example", Type: "A"})

	readQueries := func(rangeKey string) int {
		t.Helper()
		preset := dashboardRangePresets[rangeKey]
		body, err := server.dashboardV1Response(t.Context(), preset, now)
		if err != nil {
			t.Fatal(err)
		}
		var response dashboardV1Response
		if err := json.Unmarshal(body, &response); err != nil {
			t.Fatal(err)
		}
		return response.Summary.Queries
	}

	if got := readQueries("1h"); got != 1 {
		t.Fatalf("initial queries = %d", got)
	}
	server.store.AddEvent(models.QueryEvent{UnixTime: now.Unix(), Domain: "second.example", Type: "AAAA"})
	if got := readQueries("1h"); got != 1 {
		t.Fatalf("cached 1h queries = %d, want 1", got)
	}
	if got := readQueries("6h"); got != 2 {
		t.Fatalf("uncached 6h queries = %d, want 2", got)
	}
}

func TestDashboardV1MarksRetentionLimitedRanges(t *testing.T) {
	server := newDashboardTestServer(t)
	body, err := server.dashboardV1Response(
		t.Context(),
		dashboardRangePresets["7d"],
		time.Now(),
	)
	if err != nil {
		t.Fatal(err)
	}
	var response dashboardV1Response
	if err := json.Unmarshal(body, &response); err != nil {
		t.Fatal(err)
	}
	if !response.Range.RetentionLimited {
		t.Fatal("7d range was not marked as limited by the default 72h retention")
	}
	if response.Comparison.Available || !response.Comparison.RetentionLimited || response.Comparison.Summary != nil {
		t.Fatalf("comparison should be unavailable for retained 7d range: %+v", response.Comparison)
	}
	if response.Range.AvailableSeconds != int64(config.DefaultHistoryRetention.Seconds()) {
		t.Fatalf("available seconds = %d", response.Range.AvailableSeconds)
	}
}

func TestVersionsDiffer(t *testing.T) {
	tests := []struct {
		name   string
		local  string
		remote string
		want   bool
	}{
		{name: "same", local: "2.5.0", remote: "2.5.0"},
		{name: "leading v is normalized", local: "v2.5.0", remote: "2.5.0"},
		{name: "different", local: "2.5.0", remote: "2.4.9", want: true},
		{name: "unknown local", remote: "2.4.9"},
		{name: "unknown remote", local: "2.5.0"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := versionsDiffer(test.local, test.remote); got != test.want {
				t.Fatalf("versionsDiffer(%q, %q) = %t, want %t", test.local, test.remote, got, test.want)
			}
		})
	}
}

func newDashboardTestServer(t *testing.T) *Server {
	t.Helper()
	cfg := &config.Config{
		BaseURL:              "/",
		Mode:                 config.ModeController,
		MaxEvents:            100,
		HistoryDir:           t.TempDir(),
		DBPath:               "dashboard.db",
		HistoryRetention:     config.DefaultHistoryRetention,
		NodeOfflineThreshold: config.DefaultNodeOfflineThreshold,
	}
	store := storage.NewStore(cfg)
	store.Init()
	t.Cleanup(store.Close)
	server := testServer(cfg)
	server.store = store
	server.dashboardCache = make(map[string]statsCacheEntry)
	return server
}

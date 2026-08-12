package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/arumes31/resolix/webgui/internal/config"
	"github.com/arumes31/resolix/webgui/internal/models"
	"github.com/arumes31/resolix/webgui/internal/storage"
)

func newHistoryTestServer(t *testing.T) (*Server, func()) {
	t.Helper()
	cfg := &config.Config{
		MaxEvents:        100,
		HistoryDir:       t.TempDir(),
		DBPath:           "history.db",
		HistoryRetention: 72 * time.Hour,
	}
	store := storage.NewStore(cfg)
	store.Init()
	server := testServer(cfg)
	server.store = store
	return server, store.Close
}

func TestHandleHistoryFiltersAndPaginatesPersistedEvents(t *testing.T) {
	server, cleanup := newHistoryTestServer(t)
	defer cleanup()
	now := time.Now().Unix()
	server.store.AddEvent(models.QueryEvent{
		UnixTime: now - 1, Domain: "allowed.example", ClientIP: "192.0.2.1", Type: "A",
	})
	server.store.AddEvent(models.QueryEvent{
		UnixTime: now, Domain: "blocked.example", ClientIP: "192.0.2.2", Type: "AAAA", Blocked: true,
	})
	server.store.ArchiveStep(time.Now())

	request := httptest.NewRequest(http.MethodGet, "/api/history?status=blocked&limit=1", nil)
	recorder := httptest.NewRecorder()
	server.handleHistory(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	var page storage.HistoryPage
	if err := json.Unmarshal(recorder.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Events) != 1 || page.Events[0].Domain != "blocked.example" {
		t.Fatalf("page = %+v", page)
	}

	request = httptest.NewRequest(http.MethodGet, "/api/history?cursor=invalid", nil)
	recorder = httptest.NewRecorder()
	server.handleHistory(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("invalid cursor status = %d", recorder.Code)
	}
}

func TestHandleStorageStatus(t *testing.T) {
	server, cleanup := newHistoryTestServer(t)
	defer cleanup()
	request := httptest.NewRequest(http.MethodGet, "/api/storage/status", nil)
	recorder := httptest.NewRecorder()
	server.handleStorageStatus(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d", recorder.Code)
	}
	var metrics storage.DatabaseMetrics
	if err := json.Unmarshal(recorder.Body.Bytes(), &metrics); err != nil {
		t.Fatal(err)
	}
	if metrics.DatabaseBytes <= 0 || metrics.BusyTimeoutMS != 5000 {
		t.Fatalf("metrics = %+v", metrics)
	}
}

func TestHistoryAndStorageStatusValidation(t *testing.T) {
	server, cleanup := newHistoryTestServer(t)
	defer cleanup()

	tests := []struct {
		name    string
		handler http.HandlerFunc
		method  string
		target  string
		want    int
	}{
		{name: "history method", handler: server.handleHistory, method: http.MethodPost, target: "/api/history", want: http.StatusMethodNotAllowed},
		{name: "zero cursor", handler: server.handleHistory, method: http.MethodGet, target: "/api/history?cursor=0", want: http.StatusBadRequest},
		{name: "invalid limit", handler: server.handleHistory, method: http.MethodGet, target: "/api/history?limit=0", want: http.StatusBadRequest},
		{name: "invalid status", handler: server.handleHistory, method: http.MethodGet, target: "/api/history?status=bad%20status", want: http.StatusBadRequest},
		{name: "storage method", handler: server.handleStorageStatus, method: http.MethodPost, target: "/api/storage/status", want: http.StatusMethodNotAllowed},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			test.handler(recorder, httptest.NewRequest(test.method, test.target, nil))
			if recorder.Code != test.want {
				t.Fatalf("status = %d, want %d; body=%q", recorder.Code, test.want, recorder.Body.String())
			}
		})
	}
}

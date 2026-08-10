package parser

import (
	"testing"
	"time"

	"github.com/arumes31/resolix/webgui/internal/config"
	"github.com/arumes31/resolix/webgui/internal/storage"
)

func TestParseResponseCodeIgnoresDomain(t *testing.T) {
	parts := [][]byte{
		[]byte("reply"), []byte("nxdomain.example"), []byte("is"), []byte("192.0.2.1"),
	}
	if got := parseResponseCode(0, parts); got != "NOERROR" {
		t.Fatalf("response code = %q; want NOERROR", got)
	}
}

func TestParsePipeDNSSEC(t *testing.T) {
	cfg := &config.Config{
		MaxEvents:                10,
		HistoryDir:               t.TempDir(),
		DBPath:                   "parser.db",
		HistoryRetention:         time.Hour,
		UpstreamLatencyThreshold: 200,
	}
	store := storage.NewStore(cfg)
	store.Init()
	defer store.Close()
	prs := NewParser(store, false)
	prs.ParseLogBytes([]byte("query[A] example.com from 192.0.2.1"), "node")
	prs.ParseLogBytes([]byte("validation|example.com|IN|secure"), "node")
	events := store.GetRecentEvents(0)
	if len(events) != 1 || events[0].DNSSEC != "secure" {
		t.Fatalf("events = %#v; want one secure event", events)
	}
}

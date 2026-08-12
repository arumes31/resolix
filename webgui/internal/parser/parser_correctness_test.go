package parser

import (
	"strings"
	"testing"
	"time"

	"github.com/arumes31/resolix/webgui/internal/config"
	"github.com/arumes31/resolix/webgui/internal/storage"
)

func newTestParser(t *testing.T, debug bool) (*Parser, *storage.Store) {
	t.Helper()
	store := storage.NewStore(&config.Config{
		MaxEvents:                100,
		HistoryDir:               t.TempDir(),
		DBPath:                   "parser.db",
		HistoryRetention:         time.Hour,
		UpstreamLatencyThreshold: 200,
	})
	store.Init()
	t.Cleanup(store.Close)
	return NewParser(store, debug), store
}

func TestParseResponseCodeIgnoresDomain(t *testing.T) {
	parts := [][]byte{
		[]byte("reply"), []byte("nxdomain.example"), []byte("is"), []byte("192.0.2.1"),
	}
	if got := parseResponseCode(0, parts); got != "NOERROR" {
		t.Fatalf("response code = %q; want NOERROR", got)
	}
}

func TestParsePipeDNSSEC(t *testing.T) {
	prs, store := newTestParser(t, false)
	prs.ParseLogBytes([]byte("query[A] example.com from 192.0.2.1"), "node")
	prs.ParseLogBytes([]byte("validation|example.com|IN|secure"), "node")
	events := store.GetRecentEvents(0)
	if len(events) != 1 || events[0].DNSSEC != "secure" {
		t.Fatalf("events = %#v; want one secure event", events)
	}
}

func TestParserQueryAndResponseFlow(t *testing.T) {
	prs, _ := newTestParser(t, false)
	event := prs.ParseLogBytes(
		[]byte("Jan 02 15:04:05 dnsmasq[12]: query[AAAA] EXAMPLE.COM. from 192.0.2.10"),
		"node-a",
	)
	if event == nil || event.Domain != "example.com" || event.Type != "AAAA" ||
		event.ClientIP != "192.0.2.10" || event.Node != "node-a" {
		t.Fatalf("query event = %+v", event)
	}
	prs.ParseLogBytes([]byte("forwarded example.com to 192.0.2.53"), "node-a")
	completed := prs.ParseLogBytes([]byte("reply example.com is NXDOMAIN"), "node-a")
	if completed == nil || completed.Upstream != "192.0.2.53" ||
		completed.ResponseCode != "NXDOMAIN" || !completed.Latency.Valid {
		t.Fatalf("completed event = %+v", completed)
	}
}

func TestParserResponseSources(t *testing.T) {
	tests := []struct {
		name     string
		action   string
		upstream string
	}{
		{name: "cache", action: "cached", upstream: "System Cache"},
		{name: "config", action: "config", upstream: "Local Override"},
		{name: "internal override", action: "reply", upstream: "Local Override"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			prs, _ := newTestParser(t, true)
			prs.ParseLogBytes([]byte("query[A] example.test from 192.0.2.1"), "node")
			if test.action == "reply" {
				prs.ParseLogBytes([]byte("forwarded example.test to 127.0.0.1#5353"), "node")
			}
			completed := prs.ParseLogBytes([]byte(test.action+" example.test is 192.0.2.2"), "node")
			if completed == nil || completed.Upstream != test.upstream || completed.ResponseCode != "NOERROR" {
				t.Fatalf("completed event = %+v", completed)
			}
		})
	}
}

func TestParserRejectsMalformedLines(t *testing.T) {
	prs, _ := newTestParser(t, true)
	lines := []string{
		"",
		"unrelated log message",
		"query[",
		"query[A] example.test missing 192.0.2.1",
		"forwarded example.test not-to 192.0.2.53",
		"reply unknown.test is SERVFAIL",
		"validation example.test IN unknown",
		"validation|example.test|IN",
		"validation|example.test|IN|unknown",
	}
	for _, line := range lines {
		if got := prs.ParseLogBytes([]byte(line), "node"); got != nil {
			t.Errorf("ParseLogBytes(%q) = %+v, want nil", line, got)
		}
	}
}

func TestParserDNSSECFormats(t *testing.T) {
	prs, store := newTestParser(t, false)
	for _, domain := range []string{"space.test", "pipe.test"} {
		prs.ParseLogBytes([]byte("query[A] "+domain+" from 192.0.2.1"), "node")
	}
	prs.ParseLogBytes([]byte("validation SPACE.TEST. IN bogus"), "node")
	prs.ParseLogBytes([]byte("prefix validation|PIPE.TEST.|IN|indeterminate"), "node")

	results := make(map[string]string)
	for _, event := range store.GetRecentEvents(0) {
		results[event.Domain] = event.DNSSEC
	}
	if results["space.test"] != "bogus" || results["pipe.test"] != "indeterminate" {
		t.Fatalf("DNSSEC results = %#v", results)
	}
}

func TestParseResponseCode(t *testing.T) {
	tests := []struct {
		name   string
		line   string
		action int
		want   string
	}{
		{name: "invalid index", line: "reply example.test is NXDOMAIN", action: -1},
		{name: "short payload", line: "reply example.test", action: 0},
		{name: "nxdomain", line: "reply example.test is NXDOMAIN", action: 0, want: "NXDOMAIN"},
		{name: "servfail", line: "reply example.test is SERVFAIL", action: 0, want: "SERVFAIL"},
		{name: "refused", line: "reply example.test is REFUSED", action: 0, want: "REFUSED"},
		{name: "timeout", line: "reply example.test timed out", action: 0, want: "TIMEOUT"},
		{name: "noerror", line: "cached example.test is 192.0.2.1", action: 0, want: "NOERROR"},
		{name: "unknown action", line: "other example.test is value", action: 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fields := strings.Fields(test.line)
			parts := make([][]byte, len(fields))
			for index := range fields {
				parts[index] = []byte(fields[index])
			}
			if got := parseResponseCode(test.action, parts); got != test.want {
				t.Fatalf("parseResponseCode() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestBufferPoolResetsBuffers(t *testing.T) {
	buffer := getBuffer()
	buffer.WriteString("used")
	putBuffer(buffer)
	buffer = getBuffer()
	defer putBuffer(buffer)
	if buffer.Len() != 0 {
		t.Fatalf("pooled buffer length = %d, want 0", buffer.Len())
	}
}

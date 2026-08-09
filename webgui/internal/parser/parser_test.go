// Package parser provides benchmark tests for log parsing routines,
// measuring throughput and allocation rates for various dnsmasq log
// line formats.
package parser

import (
	"fmt"
	"testing"
	"time"

	"tailscale-dnsrewrite/webgui/internal/config"
	"tailscale-dnsrewrite/webgui/internal/storage"
)

// newBenchStore creates a Store for benchmarking with an in-memory database.
func newBenchStore(b *testing.B) *storage.Store {
	b.Helper()
	cfg := &config.Config{
		MaxEvents:                100000,
		HistoryDir:               b.TempDir(),
		DBPath:                   "bench.db",
		HistoryRetention:         72 * time.Hour,
		UpstreamLatencyThreshold: 200,
	}
	s := storage.NewStore(cfg)
	s.Init()
	return s
}

// Realistic dnsmasq log line samples for benchmarking.
var benchLogLines = []struct {
	name string
	line []byte
}{
	{
		name: "query_A",
		line: []byte("Jan 02 15:04:05 dnsmasq[1234]: query[A] google.com from 192.168.1.100"),
	},
	{
		name: "query_AAAA",
		line: []byte("Jan 02 15:04:05 dnsmasq[1234]: query[AAAA] ipv6.google.com from 192.168.1.100"),
	},
	{
		name: "query_TXT",
		line: []byte("Jan 02 15:04:05 dnsmasq[1234]: query[TXT] _dmarc.example.com from 10.0.0.1"),
	},
	{
		name: "query_SRV",
		line: []byte("Jan 02 15:04:05 dnsmasq[1234]: query[SRV] _sip._tcp.example.com from 10.0.0.1"),
	},
	{
		name: "forwarded",
		line: []byte("Jan 02 15:04:05 dnsmasq[1234]: forwarded google.com to 8.8.8.8"),
	},
	{
		name: "reply",
		line: []byte("Jan 02 15:04:05 dnsmasq[1234]: reply google.com is 142.250.80.46"),
	},
	{
		name: "cached",
		line: []byte("Jan 02 15:04:05 dnsmasq[1234]: cached google.com is 142.250.80.46"),
	},
	{
		name: "config",
		line: []byte("Jan 02 15:04:05 dnsmasq[1234]: config example.com is 10.0.0.5"),
	},
	{
		name: "validation",
		line: []byte("Jan 02 15:04:05 dnsmasq[1234]: validation dnsmasq.org IN secure"),
	},
	{
		name: "reply_nxdomain",
		line: []byte("Jan 02 15:04:05 dnsmasq[1234]: reply nonexistent.example.com is NXDOMAIN"),
	},
}

// BenchmarkParseLine benchmarks single line parsing for each log format.
func BenchmarkParseLine(b *testing.B) {
	store := newBenchStore(b)
	defer store.Close()
	prs := NewParser(store, false)

	for _, tt := range benchLogLines {
		b.Run(tt.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				prs.ParseLogBytes(tt.line, "bench-node")
			}
		})
	}
}

// BenchmarkParseBatch benchmarks parsing 1000 lines in sequence.
func BenchmarkParseBatch(b *testing.B) {
	store := newBenchStore(b)
	defer store.Close()
	prs := NewParser(store, false)

	// Generate 1000 realistic log lines
	lines := make([][]byte, 1000)
	for i := 0; i < 1000; i++ {
		switch i % 5 {
		case 0:
			lines[i] = []byte(fmt.Sprintf("Jan 02 15:04:05 dnsmasq[1234]: query[A] domain%d.com from 192.168.1.%d", i%100, i%254+1))
		case 1:
			lines[i] = []byte(fmt.Sprintf("Jan 02 15:04:05 dnsmasq[1234]: query[AAAA] ipv6-domain%d.com from 10.0.0.%d", i%100, i%254+1))
		case 2:
			lines[i] = []byte(fmt.Sprintf("Jan 02 15:04:05 dnsmasq[1234]: forwarded domain%d.com to 8.8.8.8", i%100))
		case 3:
			lines[i] = []byte(fmt.Sprintf("Jan 02 15:04:05 dnsmasq[1234]: reply domain%d.com is 1.2.3.4", i%100))
		case 4:
			lines[i] = []byte(fmt.Sprintf("Jan 02 15:04:05 dnsmasq[1234]: cached domain%d.com is 5.6.7.8", i%100))
		}
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, line := range lines {
			prs.ParseLogBytes(line, "bench-node")
		}
	}
}

// BenchmarkParseLineParallel benchmarks parallel parsing of log lines.
func BenchmarkParseLineParallel(b *testing.B) {
	store := newBenchStore(b)
	defer store.Close()
	prs := NewParser(store, false)

	line := []byte("Jan 02 15:04:05 dnsmasq[1234]: query[A] parallel-bench.com from 192.168.1.1")

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			prs.ParseLogBytes(line, fmt.Sprintf("node-%d", i%10))
			i++
		}
	})
}

// BenchmarkBufPoolGetPut benchmarks the sync.Pool buffer get/put cycle.
func BenchmarkBufPoolGetPut(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf := getBuffer()
		buf.WriteString("test data for benchmarking")
		putBuffer(buf)
	}
}

// BenchmarkParseResponseCode benchmarks the response code parsing function.
func BenchmarkParseResponseCode(b *testing.B) {
	b.ReportAllocs()
	parts := [][]byte{
		[]byte("Jan"), []byte("02"), []byte("15:04:05"),
		[]byte("dnsmasq[1234]:"), []byte("reply"),
		[]byte("example.com"), []byte("is"), []byte("NXDOMAIN"),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		parseResponseCode(4, parts)
	}
}

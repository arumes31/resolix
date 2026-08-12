package filter

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"
)

const realWorldListDirEnv = "RESOLIX_FILTER_BENCH_DIR"

type realWorldCorpus struct {
	engine          *Engine
	rules           int
	indexedDomains  int
	allowOverrides  int
	ignored         int
	truncated       int
	parseDuration   time.Duration
	publishDuration time.Duration
	memoryBytes     uint64
}

// TestRealWorldListCorpus measures operator-provided list snapshots without
// making the regular test suite depend on the network or large fixtures.
func TestRealWorldListCorpus(t *testing.T) {
	corpus := loadRealWorldCorpus(t)
	if corpus.rules == 0 {
		t.Fatal("real-world corpus loaded no active rules")
	}
	t.Logf(
		"rules=%d indexed_domains=%d allow_overrides=%d ignored=%d truncated_sources=%d parse=%s publish=%s retained_memory=%d MiB",
		corpus.rules,
		corpus.indexedDomains,
		corpus.allowOverrides,
		corpus.ignored,
		corpus.truncated,
		corpus.parseDuration,
		corpus.publishDuration,
		corpus.memoryBytes/(1<<20),
	)
}

func TestRealWorldListHTTPRefresh(t *testing.T) {
	directory := strings.TrimSpace(os.Getenv(realWorldListDirEnv))
	if directory == "" {
		t.Skipf("set %s to run the real-world HTTP refresh test", realWorldListDirEnv)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.FileServer(http.Dir(directory)))
	t.Cleanup(server.Close)

	engine := New()
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".txt") {
			continue
		}
		engine.AddURLSourceWithOptions(Subscription{
			ID:           entry.Name(),
			Name:         entry.Name(),
			URL:          server.URL + "/" + entry.Name(),
			AllowOnly:    strings.HasPrefix(strings.ToLower(entry.Name()), "allow-"),
			Enabled:      true,
			AllowPrivate: true,
		})
	}
	start := time.Now()
	done := make(chan struct{})
	go func() {
		engine.UpdateAll(context.Background())
		close(done)
	}()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	var maxLookup time.Duration
	lookupCount := 0
refreshLoop:
	for {
		select {
		case <-done:
			break refreshLoop
		case <-ticker.C:
			lookupStart := time.Now()
			_ = engine.Match("refresh-probe.resolix.invalid")
			latency := time.Since(lookupStart)
			if latency > maxLookup {
				maxLookup = latency
			}
			lookupCount++
		}
	}
	duration := time.Since(start)

	totalRules := 0
	truncatedSources := 0
	for _, source := range engine.Sources() {
		if source.LastError != "" {
			t.Errorf("%s refresh error: %s", source.Title, source.LastError)
		}
		totalRules += source.RuleCount + source.AllowRuleCount
		if source.Truncated {
			truncatedSources++
		}
	}
	if t.Failed() {
		return
	}
	if result := engine.Match("github.com"); !result.Allowed {
		t.Fatalf("allowlist did not allow github.com: %+v", result)
	}
	if result := engine.Match("doubleclick.net"); !result.Blocked {
		t.Fatalf("blocklists did not block doubleclick.net: %+v", result)
	}
	if truncatedSources != 0 {
		t.Fatalf("truncated sources = %d, want 0", truncatedSources)
	}
	if maxLookup > 250*time.Millisecond {
		t.Fatalf("maximum lookup latency during refresh = %s, want <= 250ms", maxLookup)
	}
	t.Logf(
		"HTTP refresh loaded %d rules from %d sources in %s; %d concurrent lookups, max latency %s",
		totalRules,
		len(engine.Sources()),
		duration,
		lookupCount,
		maxLookup,
	)
}

// BenchmarkRealWorldFilterMatch measures lookup cost against the exact list
// snapshots selected through RESOLIX_FILTER_BENCH_DIR.
func BenchmarkRealWorldFilterMatch(b *testing.B) {
	corpus := loadRealWorldCorpus(b)
	blockedDomain, allowedDomain := corpus.sampleDomains()
	queries := []struct {
		name   string
		domain string
	}{
		{name: "blocked", domain: blockedDomain},
		{name: "allowed", domain: allowedDomain},
		{name: "miss", domain: "definitely-not-listed.resolix.invalid"},
	}
	for _, query := range queries {
		b.Run(query.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ReportMetric(float64(corpus.rules), "active-rules")
			for b.Loop() {
				_ = corpus.engine.Match(query.domain)
			}
		})
	}
}

func loadRealWorldCorpus(tb testing.TB) realWorldCorpus {
	tb.Helper()
	directory := strings.TrimSpace(os.Getenv(realWorldListDirEnv))
	if directory == "" {
		tb.Skipf("set %s to a directory containing block-*.txt and allow-*.txt snapshots", realWorldListDirEnv)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		tb.Fatalf("read real-world list directory: %v", err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	corpus := realWorldCorpus{engine: New()}
	corpus.engine.beginRuleUpdateBatch()
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".txt") {
			continue
		}
		path := filepath.Join(directory, entry.Name())
		file, err := os.Open(path) // #nosec G304,G703 -- opt-in benchmark path is supplied by the developer.
		if err != nil {
			tb.Fatalf("open %s: %v", entry.Name(), err)
		}
		allowOnly := strings.HasPrefix(strings.ToLower(entry.Name()), "allow-")
		parseStart := time.Now()
		block, allow, ignored, truncated, parseErr := parseRulesCapped(file, allowOnly)
		closeErr := file.Close()
		corpus.parseDuration += time.Since(parseStart)
		if parseErr != nil {
			tb.Fatalf("parse %s: %v", entry.Name(), parseErr)
		}
		if closeErr != nil {
			tb.Fatalf("close %s: %v", entry.Name(), closeErr)
		}

		source := &Source{Name: entry.Name(), Kind: "file", AllowOnly: allowOnly, Enabled: true}
		corpus.engine.mu.Lock()
		corpus.engine.sources = append(corpus.engine.sources, source)
		corpus.engine.mu.Unlock()
		publishStart := time.Now()
		corpus.engine.setRulesStatus(source, block, allow, "", ignored, truncated, 0, "", "", 0)
		corpus.publishDuration += time.Since(publishStart)
		corpus.rules += len(block) + len(allow)
		corpus.ignored += ignored
		if truncated {
			corpus.truncated++
		}
	}
	publishStart := time.Now()
	corpus.engine.endRuleUpdateBatch()
	corpus.publishDuration += time.Since(publishStart)
	corpus.engine.mu.RLock()
	corpus.indexedDomains = len(corpus.engine.blockDomainIndex) + len(corpus.engine.allowDomainIndex)
	corpus.engine.mu.RUnlock()
	corpus.allowOverrides = len(corpus.engine.AllowlistOverrides(10000))
	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	if after.HeapAlloc > before.HeapAlloc {
		corpus.memoryBytes = after.HeapAlloc - before.HeapAlloc
	}
	return corpus
}

func (c realWorldCorpus) sampleDomains() (blocked, allowed string) {
	c.engine.mu.RLock()
	defer c.engine.mu.RUnlock()
	for _, candidate := range []string{"doubleclick.net", "googleadservices.com", "adservice.google.com"} {
		if _, ok := c.engine.blockDomainIndex[candidate]; ok {
			blocked = candidate
			break
		}
	}
	if _, ok := c.engine.allowDomainIndex["github.com"]; ok {
		allowed = "github.com"
	}
	for domain := range c.engine.blockDomainIndex {
		if blocked != "" {
			break
		}
		blocked = domain
	}
	for domain := range c.engine.allowDomainIndex {
		if allowed != "" {
			break
		}
		allowed = domain
	}
	if allowed == "" {
		allowed = "allowlist-sample.resolix.invalid"
	}
	return blocked, allowed
}

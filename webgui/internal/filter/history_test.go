package filter

import (
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestRulesChangedCallbackOnlyRunsAfterChangedPublication(t *testing.T) {
	engine := New()
	source := engine.AddURLSourceWithOptions(Subscription{
		ID: "managed", URL: "https://example.com/list.txt", Enabled: true,
	})
	var calls atomic.Int32
	engine.SetRulesChangedCallback(func() { calls.Add(1) })
	first, _ := parseRules(strings.NewReader("one.example\n"), false)
	second, _ := parseRules(strings.NewReader("two.example\n"), false)

	engine.setRules(source, first, nil, "")
	engine.setRules(source, first, nil, "")
	engine.setRules(source, nil, nil, "download failed")
	engine.setRules(source, second, nil, "")
	if got := calls.Load(); got != 2 {
		t.Fatalf("callback calls = %d, want 2", got)
	}
}

func TestRuleHistoryPersistsAcrossRestart(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "history")
	newEngine := func() (*Engine, *Source) {
		engine := New()
		source := engine.AddURLSourceWithOptions(Subscription{
			ID: "managed", URL: "https://example.com/list.txt", Enabled: true,
		})
		engine.SetHistoryDir(dir)
		return engine, source
	}
	engine, source := newEngine()
	first, _ := parseRules(strings.NewReader("one.example\n"), false)
	second, _ := parseRules(strings.NewReader("two.example\n"), false)
	engine.setRules(source, first, nil, "")
	engine.setRules(source, second, nil, "")

	restarted, _ := newEngine()
	if err := restarted.RollbackSource("managed"); err != nil {
		t.Fatalf("RollbackSource after restart: %v", err)
	}
	if result := restarted.Match("one.example"); !result.Blocked {
		t.Fatalf("rolled-back match = %+v", result)
	}
}

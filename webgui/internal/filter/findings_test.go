package filter

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

func TestRollbackNeverRestoresBlockRulesIntoAllowOnlySource(t *testing.T) {
	engine := New()
	source := engine.AddURLSourceWithOptions(Subscription{
		ID: "managed", URL: "https://example.com/list.txt", Enabled: true,
	})
	first, _ := parseRules(strings.NewReader("blocked.example\n"), false)
	second, _ := parseRules(strings.NewReader("other.example\n"), false)
	engine.setRules(source, first, nil, "")
	engine.setRules(source, second, nil, "")

	engine.mu.Lock()
	source.AllowOnly = true
	engine.mu.Unlock()
	if err := engine.RollbackSource("managed"); err != nil {
		t.Fatalf("RollbackSource: %v", err)
	}
	if result := engine.Match("blocked.example"); result.Blocked || !result.Allowed {
		t.Fatalf("exception-only rollback match = %+v, want allowed and not blocked", result)
	}
	if source.RuleCount != 0 || source.AllowRuleCount != 1 {
		t.Fatalf("rule counts = %d block / %d allow", source.RuleCount, source.AllowRuleCount)
	}
}

func TestPersistedHistoryIsBoundToAllowOnlyPolicy(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "history")
	engine := New()
	engine.SetHistoryDir(dir)
	subscription := Subscription{ID: "managed", URL: "https://example.com/list.txt", Enabled: true}
	engine.ReplaceURLSources([]Subscription{subscription})
	source := engine.sourceByID("managed")
	first, _ := parseRules(strings.NewReader("blocked.example\n"), false)
	second, _ := parseRules(strings.NewReader("other.example\n"), false)
	engine.setRules(source, first, nil, "")
	engine.setRules(source, second, nil, "")

	subscription.AllowOnly = true
	engine.ReplaceURLSources([]Subscription{subscription})
	if err := engine.RollbackSource("managed"); err == nil {
		t.Fatal("history captured under a different AllowOnly policy was restored")
	}
	if _, ok := readSourceHistory(dir, "managed", false); !ok {
		t.Fatal("history should still load for its original policy")
	}

	allowOnlyFirst, allowOnlyRules := parseRules(strings.NewReader("trusted.example\n"), true)
	_ = allowOnlyFirst
	allowOnlySource := engine.sourceByID("managed")
	allowOnlySecond, allowOnlyRulesSecond := parseRules(strings.NewReader("second.example\n"), true)
	_ = allowOnlySecond
	engine.setRules(allowOnlySource, nil, allowOnlyRules, "")
	engine.setRules(allowOnlySource, nil, allowOnlyRulesSecond, "")
	history, ok := readSourceHistory(dir, "managed", true)
	if !ok || len(history) == 0 || len(history[len(history)-1].allow) != 1 {
		t.Fatalf("exception-only history did not round-trip: ok=%v history=%+v", ok, history)
	}
}

func TestRegexProgramBudgetPerExpression(t *testing.T) {
	if _, _, ok := parseLine(`/^ad[0-9]+\.example\.com$/`); !ok {
		t.Fatal("small regex rejected")
	}
	if _, _, ok := parseLine(`/(?:a{1000}){1000}/`); ok {
		t.Fatal("expanded regex accepted")
	}
	if _, _, ok := parseLine(`/(?:[a-z]{100}){30}/`); ok {
		t.Fatal("regex over the instruction budget accepted")
	}
}

func TestRegexProgramBudgetPerSourceRejectsUpdate(t *testing.T) {
	var body strings.Builder
	// Each rule compiles to a sizable program; together they exceed the source budget.
	pattern := `/^x[a-z0-9]{500}%d$/` + "\n"
	rule, _, ok := parseLine(fmt.Sprintf(pattern, 0))
	if !ok || rule.insts < 500 {
		t.Fatalf("test pattern rejected or too small: ok=%v insts=%d", ok, rule.insts)
	}
	for i := 0; i <= maxRegexInstsPerSource/rule.insts; i++ {
		fmt.Fprintf(&body, pattern, i)
	}
	if _, _, _, _, err := parseRulesCapped(strings.NewReader(body.String()), false); err == nil {
		t.Fatal("aggregate regex budget not enforced")
	}
	if _, _, _, _, err := parseRulesCapped(strings.NewReader("/^ads?\\./\n||example.com^\n"), false); err != nil {
		t.Fatalf("small source rejected: %v", err)
	}
}

func TestAllowlistOverridesHonorsCancellationAndBudget(t *testing.T) {
	engine := New()
	var allow, block strings.Builder
	for i := 0; i < 50; i++ {
		fmt.Fprintf(&allow, "@@||safe%d.ads.example^\n", i)
	}
	block.WriteString("||ads.example^\n")
	engine.AddFileSource(writeTempList(t, block.String()), false)
	engine.AddFileSource(writeTempList(t, allow.String()), false)

	if got := engine.AllowlistOverrides(10); len(got) != 10 {
		t.Fatalf("overrides = %d, want 10", len(got))
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := engine.AllowlistOverridesContext(ctx, 10); len(got) != 0 {
		t.Fatalf("canceled report returned %d overrides", len(got))
	}

	// A regex set larger than the evaluation budget stops the report early.
	var regexes strings.Builder
	for i := 0; i < maxOverrideRegexEvaluations/10+1; i++ {
		fmt.Fprintf(&regexes, "/^never%d$/\n", i)
	}
	engine.AddFileSource(writeTempList(t, regexes.String()), false)
	got := engine.AllowlistOverrides(100)
	if len(got) >= 50 {
		t.Fatalf("budget not enforced: %d overrides", len(got))
	}
}

func (e *Engine) sourceByID(id string) *Source {
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, src := range e.sources {
		if src.ID == id {
			return src
		}
	}
	return nil
}

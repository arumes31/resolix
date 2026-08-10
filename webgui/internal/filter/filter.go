package filter

import (
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Result describes the outcome of a filter match.
type Result struct {
	// Allowed is true when an exception (@@) rule matched.
	Allowed bool
	// Blocked is true when a block rule matched.
	Blocked bool
	// Rule is the raw text of the matched rule (MatchedRule on events).
	Rule string
	// Source is the name (file path or URL) of the list containing the rule.
	Source string
	// Reason is a short machine-readable block reason (BlockReason on events).
	Reason string
}

// Block reasons, roughly following AdGuard Home query-log naming.
const (
	ReasonBlocklist = "FilteredByBlocklist"
	ReasonRegex     = "FilteredByRegex"
)

// Source describes a rule source (local file or remote URL) and its status.
type Source struct {
	ID             string    `json:"id,omitempty"`
	Title          string    `json:"title,omitempty"`
	Name           string    `json:"name"`
	Kind           string    `json:"kind"` // "file" or "url"
	Enabled        bool      `json:"enabled"`
	AllowOnly      bool      `json:"allow_only"`
	RuleCount      int       `json:"rule_count"`
	AllowRuleCount int       `json:"allow_rule_count"`
	LastUpdate     time.Time `json:"last_update"`
	LastChecked    time.Time `json:"last_checked"`
	LastChanged    time.Time `json:"last_changed"`
	LastError      string    `json:"last_error,omitempty"`
	IgnoredCount   int       `json:"ignored_count"`
	Truncated      bool      `json:"truncated"`

	// Conditional-GET state (not serialized).
	etag         string
	lastModified string
	validURL     bool
}

// Engine is the filter rule engine. It is safe for concurrent use.
type Engine struct {
	mu               sync.RWMutex
	sources          []*Source
	blockRules       map[*Source][]Rule
	allowRules       map[*Source][]Rule
	blockDomainIndex map[string][]indexedRule
	allowDomainIndex map[string][]indexedRule
	blockRegexRules  []indexedRule
	allowRegexRules  []indexedRule

	pausedUntil    atomic.Int64 // unix seconds; 0 = protection enabled
	blockedTotal   atomic.Int64
	allowedTotal   atomic.Int64
	httpClient     *http.Client
	updateRequests chan struct{}
}

type indexedRule struct {
	rule   Rule
	source *Source
	order  int
}

// New creates an empty filter engine.
func New() *Engine {
	return &Engine{
		blockRules:       make(map[*Source][]Rule),
		allowRules:       make(map[*Source][]Rule),
		blockDomainIndex: make(map[string][]indexedRule),
		allowDomainIndex: make(map[string][]indexedRule),
		httpClient:       &http.Client{Timeout: fetchTimeout},
		updateRequests:   make(chan struct{}, 1),
	}
}

// Match evaluates the rules for the given normalized domain. Exceptions are
// evaluated before block rules. When the engine has no sources or no rule
// matches, the zero Result is returned.
func (e *Engine) Match(domain string) Result {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if match, ok := firstIndexedMatch(domain, e.allowDomainIndex, e.allowRegexRules); ok {
		e.allowedTotal.Add(1)
		return Result{Allowed: true, Rule: match.rule.Raw, Source: match.source.Name}
	}
	if match, ok := firstIndexedMatch(domain, e.blockDomainIndex, e.blockRegexRules); ok {
		e.blockedTotal.Add(1)
		reason := ReasonBlocklist
		if match.rule.kind == kindRegex {
			reason = ReasonRegex
		}
		return Result{Blocked: true, Rule: match.rule.Raw, Source: match.source.Name, Reason: reason}
	}
	return Result{}
}

func firstIndexedMatch(domain string, domains map[string][]indexedRule, regex []indexedRule) (indexedRule, bool) {
	var first indexedRule
	found := false
	for candidate := domain; candidate != ""; {
		for _, match := range domains[candidate] {
			if !found || match.order < first.order {
				first, found = match, true
			}
		}
		dot := strings.IndexByte(candidate, '.')
		if dot < 0 {
			break
		}
		candidate = candidate[dot+1:]
	}
	for _, match := range regex {
		if match.rule.matches(domain) && (!found || match.order < first.order) {
			first, found = match, true
		}
	}
	return first, found
}

// Pause disables protection for the given number of minutes; minutes <= 0
// resumes protection immediately.
func (e *Engine) Pause(minutes int) {
	if minutes <= 0 {
		e.pausedUntil.Store(0)
		return
	}
	e.pausedUntil.Store(time.Now().Add(time.Duration(minutes) * time.Minute).Unix())
}

// Paused reports whether filtering is currently paused.
func (e *Engine) Paused() bool {
	until := e.pausedUntil.Load()
	return until != 0 && time.Now().Unix() < until
}

// PausedUntil returns the pause deadline (zero time when not paused).
func (e *Engine) PausedUntil() time.Time {
	until := e.pausedUntil.Load()
	if until == 0 || time.Now().Unix() >= until {
		return time.Time{}
	}
	return time.Unix(until, 0)
}

// Stats returns the cumulative match counters for metrics.
func (e *Engine) Stats() (blocked, allowed int64) {
	return e.blockedTotal.Load(), e.allowedTotal.Load()
}

// Sources returns a snapshot of the source list for status reporting.
func (e *Engine) Sources() []Source {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]Source, len(e.sources))
	for i, src := range e.sources {
		out[i] = *src
	}
	return out
}

// ReplaceURLSources atomically replaces managed URL subscriptions while
// preserving local file sources. Call UpdateAll after replacement to fetch
// the newly configured subscriptions.
func (e *Engine) ReplaceURLSources(subscriptions []Subscription) {
	e.mu.Lock()
	defer e.mu.Unlock()

	kept := make([]*Source, 0, len(e.sources)+len(subscriptions))
	for _, src := range e.sources {
		if src.Kind == "url" {
			delete(e.blockRules, src)
			delete(e.allowRules, src)
			continue
		}
		kept = append(kept, src)
	}
	for _, subscription := range subscriptions {
		if !subscription.Enabled {
			continue
		}
		src := newURLSource(subscription)
		kept = append(kept, src)
	}
	e.sources = kept
	e.rebuildIndexesLocked()
}

// setRules atomically swaps the parsed rules of a source and refreshes its
// status (keep-last-good: callers only invoke this on successful loads).
func (e *Engine) setRules(src *Source, block, allow []Rule, loadErr string) {
	e.setRulesStatus(src, block, allow, loadErr, 0, false)
}

func (e *Engine) setRulesStatus(src *Source, block, allow []Rule, loadErr string, ignored int, truncated bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	active := false
	for _, current := range e.sources {
		if current == src {
			active = true
			break
		}
	}
	if !active {
		return
	}
	src.LastChecked = time.Now()
	if loadErr == "" {
		changed := !rulesEqual(e.blockRules[src], block) || !rulesEqual(e.allowRules[src], allow)
		e.blockRules[src] = block
		e.allowRules[src] = allow
		e.rebuildIndexesLocked()
		src.RuleCount = len(block)
		src.AllowRuleCount = len(allow)
		src.LastUpdate = src.LastChecked
		if changed {
			src.LastChanged = src.LastChecked
		}
		src.IgnoredCount = ignored
		src.Truncated = truncated
	}
	src.LastError = loadErr
}

func rulesEqual(a, b []Rule) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Raw != b[i].Raw || a[i].kind != b[i].kind || a[i].domain != b[i].domain {
			return false
		}
		aPattern, bPattern := "", ""
		if a[i].re != nil {
			aPattern = a[i].re.String()
		}
		if b[i].re != nil {
			bPattern = b[i].re.String()
		}
		if aPattern != bPattern {
			return false
		}
	}
	return true
}

func (e *Engine) rebuildIndexesLocked() {
	e.blockDomainIndex = make(map[string][]indexedRule)
	e.allowDomainIndex = make(map[string][]indexedRule)
	e.blockRegexRules = nil
	e.allowRegexRules = nil
	blockOrder, allowOrder := 0, 0
	for _, src := range e.sources {
		for _, rule := range e.allowRules[src] {
			match := indexedRule{rule: rule, source: src, order: allowOrder}
			allowOrder++
			if rule.kind == kindRegex {
				e.allowRegexRules = append(e.allowRegexRules, match)
			} else {
				e.allowDomainIndex[rule.domain] = append(e.allowDomainIndex[rule.domain], match)
			}
		}
		for _, rule := range e.blockRules[src] {
			match := indexedRule{rule: rule, source: src, order: blockOrder}
			blockOrder++
			if rule.kind == kindRegex {
				e.blockRegexRules = append(e.blockRegexRules, match)
			} else {
				e.blockDomainIndex[rule.domain] = append(e.blockDomainIndex[rule.domain], match)
			}
		}
	}
}

func (e *Engine) setSourceError(src *Source, loadErr string) {
	e.mu.Lock()
	src.LastChecked = time.Now()
	src.LastError = loadErr
	e.mu.Unlock()
}

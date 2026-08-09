package filter

import (
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
	Name           string    `json:"name"`
	Kind           string    `json:"kind"` // "file" or "url"
	AllowOnly      bool      `json:"allow_only"`
	RuleCount      int       `json:"rule_count"`
	AllowRuleCount int       `json:"allow_rule_count"`
	LastUpdate     time.Time `json:"last_update"`
	LastError      string    `json:"last_error,omitempty"`

	// Conditional-GET state (not serialized).
	etag         string
	lastModified string
}

// Engine is the filter rule engine. It is safe for concurrent use.
type Engine struct {
	mu         sync.RWMutex
	sources    []*Source
	blockRules map[*Source][]Rule
	allowRules map[*Source][]Rule

	pausedUntil  atomic.Int64 // unix seconds; 0 = protection enabled
	blockedTotal atomic.Int64
	allowedTotal atomic.Int64
}

// New creates an empty filter engine.
func New() *Engine {
	return &Engine{
		blockRules: make(map[*Source][]Rule),
		allowRules: make(map[*Source][]Rule),
	}
}

// Match evaluates the rules for the given normalized domain. Exceptions are
// evaluated before block rules. When the engine has no sources or no rule
// matches, the zero Result is returned.
func (e *Engine) Match(domain string) Result {
	e.mu.RLock()
	defer e.mu.RUnlock()

	for _, src := range e.sources {
		for _, r := range e.allowRules[src] {
			if r.matches(domain) {
				e.allowedTotal.Add(1)
				return Result{Allowed: true, Rule: r.Raw, Source: src.Name}
			}
		}
	}
	for _, src := range e.sources {
		for _, r := range e.blockRules[src] {
			if r.matches(domain) {
				e.blockedTotal.Add(1)
				reason := ReasonBlocklist
				if r.kind == kindRegex {
					reason = ReasonRegex
				}
				return Result{Blocked: true, Rule: r.Raw, Source: src.Name, Reason: reason}
			}
		}
	}
	return Result{}
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

// setRules atomically swaps the parsed rules of a source and refreshes its
// status (keep-last-good: callers only invoke this on successful loads).
func (e *Engine) setRules(src *Source, block, allow []Rule, loadErr string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if loadErr == "" {
		e.blockRules[src] = block
		e.allowRules[src] = allow
		src.RuleCount = len(block)
		src.AllowRuleCount = len(allow)
		src.LastUpdate = time.Now()
	}
	src.LastError = loadErr
}

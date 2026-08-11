package filter

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"sort"
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
	ID              string    `json:"id,omitempty"`
	Title           string    `json:"title,omitempty"`
	Name            string    `json:"name"`
	Kind            string    `json:"kind"` // "file" or "url"
	Enabled         bool      `json:"enabled"`
	AllowOnly       bool      `json:"allow_only"`
	RuleCount       int       `json:"rule_count"`
	AllowRuleCount  int       `json:"allow_rule_count"`
	LastUpdate      time.Time `json:"last_update"`
	LastChecked     time.Time `json:"last_checked"`
	LastChanged     time.Time `json:"last_changed"`
	LastError       string    `json:"last_error,omitempty"`
	IgnoredCount    int       `json:"ignored_count"`
	IgnoredReason   string    `json:"ignored_reason,omitempty"`
	Truncated       bool      `json:"truncated"`
	TruncatedReason string    `json:"truncated_reason,omitempty"`
	RuleCountDelta  int       `json:"rule_count_delta"`
	DownloadedBytes int64     `json:"downloaded_bytes"`
	FinalURL        string    `json:"final_url,omitempty"`
	FinalHostname   string    `json:"final_hostname,omitempty"`
	RedirectCount   int       `json:"redirect_count"`
	Checksum        string    `json:"checksum,omitempty"`
	RollbackCount   int       `json:"rollback_count"`

	// Conditional-GET state (not serialized).
	etag              string
	lastModified      string
	validURL          bool
	allowPrivate      bool
	timeout           time.Duration
	redirectLimit     int
	refreshGeneration string
	refreshAtMinute   int
	lastScheduledDay  string
	history           []ruleSnapshot
}

type ruleSnapshot struct {
	block    []Rule
	allow    []Rule
	checksum string
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
	updateRequests chan struct{}
	updateMu       sync.Mutex
	updateAll      bool
	updateIDs      map[string]struct{}
	onRulesChanged func()
	historyDir     string
}

// SetRulesChangedCallback configures a callback invoked after a successful
// publication changes the active rules. The callback runs without e.mu held.
func (e *Engine) SetRulesChangedCallback(callback func()) {
	e.mu.Lock()
	e.onRulesChanged = callback
	e.mu.Unlock()
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
		updateRequests:   make(chan struct{}, 1),
		updateIDs:        make(map[string]struct{}),
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

// Evaluation describes the effective decision and any allow rule that
// overrides a simultaneous block match.
type Evaluation struct {
	Domain      string `json:"domain"`
	Result      Result `json:"result"`
	AllowRule   string `json:"allow_rule,omitempty"`
	AllowSource string `json:"allow_source,omitempty"`
	BlockRule   string `json:"block_rule,omitempty"`
	BlockSource string `json:"block_source,omitempty"`
	Override    bool   `json:"allowlist_override"`
}

// Explain evaluates one domain without incrementing filter counters.
func (e *Engine) Explain(domain string) Evaluation {
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	evaluation := Evaluation{Domain: domain}
	e.mu.RLock()
	defer e.mu.RUnlock()
	allow, hasAllow := firstIndexedMatch(domain, e.allowDomainIndex, e.allowRegexRules)
	block, hasBlock := firstIndexedMatch(domain, e.blockDomainIndex, e.blockRegexRules)
	if hasAllow {
		evaluation.AllowRule = allow.rule.Raw
		evaluation.AllowSource = allow.source.Name
		evaluation.Result = Result{Allowed: true, Rule: allow.rule.Raw, Source: allow.source.Name}
	}
	if hasBlock {
		evaluation.BlockRule = block.rule.Raw
		evaluation.BlockSource = block.source.Name
		if !hasAllow {
			reason := ReasonBlocklist
			if block.rule.kind == kindRegex {
				reason = ReasonRegex
			}
			evaluation.Result = Result{Blocked: true, Rule: block.rule.Raw, Source: block.source.Name, Reason: reason}
		}
	}
	evaluation.Override = hasAllow && hasBlock
	return evaluation
}

// AllowlistOverrides reports exact allow-domain rules that currently
// suppress a block rule. Regex-only allow rules remain visible through the
// per-domain tester because they cannot be enumerated safely.
func (e *Engine) AllowlistOverrides(limit int) []Evaluation {
	if limit <= 0 {
		limit = 100
	}
	e.mu.RLock()
	domains := make([]string, 0, len(e.allowDomainIndex))
	for domain := range e.allowDomainIndex {
		domains = append(domains, domain)
	}
	e.mu.RUnlock()
	sort.Strings(domains)
	result := make([]Evaluation, 0)
	for _, domain := range domains {
		evaluation := e.Explain(domain)
		if evaluation.Override {
			result = append(result, evaluation)
			if len(result) >= limit {
				break
			}
		}
	}
	return result
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
// preserving local file sources and unchanged URL source state. Call
// UpdateAll after replacement to fetch newly configured subscriptions.
func (e *Engine) ReplaceURLSources(subscriptions []Subscription) {
	e.mu.Lock()

	kept := make([]*Source, 0, len(e.sources)+len(subscriptions))
	refreshIDs := make([]string, 0, len(subscriptions))
	historyIDs := make([]string, 0, len(subscriptions))
	reusable := make(map[string]*Source, len(e.sources))
	for _, src := range e.sources {
		if src.Kind == "url" {
			if src.ID != "" {
				reusable[src.ID] = src
			}
			continue
		}
		kept = append(kept, src)
	}
	for _, subscription := range subscriptions {
		if !subscription.Enabled {
			continue
		}
		src := reusable[subscription.ID]
		if src == nil || !sourceMatchesSubscription(src, subscription) {
			src = newURLSource(subscription)
			refreshIDs = append(refreshIDs, subscription.ID)
			historyIDs = append(historyIDs, subscription.ID)
		} else {
			src.Title = subscription.Name
			src.Enabled = true
			if src.refreshGeneration != subscription.RefreshGeneration {
				src.refreshGeneration = subscription.RefreshGeneration
				refreshIDs = append(refreshIDs, subscription.ID)
			}
			delete(reusable, subscription.ID)
		}
		kept = append(kept, src)
	}
	for _, src := range e.sources {
		if src.Kind == "url" && !slices.Contains(kept, src) {
			delete(e.blockRules, src)
			delete(e.allowRules, src)
		}
	}
	e.sources = kept
	e.rebuildIndexesLocked()
	e.mu.Unlock()
	for _, id := range historyIDs {
		e.loadSourceHistory(id)
	}
	for _, id := range refreshIDs {
		e.requestSourceUpdate(id)
	}
}

func sourceMatchesSubscription(src *Source, subscription Subscription) bool {
	timeout := subscriptionTimeout(subscription.TimeoutSeconds)
	redirectLimit := subscriptionRedirectLimit(subscription.RedirectLimit)
	return src.Name == subscription.URL && src.AllowOnly == subscription.AllowOnly &&
		src.allowPrivate == subscription.AllowPrivate && src.timeout == timeout &&
		src.redirectLimit == redirectLimit && src.refreshAtMinute == refreshAtMinute(subscription.RefreshAtUTC)
}

func refreshAtMinute(value string) int {
	minute, err := parseRefreshAtUTC(value)
	if err != nil {
		return -1
	}
	return minute
}

// setRules atomically swaps the parsed rules of a source and refreshes its
// status (keep-last-good: callers only invoke this on successful loads).
func (e *Engine) setRules(src *Source, block, allow []Rule, loadErr string) {
	e.setRulesStatus(src, block, allow, loadErr, 0, false, 0, "", "", 0)
}

func (e *Engine) setRulesStatus(
	src *Source,
	block, allow []Rule,
	loadErr string,
	ignored int,
	truncated bool,
	downloadedBytes int64,
	finalURL string,
	finalHostname string,
	redirectCount int,
) {
	e.mu.Lock()
	active := false
	for _, current := range e.sources {
		if current == src {
			active = true
			break
		}
	}
	if !active {
		e.mu.Unlock()
		return
	}
	changed := false
	src.LastChecked = time.Now()
	if loadErr == "" {
		previousCount := src.RuleCount + src.AllowRuleCount
		changed = !rulesEqual(e.blockRules[src], block) || !rulesEqual(e.allowRules[src], allow)
		if changed && previousCount > 0 {
			src.history = append(src.history, ruleSnapshot{
				block: slices.Clone(e.blockRules[src]), allow: slices.Clone(e.allowRules[src]), checksum: src.Checksum,
			})
			if len(src.history) > 3 {
				src.history = slices.Clone(src.history[len(src.history)-3:])
			}
		}
		e.blockRules[src] = block
		e.allowRules[src] = allow
		e.rebuildIndexesLocked()
		src.RuleCount = len(block)
		src.AllowRuleCount = len(allow)
		src.RuleCountDelta = len(block) + len(allow) - previousCount
		src.LastUpdate = src.LastChecked
		if changed {
			src.LastChanged = src.LastChecked
		}
		src.IgnoredCount = ignored
		src.IgnoredReason = ""
		if ignored > 0 {
			src.IgnoredReason = "blank, comment, cosmetic, or unsupported lines"
		}
		src.Truncated = truncated
		src.TruncatedReason = ""
		if truncated {
			src.TruncatedReason = "maximum active-rule limit reached; remaining lines were ignored"
		}
		src.DownloadedBytes = downloadedBytes
		src.FinalURL = finalURL
		src.FinalHostname = finalHostname
		src.RedirectCount = redirectCount
		src.Checksum = activeRulesChecksum(block, allow)
		src.RollbackCount = len(src.history)
	}
	src.LastError = loadErr
	callback := e.onRulesChanged
	sourceID := src.ID
	notify := changed && src.Kind == "url"
	e.mu.Unlock()
	if notify {
		e.persistSourceHistory(sourceID)
		if callback != nil {
			callback()
		}
	}
}

// RollbackSource restores the most recent successful rules retained in
// memory. At most three versions are retained per active source.
func (e *Engine) RollbackSource(id string) error {
	e.mu.Lock()
	for _, src := range e.sources {
		if src.Kind != "url" || src.ID != id {
			continue
		}
		if len(src.history) == 0 {
			e.mu.Unlock()
			return fmt.Errorf("subscription %q has no rollback snapshot", id)
		}
		index := len(src.history) - 1
		snapshot := src.history[index]
		src.history = slices.Clone(src.history[:index])
		previousCount := src.RuleCount + src.AllowRuleCount
		e.blockRules[src] = slices.Clone(snapshot.block)
		e.allowRules[src] = slices.Clone(snapshot.allow)
		src.RuleCount = len(snapshot.block)
		src.AllowRuleCount = len(snapshot.allow)
		src.RuleCountDelta = src.RuleCount + src.AllowRuleCount - previousCount
		src.Checksum = snapshot.checksum
		src.LastChanged = time.Now()
		src.LastUpdate = src.LastChanged
		src.LastChecked = src.LastChanged
		src.LastError = ""
		src.RollbackCount = len(src.history)
		e.rebuildIndexesLocked()
		callback := e.onRulesChanged
		e.mu.Unlock()
		e.persistSourceHistory(id)
		if callback != nil {
			callback()
		}
		return nil
	}
	e.mu.Unlock()
	return fmt.Errorf("subscription %q was not found", id)
}

func activeRulesChecksum(block, allow []Rule) string {
	hash := sha256.New()
	for _, rule := range block {
		_, _ = hash.Write([]byte("block\x00" + rule.Raw + "\n"))
	}
	for _, rule := range allow {
		_, _ = hash.Write([]byte("allow\x00" + rule.Raw + "\n"))
	}
	return hex.EncodeToString(hash.Sum(nil))
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

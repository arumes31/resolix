package filter

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"slices"
)

const (
	ruleHistoryVersion  = 1
	maxRuleHistoryBytes = 4 << 20
)

type persistedRuleSnapshot struct {
	Block    []string `json:"block"`
	Allow    []string `json:"allow"`
	Checksum string   `json:"checksum"`
}

type persistedRuleHistory struct {
	Version  int    `json:"version"`
	SourceID string `json:"source_id"`
	// AllowOnly binds the history to the policy its rules were classified
	// under, so it is never restored into a source whose policy differs.
	AllowOnly bool                    `json:"allow_only,omitempty"`
	Snapshots []persistedRuleSnapshot `json:"snapshots"`
}

// SetHistoryDir enables bounded, restart-safe last-good rule history.
func (e *Engine) SetHistoryDir(dir string) {
	if dir == "" {
		e.mu.Lock()
		e.historyDir = ""
		e.mu.Unlock()
		return
	}
	dir = filepath.Clean(dir)
	e.mu.RLock()
	ids := make(map[string]bool, len(e.sources))
	for _, src := range e.sources {
		if src.Kind == "url" && src.ID != "" {
			ids[src.ID] = src.AllowOnly
		}
	}
	e.mu.RUnlock()
	loaded := make(map[string][]ruleSnapshot, len(ids))
	for id, allowOnly := range ids {
		if history, ok := readSourceHistory(dir, id, allowOnly); ok {
			loaded[id] = history
		}
	}
	e.mu.Lock()
	e.historyDir = dir
	for _, src := range e.sources {
		if history, ok := loaded[src.ID]; ok && len(src.history) == 0 && ids[src.ID] == src.AllowOnly {
			src.history = history
			src.RollbackCount = len(history)
		}
	}
	e.mu.Unlock()
}

func ruleHistoryPath(dir, id string) string {
	sum := sha256.Sum256([]byte(id))
	return filepath.Join(dir, hex.EncodeToString(sum[:])+".json")
}

func (e *Engine) persistSourceHistory(id string) {
	if id == "" {
		return
	}
	e.mu.RLock()
	dir := e.historyDir
	var snapshots []ruleSnapshot
	allowOnly := false
	for _, src := range e.sources {
		if src.ID == id {
			snapshots = slices.Clone(src.history)
			allowOnly = src.AllowOnly
			break
		}
	}
	e.mu.RUnlock()
	if dir == "" {
		return
	}
	document := persistedRuleHistory{Version: ruleHistoryVersion, SourceID: id, AllowOnly: allowOnly}
	for _, snapshot := range snapshots {
		item := persistedRuleSnapshot{Checksum: snapshot.checksum}
		for _, rule := range snapshot.block {
			item.Block = append(item.Block, rule.Raw)
		}
		for _, rule := range snapshot.allow {
			item.Allow = append(item.Allow, rule.Raw)
		}
		document.Snapshots = append(document.Snapshots, item)
	}
	data, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		log.Printf("[WARN] filter: encode rule rollback history: %v", err)
		return
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		log.Printf("[WARN] filter: create rule rollback directory: %v", err)
		return
	}
	if err := writeSubscriptionsAtomic(ruleHistoryPath(dir, id), data); err != nil {
		log.Printf("[WARN] filter: persist rule rollback history: %v", err)
	}
}

func (e *Engine) loadSourceHistory(id string) {
	e.mu.RLock()
	dir := e.historyDir
	allowOnly := false
	for _, src := range e.sources {
		if src.Kind == "url" && src.ID == id {
			allowOnly = src.AllowOnly
			break
		}
	}
	e.mu.RUnlock()
	if dir == "" {
		return
	}
	history, ok := readSourceHistory(dir, id, allowOnly)
	if !ok {
		return
	}
	e.mu.Lock()
	for _, src := range e.sources {
		if src.Kind == "url" && src.ID == id && src.AllowOnly == allowOnly {
			src.history = history
			src.RollbackCount = len(history)
			break
		}
	}
	e.mu.Unlock()
}

func readSourceHistory(dir, id string, allowOnly bool) ([]ruleSnapshot, bool) {
	file, err := os.Open(ruleHistoryPath(dir, id)) // #nosec G304 -- hashed filename below trusted state directory
	if err != nil {
		return nil, false
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxRuleHistoryBytes {
		return nil, false
	}
	decoder := json.NewDecoder(file)
	var document persistedRuleHistory
	if err := decoder.Decode(&document); err != nil || document.Version != ruleHistoryVersion || document.SourceID != id ||
		document.AllowOnly != allowOnly {
		return nil, false
	}
	if len(document.Snapshots) > 3 {
		document.Snapshots = document.Snapshots[len(document.Snapshots)-3:]
	}
	history := make([]ruleSnapshot, 0, len(document.Snapshots))
	for _, item := range document.Snapshots {
		snapshot := ruleSnapshot{checksum: item.Checksum}
		if allowOnly && len(item.Block) > 0 {
			return nil, false
		}
		if !decodeHistoryRules(item.Block, false, false, &snapshot.block) ||
			!decodeHistoryRules(item.Allow, true, allowOnly, &snapshot.allow) {
			return nil, false
		}
		history = append(history, snapshot)
	}
	return history, true
}

// decodeHistoryRules parses persisted rules for one bucket. Exception-only
// sources classify every rule as an allow rule, so their allow bucket accepts
// rules without the @@ prefix.
func decodeHistoryRules(rawRules []string, wantAllow, allowOnly bool, destination *[]Rule) bool {
	for _, raw := range rawRules {
		rule, allow, ok := parseLine(raw)
		if !ok || (allow != wantAllow && (!wantAllow || !allowOnly)) {
			return false
		}
		*destination = append(*destination, rule)
	}
	return true
}

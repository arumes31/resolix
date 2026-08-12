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
	Version   int                     `json:"version"`
	SourceID  string                  `json:"source_id"`
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
	ids := make([]string, 0, len(e.sources))
	for _, src := range e.sources {
		if src.Kind == "url" && src.ID != "" {
			ids = append(ids, src.ID)
		}
	}
	e.mu.RUnlock()
	loaded := make(map[string][]ruleSnapshot, len(ids))
	for _, id := range ids {
		if history, ok := readSourceHistory(dir, id); ok {
			loaded[id] = history
		}
	}
	e.mu.Lock()
	e.historyDir = dir
	for _, src := range e.sources {
		if history, ok := loaded[src.ID]; ok && len(src.history) == 0 {
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
	for _, src := range e.sources {
		if src.ID == id {
			snapshots = slices.Clone(src.history)
			break
		}
	}
	e.mu.RUnlock()
	if dir == "" {
		return
	}
	document := persistedRuleHistory{Version: ruleHistoryVersion, SourceID: id}
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
	e.mu.RUnlock()
	if dir == "" {
		return
	}
	history, ok := readSourceHistory(dir, id)
	if !ok {
		return
	}
	e.mu.Lock()
	for _, src := range e.sources {
		if src.Kind == "url" && src.ID == id {
			src.history = history
			src.RollbackCount = len(history)
			break
		}
	}
	e.mu.Unlock()
}

func readSourceHistory(dir, id string) ([]ruleSnapshot, bool) {
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
	if err := decoder.Decode(&document); err != nil || document.Version != ruleHistoryVersion || document.SourceID != id {
		return nil, false
	}
	if len(document.Snapshots) > 3 {
		document.Snapshots = document.Snapshots[len(document.Snapshots)-3:]
	}
	history := make([]ruleSnapshot, 0, len(document.Snapshots))
	for _, item := range document.Snapshots {
		snapshot := ruleSnapshot{checksum: item.Checksum}
		if !decodeHistoryRules(item.Block, false, &snapshot.block) || !decodeHistoryRules(item.Allow, true, &snapshot.allow) {
			return nil, false
		}
		history = append(history, snapshot)
	}
	return history, true
}

func decodeHistoryRules(rawRules []string, wantAllow bool, destination *[]Rule) bool {
	for _, raw := range rawRules {
		rule, allow, ok := parseLine(raw)
		if !ok || allow != wantAllow {
			return false
		}
		*destination = append(*destination, rule)
	}
	return true
}

package filter

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

const (
	// maxFetchBytes caps the size of a downloaded subscription (20MB).
	maxFetchBytes = 20 << 20
	// maxRulesPerSource caps parsed rules per source to bound memory.
	maxRulesPerSource = 500000
	// fetchTimeout bounds a single subscription download.
	fetchTimeout = 30 * time.Second
)

// AddFileSource registers a local file source and loads it immediately.
// allowOnly sources contribute exceptions only (ALLOWLIST_FILE).
func (e *Engine) AddFileSource(path string, allowOnly bool) *Source {
	src := &Source{Name: path, Kind: "file", AllowOnly: allowOnly}
	e.mu.Lock()
	e.sources = append(e.sources, src)
	e.mu.Unlock()
	e.loadFileSource(src)
	return src
}

// AddURLSource registers a remote subscription source. The initial fetch
// happens on the first UpdateAll/StartUpdateLoop pass.
// allowOnly sources contribute exceptions only (ALLOWLIST_URLS).
func (e *Engine) AddURLSource(rawurl string, allowOnly bool) *Source {
	src := &Source{Name: rawurl, Kind: "url", AllowOnly: allowOnly}
	e.mu.Lock()
	e.sources = append(e.sources, src)
	e.mu.Unlock()
	return src
}

// loadFileSource reads and parses a local file source.
func (e *Engine) loadFileSource(src *Source) {
	f, err := os.Open(src.Name) // #nosec G304 -- filter list path comes from trusted config (env/defaults), not request input
	if err != nil {
		e.setRules(src, nil, nil, err.Error())
		log.Printf("[WARN] filter: cannot open %s: %v", src.Name, err)
		return
	}
	defer func() { _ = f.Close() }()

	block, allow := parseRules(f, src.AllowOnly)
	e.setRules(src, block, allow, "")
	log.Printf("[INFO] filter: loaded %d rules (%d exceptions) from %s", len(block), len(allow), src.Name)
}

// LoadLocal reloads all local file sources.
func (e *Engine) LoadLocal() {
	for _, src := range e.Sources() {
		if src.Kind == "file" {
			e.loadFileSource(e.findSource(src.Name))
		}
	}
}

// findSource returns the internal source pointer by name.
func (e *Engine) findSource(name string) *Source {
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, src := range e.sources {
		if src.Name == name {
			return src
		}
	}
	return nil
}

// UpdateAll fetches every URL subscription once (conditional GET).
func (e *Engine) UpdateAll() {
	e.mu.RLock()
	urls := make([]*Source, 0, len(e.sources))
	for _, src := range e.sources {
		if src.Kind == "url" {
			urls = append(urls, src)
		}
	}
	e.mu.RUnlock()

	for _, src := range urls {
		e.fetchSource(src)
	}
}

// fetchSource downloads a subscription with ETag/Last-Modified conditional
// GET. On 304 the existing rules are kept; on 200 the rules are parsed and
// atomically swapped; on any error the last good rules are kept.
func (e *Engine) fetchSource(src *Source) {
	client := &http.Client{Timeout: fetchTimeout}
	req, err := http.NewRequest(http.MethodGet, src.Name, nil)
	if err != nil {
		e.setRules(src, nil, nil, err.Error())
		return
	}
	e.mu.RLock()
	if src.etag != "" {
		req.Header.Set("If-None-Match", src.etag)
	}
	if src.lastModified != "" {
		req.Header.Set("If-Modified-Since", src.lastModified)
	}
	e.mu.RUnlock()

	resp, err := client.Do(req)
	if err != nil {
		e.setRules(src, nil, nil, err.Error())
		log.Printf("[WARN] filter: update failed for %s (keeping last good): %v", src.Name, err)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotModified {
		e.mu.Lock()
		src.LastUpdate = time.Now()
		e.mu.Unlock()
		log.Printf("[DEBUG] filter: %s not modified (304)", src.Name)
		return
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		err = fmt.Errorf("unexpected status %d", resp.StatusCode)
		e.setRules(src, nil, nil, err.Error())
		log.Printf("[WARN] filter: update failed for %s (keeping last good): %v", src.Name, err)
		return
	}

	block, allow, readErr := parseRulesCapped(io.LimitReader(resp.Body, maxFetchBytes), src.AllowOnly)
	if readErr != nil {
		e.setRules(src, nil, nil, readErr.Error())
		log.Printf("[WARN] filter: parse failed for %s (keeping last good): %v", src.Name, readErr)
		return
	}

	e.mu.Lock()
	src.etag = resp.Header.Get("ETag")
	src.lastModified = resp.Header.Get("Last-Modified")
	e.mu.Unlock()
	e.setRules(src, block, allow, "")
	log.Printf("[INFO] filter: updated %s — %d rules (%d exceptions)", src.Name, len(block), len(allow))
}

// StartUpdateLoop performs an initial update of all sources and then
// refreshes URL subscriptions on the given interval until ctx is canceled.
func (e *Engine) StartUpdateLoop(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 24 * time.Hour
	}
	go func() {
		e.LoadLocal()
		e.UpdateAll()

		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				e.LoadLocal()
				e.UpdateAll()
			}
		}
	}()
}

// parseRules parses all rule lines from r.
func parseRules(r io.Reader, allowOnly bool) (block, allow []Rule) {
	block, allow, _ = parseRulesCapped(r, allowOnly)
	return block, allow
}

// parseRulesCapped parses rule lines with a per-source rule cap.
func parseRulesCapped(r io.Reader, allowOnly bool) (block, allow []Rule, err error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024) // tolerate long lines up to 1MB
	count := 0
	for scanner.Scan() {
		rule, exception, ok := parseLine(scanner.Text())
		if !ok {
			continue
		}
		count++
		if count > maxRulesPerSource {
			log.Printf("[WARN] filter: rule cap (%d) reached, ignoring remaining rules", maxRulesPerSource)
			break
		}
		if exception || allowOnly {
			allow = append(allow, rule)
		} else {
			block = append(block, rule)
		}
	}
	if scanErr := scanner.Err(); scanErr != nil {
		return block, allow, fmt.Errorf("read rules: %w", scanErr)
	}
	return block, allow, nil
}

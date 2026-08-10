package filter

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"sync"
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
	src := &Source{Name: rawurl, Kind: "url", AllowOnly: allowOnly, validURL: true}
	u, err := url.Parse(rawurl)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
		src.validURL = false
		src.LastError = "invalid URL: only http/https without embedded credentials is allowed"
	}
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

// ReloadSource re-reads one file source by name (used after user-rule edits
// via the query-log block/unblock actions).
func (e *Engine) ReloadSource(name string) {
	if src := e.findSource(name); src != nil && src.Kind == "file" {
		e.loadFileSource(src)
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

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 4)
	for _, src := range urls {
		if !src.validURL {
			continue
		}
		wg.Add(1)
		go func(source *Source) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			e.fetchSource(source)
		}(src)
	}
	wg.Wait()
}

// fetchSource downloads a subscription with ETag/Last-Modified conditional
// GET. On 304 the existing rules are kept; on 200 the rules are parsed and
// atomically swapped; on any error the last good rules are kept.
func (e *Engine) fetchSource(src *Source) {
	logName := sourceLogName(src)
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

	resp, err := e.httpClient.Do(req)
	if err != nil {
		e.setRules(src, nil, nil, "request failed")
		log.Printf("[WARN] filter: update request failed for %s (keeping last good)", logName)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotModified {
		e.mu.Lock()
		src.LastChecked = time.Now()
		src.LastError = ""
		e.mu.Unlock()
		log.Printf("[DEBUG] filter: %s not modified (304)", logName)
		return
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		err = fmt.Errorf("unexpected status %d", resp.StatusCode)
		e.setRules(src, nil, nil, err.Error())
		log.Printf("[WARN] filter: update failed for %s (keeping last good): %v", logName, err)
		return
	}

	counter := &countingReader{r: io.LimitReader(resp.Body, int64(maxFetchBytes)+1)}
	body, readErr := io.ReadAll(counter)
	if readErr != nil {
		e.setSourceError(src, readErr.Error())
		log.Printf("[WARN] filter: parse failed for %s (keeping last good): %v", logName, readErr)
		return
	}
	if counter.n > maxFetchBytes {
		readErr = fmt.Errorf("subscription exceeds %d-byte limit", maxFetchBytes)
		e.setSourceError(src, readErr.Error())
		log.Printf("[WARN] filter: update failed for %s (keeping last good): %v", logName, readErr)
		return
	}
	block, allow, ignored, truncated, readErr := parseRulesCapped(bytes.NewReader(body), src.AllowOnly)
	if readErr != nil {
		e.setSourceError(src, readErr.Error())
		log.Printf("[WARN] filter: parse failed for %s (keeping last good): %v", logName, readErr)
		return
	}

	e.mu.Lock()
	src.etag = resp.Header.Get("ETag")
	src.lastModified = resp.Header.Get("Last-Modified")
	e.mu.Unlock()
	e.setRulesStatus(src, block, allow, "", ignored, truncated)
	log.Printf("[INFO] filter: updated %s — %d rules (%d exceptions)", logName, len(block), len(allow))
}

func sourceLogName(src *Source) string {
	if src.Kind != "url" {
		return src.Name
	}
	u, err := url.Parse(src.Name)
	if err != nil {
		return "subscription"
	}
	u.RawQuery = ""
	u.Fragment = ""
	return u.Redacted()
}

type countingReader struct {
	r io.Reader
	n int64
}

func (r *countingReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	r.n += int64(n)
	return n, err
}

// StartUpdateLoop performs an initial update of all sources and then
// refreshes URL subscriptions on the given interval until ctx is canceled.
func (e *Engine) StartUpdateLoop(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 24 * time.Hour
	}
	go func() {
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
	block, allow, _, _, _ = parseRulesCapped(r, allowOnly)
	return block, allow
}

// parseRulesCapped parses rule lines with a per-source rule cap.
func parseRulesCapped(r io.Reader, allowOnly bool) (block, allow []Rule, ignored int, truncated bool, err error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024) // tolerate long lines up to 1MB
	count := 0
	for scanner.Scan() {
		rule, exception, ok := parseLine(scanner.Text())
		if !ok {
			ignored++
			continue
		}
		count++
		if count > maxRulesPerSource {
			log.Printf("[WARN] filter: rule cap (%d) reached, ignoring remaining rules", maxRulesPerSource)
			truncated = true
			break
		}
		if exception || allowOnly {
			allow = append(allow, rule)
		} else {
			block = append(block, rule)
		}
	}
	if scanErr := scanner.Err(); scanErr != nil {
		return block, allow, ignored, truncated, fmt.Errorf("read rules: %w", scanErr)
	}
	return block, allow, ignored, truncated, nil
}

package filter

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	// maxFetchBytes caps the bytes inspected from a downloaded subscription.
	maxFetchBytes = 64 << 20
	// maxRulesPerSource caps parsed rules per source to bound memory.
	maxRulesPerSource = 2000000
	// fetchTimeout bounds a single subscription download.
	fetchTimeout = time.Duration(defaultSubscriptionTimeout) * time.Second
)

var blockedSubscriptionNetworks = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001:2::/48"),
	netip.MustParsePrefix("2001:db8::/32"),
}

// AddFileSource registers a local file source and loads it immediately.
// allowOnly sources contribute exceptions only (ALLOWLIST_FILE).
func (e *Engine) AddFileSource(path string, allowOnly bool) *Source {
	src := &Source{Name: path, Kind: "file", AllowOnly: allowOnly, Enabled: true}
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
	// Environment-provided legacy URL sources are trusted operator configuration.
	// Managed GUI subscriptions remain private-network blocked by default.
	src := newURLSource(Subscription{
		URL: rawurl, AllowOnly: allowOnly, Enabled: true, AllowPrivate: true,
	})
	e.mu.Lock()
	e.sources = append(e.sources, src)
	e.mu.Unlock()
	return src
}

// AddURLSourceWithOptions registers a URL source with explicit network
// safety and download controls.
func (e *Engine) AddURLSourceWithOptions(subscription Subscription) *Source {
	src := newURLSource(subscription)
	e.mu.Lock()
	e.sources = append(e.sources, src)
	e.mu.Unlock()
	return src
}

func newURLSource(subscription Subscription) *Source {
	timeout := subscriptionTimeout(subscription.TimeoutSeconds)
	src := &Source{
		ID:                subscription.ID,
		Title:             subscription.Name,
		Name:              subscription.URL,
		Kind:              "url",
		AllowOnly:         subscription.AllowOnly,
		Enabled:           subscription.Enabled,
		validURL:          true,
		allowPrivate:      subscription.AllowPrivate,
		timeout:           timeout,
		redirectLimit:     subscriptionRedirectLimit(subscription.RedirectLimit),
		refreshGeneration: subscription.RefreshGeneration,
		refreshAtMinute:   refreshAtMinute(subscription.RefreshAtUTC),
	}
	rawurl := subscription.URL
	u, err := url.Parse(rawurl)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
		src.validURL = false
		src.LastError = "invalid URL: only http/https without embedded credentials is allowed"
	}
	return src
}

func subscriptionTimeout(seconds int) time.Duration {
	if seconds <= 0 {
		return fetchTimeout
	}
	return time.Duration(seconds) * time.Second
}

func subscriptionRedirectLimit(limit int) int {
	if limit <= 0 {
		return defaultSubscriptionRedirects
	}
	return limit
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
	e.beginRuleUpdateBatch()
	defer e.endRuleUpdateBatch()
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
func (e *Engine) UpdateAll(ctx context.Context) {
	e.updateSources(ctx, nil)
}

func (e *Engine) updateSources(ctx context.Context, ids map[string]struct{}) {
	e.updateMatchingSources(ctx, func(src *Source) bool {
		return ids == nil || sourceIDSelected(ids, src.ID)
	})
}

func (e *Engine) updateMatchingSources(ctx context.Context, selected func(*Source) bool) {
	e.mu.RLock()
	urls := make([]*Source, 0, len(e.sources))
	for _, src := range e.sources {
		if src.Kind == "url" && selected(src) {
			urls = append(urls, src)
		}
	}
	e.mu.RUnlock()
	e.updateSourceList(ctx, urls)
}

func (e *Engine) updateSourceList(ctx context.Context, urls []*Source) {
	if len(urls) == 0 {
		return
	}
	e.beginRuleUpdateBatch()
	defer e.endRuleUpdateBatch()
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 4)
	for _, src := range urls {
		if !src.validURL {
			continue
		}
		wg.Add(1)
		go func(source *Source) {
			defer wg.Done()
			select {
			case semaphore <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-semaphore }()
			e.fetchSource(ctx, source)
		}(src)
	}
	wg.Wait()
}

func (e *Engine) updateIntervalSources(ctx context.Context) {
	e.updateMatchingSources(ctx, func(src *Source) bool { return src.refreshAtMinute < 0 })
}

func (e *Engine) updateScheduledSources(ctx context.Context, now time.Time) {
	now = now.UTC()
	minute := now.Hour()*60 + now.Minute()
	day := now.Format(time.DateOnly)
	e.mu.Lock()
	urls := make([]*Source, 0, len(e.sources))
	for _, src := range e.sources {
		if src.Kind != "url" || src.refreshAtMinute < 0 || minute < src.refreshAtMinute || src.lastScheduledDay == day {
			continue
		}
		// Claim the UTC schedule slot before fetching so overlapping ticks cannot
		// start the same source twice. A failed attempt still counts as today's
		// scheduled check, matching LastChecked's previous behavior.
		src.lastScheduledDay = day
		urls = append(urls, src)
	}
	e.mu.Unlock()
	e.updateSourceList(ctx, urls)
}

func (e *Engine) seedScheduledSourcesCheckedToday(now time.Time) {
	day := now.UTC().Format(time.DateOnly)
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, src := range e.sources {
		if src.Kind == "url" && src.refreshAtMinute >= 0 && src.LastChecked.UTC().Format(time.DateOnly) == day {
			src.lastScheduledDay = day
		}
	}
}

func sourceIDSelected(ids map[string]struct{}, id string) bool {
	_, selected := ids[id]
	return selected
}

// RequestUpdate asks the owned update loop to refresh URL subscriptions. It
// coalesces bursts so configuration changes do not wait on remote servers.
func (e *Engine) RequestUpdate() {
	e.updateMu.Lock()
	e.updateAll = true
	clear(e.updateIDs)
	e.updateMu.Unlock()
	e.signalUpdate()
}

func (e *Engine) requestSourceUpdate(id string) {
	if id == "" {
		return
	}
	e.updateMu.Lock()
	if !e.updateAll {
		e.updateIDs[id] = struct{}{}
	}
	e.updateMu.Unlock()
	e.signalUpdate()
}

// RequestSourceUpdate asks the owned update loop to refresh one URL source.
func (e *Engine) RequestSourceUpdate(id string) {
	e.requestSourceUpdate(id)
}

func (e *Engine) signalUpdate() {
	select {
	case e.updateRequests <- struct{}{}:
	default:
	}
}

func (e *Engine) takeUpdateRequest() (bool, map[string]struct{}) {
	e.updateMu.Lock()
	defer e.updateMu.Unlock()
	all := e.updateAll
	ids := e.updateIDs
	e.updateAll = false
	e.updateIDs = make(map[string]struct{})
	return all, ids
}

// fetchSource downloads a subscription with ETag/Last-Modified conditional
// GET. On 304 the existing rules are kept; on 200 the rules are parsed and
// atomically swapped; on any error the last good rules are kept.
func (e *Engine) fetchSource(ctx context.Context, src *Source) {
	logName := sourceLogName(src)
	fetchCtx, cancel := context.WithTimeout(ctx, src.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(fetchCtx, http.MethodGet, src.Name, nil)
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

	client, redirectCount := subscriptionHTTPClient(src)
	resp, err := client.Do(req)
	if err != nil {
		message := safeSubscriptionFetchError(err)
		e.setSourceError(src, message)
		log.Printf("[WARN] filter: update request failed for %s (keeping last good): %s", logName, message)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotModified {
		e.mu.Lock()
		src.LastChecked = time.Now()
		src.LastError = ""
		src.RuleCountDelta = 0
		src.FinalURL = sanitizedSubscriptionURL(resp.Request.URL)
		src.FinalHostname = strings.ToLower(resp.Request.URL.Hostname())
		src.RedirectCount = *redirectCount
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
	block, allow, ignored, truncated, readErr := parseRulesCapped(counter, src.AllowOnly)
	if counter.n > maxFetchBytes {
		readErr = fmt.Errorf("subscription exceeds %d-byte limit", maxFetchBytes)
		e.setSourceError(src, readErr.Error())
		log.Printf("[WARN] filter: update failed for %s (keeping last good): %v", logName, readErr)
		return
	}
	if readErr != nil {
		e.setSourceError(src, readErr.Error())
		log.Printf("[WARN] filter: parse failed for %s (keeping last good): %v", logName, readErr)
		return
	}

	e.mu.Lock()
	src.etag = resp.Header.Get("ETag")
	src.lastModified = resp.Header.Get("Last-Modified")
	e.mu.Unlock()
	e.setRulesStatus(
		src,
		block,
		allow,
		"",
		ignored,
		truncated,
		counter.n,
		sanitizedSubscriptionURL(resp.Request.URL),
		strings.ToLower(resp.Request.URL.Hostname()),
		*redirectCount,
	)
	log.Printf("[INFO] filter: updated %s — %d rules (%d exceptions)", logName, len(block), len(allow))
}

func safeSubscriptionFetchError(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "download timed out"
	}
	message := strings.ToLower(err.Error())
	switch {
	case strings.Contains(message, "blocked address"):
		return "blocked by private-network download protection"
	case strings.Contains(message, "redirect limit"):
		return "redirect limit exceeded"
	case strings.Contains(message, "downgrade redirect"):
		return "insecure redirect blocked"
	case strings.Contains(message, "certificate"), strings.Contains(message, "tls"):
		return "TLS validation failed"
	default:
		return "request failed"
	}
}

func sanitizedSubscriptionURL(value *url.URL) string {
	if value == nil {
		return ""
	}
	copy := *value
	copy.RawQuery = ""
	copy.Fragment = ""
	copy.User = nil
	return copy.String()
}

func subscriptionHTTPClient(src *Source) (*http.Client, *int) {
	redirectCount := 0
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           secureSubscriptionDialer(src.allowPrivate),
		DisableKeepAlives:     true,
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   src.timeout,
		ResponseHeaderTimeout: src.timeout,
	}
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			if len(via) > src.redirectLimit {
				return fmt.Errorf("subscription redirect limit (%d) exceeded", src.redirectLimit)
			}
			if len(via) > 0 && via[0].URL.Scheme == "https" && request.URL.Scheme != "https" {
				return errors.New("subscription HTTPS downgrade redirect blocked")
			}
			if _, err := normalizeSubscriptionURL(request.URL.String()); err != nil {
				return fmt.Errorf("invalid subscription redirect: %w", err)
			}
			redirectCount = len(via)
			return nil
		},
	}
	return client, &redirectCount
}

func secureSubscriptionDialer(allowPrivate bool) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, fmt.Errorf("split subscription address: %w", err)
		}
		addresses, err := resolveSubscriptionHost(ctx, host, port, allowPrivate)
		if err != nil {
			return nil, err
		}
		dialer := net.Dialer{}
		var lastErr error
		for _, candidate := range addresses {
			connection, dialErr := dialer.DialContext(ctx, network, candidate)
			if dialErr == nil {
				return connection, nil
			}
			lastErr = dialErr
		}
		return nil, fmt.Errorf("dial subscription endpoint: %w", lastErr)
	}
}

func resolveSubscriptionHost(ctx context.Context, host, port string, allowPrivate bool) ([]string, error) {
	var addresses []netip.Addr
	if literal, err := netip.ParseAddr(host); err == nil {
		addresses = []netip.Addr{literal.Unmap()}
	} else {
		resolved, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, fmt.Errorf("resolve subscription host: %w", err)
		}
		addresses = make([]netip.Addr, 0, len(resolved))
		for _, address := range resolved {
			addresses = append(addresses, address.Unmap())
		}
	}
	if len(addresses) == 0 {
		return nil, errors.New("subscription host resolved to no addresses")
	}
	candidates := make([]string, 0, len(addresses))
	seen := make(map[netip.Addr]struct{}, len(addresses))
	for _, address := range addresses {
		if !allowPrivate && !publicSubscriptionAddress(address) {
			return nil, fmt.Errorf("subscription host resolves to blocked address %s", address)
		}
		if _, exists := seen[address]; exists {
			continue
		}
		seen[address] = struct{}{}
		candidates = append(candidates, net.JoinHostPort(address.String(), port))
	}
	return candidates, nil
}

func publicSubscriptionAddress(address netip.Addr) bool {
	if !address.IsValid() || !address.IsGlobalUnicast() || address.IsPrivate() ||
		address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsMulticast() || address.IsUnspecified() {
		return false
	}
	for _, blocked := range blockedSubscriptionNetworks {
		if blocked.Contains(address) {
			return false
		}
	}
	return true
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
		// The initial pass covers sources queued while configuration was loaded.
		_, _ = e.takeUpdateRequest()
		select {
		case <-e.updateRequests:
		default:
		}
		e.UpdateAll(ctx)
		e.seedScheduledSourcesCheckedToday(time.Now())

		ticker := time.NewTicker(interval)
		scheduleTicker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		defer scheduleTicker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-e.updateRequests:
				all, ids := e.takeUpdateRequest()
				if all {
					e.UpdateAll(ctx)
				} else if len(ids) > 0 {
					e.updateSources(ctx, ids)
				}
			case <-ticker.C:
				e.LoadLocal()
				e.updateIntervalSources(ctx)
			case now := <-scheduleTicker.C:
				e.updateScheduledSources(ctx, now)
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

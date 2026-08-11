package health

import (
	"context"
	"log"
	"math/rand/v2"
	"strings"
	"sync"
	"time"

	"github.com/arumes31/resolix/webgui/internal/config"
	"github.com/arumes31/resolix/webgui/internal/upstream"
)

const (
	healthProbeTimeout     = 10 * time.Second
	bootstrapLabel         = "Bootstrap · "
	healthFailureThreshold = 3
	healthSuccessThreshold = 2
)

type probeState struct {
	consecutiveFailures  int
	consecutiveSuccesses int
	lastFailure          string
}

type probeTarget struct {
	key       string
	server    string
	bootstrap bool
}

type probeResult struct {
	ok  bool
	lat float64
	err error
}

// UpstreamStatus is a detailed health view suitable for diagnostics.
type UpstreamStatus struct {
	Healthy              bool    `json:"healthy"`
	LatencyMS            float64 `json:"latency_ms"`
	ConsecutiveFailures  int     `json:"consecutive_failures"`
	ConsecutiveSuccesses int     `json:"consecutive_successes"`
	LastFailure          string  `json:"last_failure,omitempty"`
}

// Checker monitors the health of upstream DNS servers.
type Checker struct {
	cfg              *config.Config
	upstreams        []string
	bootstrapServers []string
	healthy          []string
	latencies        map[string]float64
	probeFn          func(context.Context, string, string) error
	states           map[string]*probeState
	mu               sync.RWMutex
}

// NewChecker initializes a new upstream health checker.
func NewChecker(cfg *config.Config, upstreamDNS string, bootstrapServers []string) *Checker {
	servers := strings.Fields(upstreamDNS)
	if len(servers) == 0 {
		servers = []string{"8.8.8.8", "8.8.4.4"}
	}
	c := &Checker{
		cfg:              cfg,
		upstreams:        servers,
		bootstrapServers: append([]string(nil), bootstrapServers...),
		healthy:          servers,
		latencies:        make(map[string]float64),
		states:           make(map[string]*probeState),
	}
	for _, server := range servers {
		c.latencies[server] = -1
	}
	return c
}

// CheckUpstream verifies if a specific DNS server is responsive and measures latency.
func (c *Checker) CheckUpstream(ctx context.Context, server string) (bool, float64) {
	ok, latency, _ := c.checkUpstreamDetailed(ctx, server)
	return ok, latency
}

func (c *Checker) checkUpstreamDetailed(ctx context.Context, server string) (bool, float64, error) {
	c.mu.RLock()
	bootstrapServers := append([]string(nil), c.bootstrapServers...)
	probeFn := c.probeFn
	c.mu.RUnlock()
	probeCtx, cancel := context.WithTimeout(ctx, healthProbeTimeout)
	defer cancel()
	start := time.Now()
	var err error
	if probeFn != nil {
		err = probeFn(probeCtx, server, c.cfg.HealthDomain)
	} else {
		err = upstream.Probe(probeCtx, server, c.cfg.HealthDomain, bootstrapServers)
	}
	if err != nil {
		return false, -1, err
	}
	return true, float64(time.Since(start).Microseconds()) / 1000.0, nil
}

func (c *Checker) checkBootstrap(ctx context.Context, server, upstreamHost string) (bool, float64) {
	probeCtx, cancel := context.WithTimeout(ctx, healthProbeTimeout)
	defer cancel()
	start := time.Now()
	if err := upstream.Probe(probeCtx, server, upstreamHost, nil); err != nil {
		return false, -1
	}
	return true, float64(time.Since(start).Microseconds()) / 1000.0
}

// SetProbeFunc makes health checks use the application pool's live resolver
// instances. It is installed after the pool is initialized.
func (c *Checker) SetProbeFunc(fn func(context.Context, string, string) error) {
	c.mu.Lock()
	c.probeFn = fn
	c.mu.Unlock()
}

// UpdateBootstrapServers replaces the resolvers used for hostname-based DoT
// and DoH health probes.
func (c *Checker) UpdateBootstrapServers(servers []string) {
	c.mu.Lock()
	c.bootstrapServers = append([]string(nil), servers...)
	c.mu.Unlock()
}

// UpdateUpstreams replaces the probe target set after a hot reload.
func (c *Checker) UpdateUpstreams(servers []string) {
	servers = append([]string(nil), servers...)
	c.mu.Lock()
	c.upstreams = servers
	c.healthy = retainServers(c.healthy, serverSet(servers))
	if len(c.healthy) == 0 {
		c.healthy = append([]string(nil), servers...)
	}
	c.mu.Unlock()
}

// Start begins the health check loop.
func (c *Checker) Start(ctx context.Context, onChange func([]string, map[string]float64)) {
	c.runChecks(ctx, onChange)
	timer := time.NewTimer(nextHealthInterval())
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			c.runChecks(ctx, onChange)
			timer.Reset(nextHealthInterval())
		}
	}
}

func nextHealthInterval() time.Duration {
	return 13*time.Second + time.Duration(rand.IntN(4001))*time.Millisecond // #nosec G404 -- probe jitter is not security-sensitive
}

func (c *Checker) collectProbeResults(
	ctx context.Context,
	servers, bootstrapServers []string,
	bootstrapDomain string,
) ([]probeTarget, map[string]probeResult) {
	targets := make([]probeTarget, 0, len(servers)+len(bootstrapServers))
	for _, server := range servers {
		targets = append(targets, probeTarget{key: server, server: server})
	}
	for _, server := range bootstrapServers {
		targets = append(targets, probeTarget{key: bootstrapLabel + server, server: server, bootstrap: true})
	}
	results := make(map[string]probeResult)
	var resultsMu sync.Mutex
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 8)
	for _, target := range targets {
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case semaphore <- struct{}{}:
				defer func() { <-semaphore }()
			case <-ctx.Done():
				return
			}
			var ok bool
			var latency float64
			var probeErr error
			if target.bootstrap {
				ok, latency = c.checkBootstrap(ctx, target.server, bootstrapDomain)
			} else {
				ok, latency, probeErr = c.checkUpstreamDetailed(ctx, target.server)
			}
			resultsMu.Lock()
			results[target.key] = probeResult{ok: ok, lat: latency, err: probeErr}
			resultsMu.Unlock()
		}()
	}
	wg.Wait()
	return targets, results
}

func bootstrapProbeDomain(fallback string, servers []string) string {
	for _, server := range servers {
		spec, err := upstream.Parse(server)
		if err == nil && spec.Hostname() {
			return spec.Host
		}
	}
	return fallback
}

func (c *Checker) runChecks(ctx context.Context, onChange func([]string, map[string]float64)) {
	c.mu.RLock()
	servers := append([]string(nil), c.upstreams...)
	bootstrapServers := append([]string(nil), c.bootstrapServers...)
	c.mu.RUnlock()
	bootstrapDomain := bootstrapProbeDomain(c.cfg.HealthDomain, servers)
	targets, results := c.collectProbeResults(ctx, servers, bootstrapServers, bootstrapDomain)

	newLatencies := make(map[string]float64, len(targets))
	for _, target := range targets {
		result := results[target.key]
		if result.ok {
			newLatencies[target.key] = result.lat
		} else {
			newLatencies[target.key] = -1
		}
	}

	c.mu.Lock()
	if ctx.Err() != nil {
		c.mu.Unlock()
		return
	}
	currentServers := append([]string(nil), c.upstreams...)
	currentSet := serverSet(currentServers)
	allowedHealthKeys := serverSet(currentServers)
	for _, server := range c.bootstrapServers {
		allowedHealthKeys[bootstrapLabel+server] = struct{}{}
	}
	previousHealthy := serverSet(c.healthy)
	newHealthy := make([]string, 0, len(currentServers))
	if c.states == nil {
		c.states = make(map[string]*probeState)
	}
	for _, server := range currentServers {
		state := c.states[server]
		if state == nil {
			state = &probeState{}
			c.states[server] = state
		}
		result := results[server]
		_, wasHealthy := previousHealthy[server]
		if result.ok {
			state.consecutiveSuccesses++
			state.consecutiveFailures = 0
			state.lastFailure = ""
			if wasHealthy || state.consecutiveSuccesses >= healthSuccessThreshold {
				newHealthy = append(newHealthy, server)
			}
			continue
		}
		state.consecutiveFailures++
		state.consecutiveSuccesses = 0
		if result.err != nil {
			state.lastFailure = result.err.Error()
		} else {
			state.lastFailure = "probe returned no response"
		}
		if wasHealthy && state.consecutiveFailures < healthFailureThreshold {
			newHealthy = append(newHealthy, server)
			if previousLatency, exists := c.latencies[server]; exists && previousLatency >= 0 {
				newLatencies[server] = previousLatency
			}
		}
	}
	for server := range c.states {
		if _, exists := currentSet[server]; !exists {
			delete(c.states, server)
		}
	}
	for server := range newLatencies {
		if _, ok := allowedHealthKeys[server]; !ok {
			delete(newLatencies, server)
		}
	}
	if len(newHealthy) == 0 {
		log.Printf("CRITICAL: All upstreams failed health check. Preserving previous healthy set.")
		newHealthy = retainServers(c.healthy, currentSet)
		if len(newHealthy) == 0 {
			newHealthy = currentServers
		}
	}
	c.latencies = newLatencies
	changed := !equalSlices(c.healthy, newHealthy)
	c.healthy = newHealthy
	currentHealthy := append([]string(nil), c.healthy...)
	currentLatencies := make(map[string]float64, len(c.latencies))
	for server, latency := range c.latencies {
		currentLatencies[server] = latency
	}
	c.mu.Unlock()

	if changed {
		log.Printf("Healthy upstreams changed: %v", currentHealthy)
	}
	onChange(currentHealthy, currentLatencies)
}

// Status returns failure reasons and hysteresis counters for each upstream.
func (c *Checker) Status() map[string]UpstreamStatus {
	c.mu.RLock()
	defer c.mu.RUnlock()
	healthy := serverSet(c.healthy)
	status := make(map[string]UpstreamStatus, len(c.upstreams))
	for _, server := range c.upstreams {
		state := c.states[server]
		entry := UpstreamStatus{LatencyMS: c.latencies[server]}
		_, entry.Healthy = healthy[server]
		if state != nil {
			entry.ConsecutiveFailures = state.consecutiveFailures
			entry.ConsecutiveSuccesses = state.consecutiveSuccesses
			entry.LastFailure = state.lastFailure
		}
		status[server] = entry
	}
	return status
}

// GetHealthy returns the currently healthy upstream servers.
func (c *Checker) GetHealthy() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return append([]string(nil), c.healthy...)
}

func equalSlices(a, b []string) bool {
	setA := make(map[string]struct{}, len(a))
	for _, v := range a {
		setA[v] = struct{}{}
	}
	setB := make(map[string]struct{}, len(b))
	for _, v := range b {
		setB[v] = struct{}{}
	}
	if len(setA) != len(setB) {
		return false
	}
	for k := range setA {
		if _, ok := setB[k]; !ok {
			return false
		}
	}
	return true
}

func serverSet(servers []string) map[string]struct{} {
	set := make(map[string]struct{}, len(servers))
	for _, server := range servers {
		set[server] = struct{}{}
	}
	return set
}

func retainServers(servers []string, allowed map[string]struct{}) []string {
	retained := make([]string, 0, len(servers))
	for _, server := range servers {
		if _, ok := allowed[server]; ok {
			retained = append(retained, server)
		}
	}
	return retained
}

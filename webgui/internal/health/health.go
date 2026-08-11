package health

import (
	"context"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/arumes31/resolix/webgui/internal/config"
	"github.com/arumes31/resolix/webgui/internal/upstream"
)

const (
	healthProbeTimeout = 10 * time.Second
	bootstrapLabel     = "Bootstrap · "
)

// Checker monitors the health of upstream DNS servers.
type Checker struct {
	cfg              *config.Config
	upstreams        []string
	bootstrapServers []string
	healthy          []string
	latencies        map[string]float64
	probeFn          func(context.Context, string, string) error
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
	}
	for _, server := range servers {
		c.latencies[server] = -1
	}
	return c
}

// CheckUpstream verifies if a specific DNS server is responsive and measures latency.
func (c *Checker) CheckUpstream(ctx context.Context, server string) (bool, float64) {
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
		return false, -1
	}
	return true, float64(time.Since(start).Microseconds()) / 1000.0
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
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.runChecks(ctx, onChange)
		}
	}
}

func (c *Checker) runChecks(ctx context.Context, onChange func([]string, map[string]float64)) {
	c.mu.RLock()
	servers := append([]string(nil), c.upstreams...)
	bootstrapServers := append([]string(nil), c.bootstrapServers...)
	c.mu.RUnlock()
	bootstrapDomain := c.cfg.HealthDomain
	for _, server := range servers {
		spec, err := upstream.Parse(server)
		if err == nil && spec.Hostname() {
			bootstrapDomain = spec.Host
			break
		}
	}
	type target struct {
		key       string
		server    string
		bootstrap bool
	}
	targets := make([]target, 0, len(servers)+len(bootstrapServers))
	for _, server := range servers {
		targets = append(targets, target{key: server, server: server})
	}
	for _, server := range bootstrapServers {
		targets = append(targets, target{key: bootstrapLabel + server, server: server, bootstrap: true})
	}
	type result struct {
		ok  bool
		lat float64
	}
	results := make(map[string]result)
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
			if target.bootstrap {
				ok, latency = c.checkBootstrap(ctx, target.server, bootstrapDomain)
			} else {
				ok, latency = c.CheckUpstream(ctx, target.server)
			}
			resultsMu.Lock()
			results[target.key] = result{ok: ok, lat: latency}
			resultsMu.Unlock()
		}()
	}
	wg.Wait()

	newHealthy := make([]string, 0, len(servers))
	newLatencies := make(map[string]float64, len(targets))
	for _, target := range targets {
		result := results[target.key]
		if result.ok {
			if !target.bootstrap {
				newHealthy = append(newHealthy, target.server)
			}
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
	newHealthy = retainServers(newHealthy, currentSet)
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

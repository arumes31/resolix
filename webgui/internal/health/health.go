package health

import (
	"context"
	"log"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"

	"tailscale-dnsrewrite/webgui/internal/config"
)

// Checker monitors the health of upstream DNS servers.
type Checker struct {
	cfg       *config.Config
	upstreams []string
	healthy   []string
	latencies map[string]float64
	mu        sync.RWMutex
}

// NewChecker initializes a new upstream health checker.
func NewChecker(cfg *config.Config, upstreamDNS string) *Checker {
	servers := strings.Fields(upstreamDNS)
	if len(servers) == 0 {
		servers = []string{"8.8.8.8", "8.8.4.4"}
	}
	c := &Checker{
		cfg:       cfg,
		upstreams: servers,
		healthy:   servers,
		latencies: make(map[string]float64),
	}
	var initialHealthy []string
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, s := range servers {
		ok, lat := c.CheckUpstream(ctx, s)
		if ok {
			initialHealthy = append(initialHealthy, s)
			c.latencies[s] = lat
		} else {
			c.latencies[s] = -1
		}
	}
	if len(initialHealthy) == 0 {
		initialHealthy = servers
	}
	c.healthy = initialHealthy
	return c
}

// CheckUpstream verifies if a specific DNS server is responsive and measures latency.
func (c *Checker) CheckUpstream(ctx context.Context, server string) (bool, float64) {
	start := time.Now()
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 2 * time.Second}
			return d.DialContext(ctx, "udp", server+":53")
		},
	}
	_, err := resolver.LookupHost(ctx, c.cfg.HealthDomain)
	if err != nil {
		return false, -1
	}
	return true, float64(time.Since(start).Microseconds()) / 1000.0
}

// Start begins the health check loop.
func (c *Checker) Start(ctx context.Context, onChange func([]string, map[string]float64)) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			var wg sync.WaitGroup
			type res struct {
				ok  bool
				lat float64
			}
			results := make(map[string]res)
			var resMu sync.Mutex

			for _, ups := range c.upstreams {
				wg.Add(1)
				go func(u string) {
					defer wg.Done()
					ok, lat := c.CheckUpstream(ctx, u)
					resMu.Lock()
					results[u] = res{ok: ok, lat: lat}
					resMu.Unlock()
				}(ups)
			}
			wg.Wait()

			var newHealthy []string
			newLatencies := make(map[string]float64)
			for _, ups := range c.upstreams {
				r := results[ups]
				if r.ok {
					newHealthy = append(newHealthy, ups)
					newLatencies[ups] = r.lat
				} else {
					newLatencies[ups] = -1
				}
			}

			c.mu.Lock()
			// check for context cancellation
			select {
			case <-ctx.Done():
				c.mu.Unlock()
				return
			default:
			}

			if len(newHealthy) == 0 {
				log.Printf("CRITICAL: All upstreams failed health check. Preserving previous healthy set.")
				newHealthy = c.healthy
				if len(newHealthy) == 0 {
					newHealthy = c.upstreams
				}
			}

			c.latencies = newLatencies
			changed := !equalSlices(c.healthy, newHealthy)
			c.healthy = newHealthy

			currentHealthy := append([]string(nil), c.healthy...)
			currentLatencies := make(map[string]float64)
			for k, v := range c.latencies {
				currentLatencies[k] = v
			}
			c.mu.Unlock()

			if changed {
				log.Printf("Healthy upstreams changed: %v", currentHealthy)
				if err := exec.Command("pkill", "-HUP", "dnsmasq").Run(); err != nil {
					log.Printf("Error reloading dnsmasq: %v", err)
				}
			}
			onChange(currentHealthy, currentLatencies)
		}
	}
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

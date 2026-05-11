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
	}
	var initialHealthy []string
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, s := range servers {
		if c.CheckUpstream(ctx, s) {
			initialHealthy = append(initialHealthy, s)
		}
	}
	c.healthy = initialHealthy
	return c
}

// CheckUpstream verifies if a specific DNS server is responsive.
func (c *Checker) CheckUpstream(ctx context.Context, server string) bool {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 2 * time.Second}
			return d.DialContext(ctx, "udp", server+":53")
		},
	}
	_, err := resolver.LookupHost(ctx, c.cfg.HealthDomain)
	return err == nil
}

// Start begins the health check loop.
func (c *Checker) Start(ctx context.Context, onChange func([]string)) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			var wg sync.WaitGroup
			results := make([]bool, len(c.upstreams))

			for i, ups := range c.upstreams {
				wg.Add(1)
				go func(idx int, u string) {
					defer wg.Done()
					results[idx] = c.CheckUpstream(ctx, u)
				}(i, ups)
			}
			wg.Wait()

			var newHealthy []string
			for i, r := range results {
				if r {
					newHealthy = append(newHealthy, c.upstreams[i])
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

			changed := !equalSlices(c.healthy, newHealthy)
			if changed {
				log.Printf("Healthy upstreams changed: %v -> %v", c.healthy, newHealthy)
				c.healthy = newHealthy
				c.mu.Unlock()

				if err := exec.Command("pkill", "-HUP", "dnsmasq").Run(); err != nil {
					log.Printf("Error reloading dnsmasq: %v", err)
				}

				onChange(newHealthy)
			} else {
				c.mu.Unlock()
			}
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

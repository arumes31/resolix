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
	return &Checker{
		cfg:       cfg,
		upstreams: servers,
		healthy:   servers,
	}
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
			var mu sync.Mutex
			newHealthy := []string{}

			for _, ups := range c.upstreams {
				wg.Add(1)
				go func(u string) {
					defer wg.Done()
					if c.CheckUpstream(ctx, u) {
						mu.Lock()
						newHealthy = append(newHealthy, u)
						mu.Unlock()
					}
				}(ups)
			}
			wg.Wait()

			c.mu.Lock()
			changed := !equalSlices(c.healthy, newHealthy)
			if changed && len(newHealthy) > 0 {
				log.Printf("Healthy upstreams changed: %v -> %v", c.healthy, newHealthy)
				c.healthy = newHealthy
				c.mu.Unlock()

				// Reload dnsmasq configuration (Improvement 39)
				_ = exec.Command("pkill", "-HUP", "dnsmasq").Run()

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
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

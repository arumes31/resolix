package resolver

import (
	"context"
	"net"
	"sync"
	"time"

	"tailscale-dnsrewrite/webgui/internal/logger"
)

const (
	// cacheTTL is how long a cached hostname entry is considered valid.
	cacheTTL = 5 * time.Minute
	// queueSize is the buffer capacity of the work queue channel.
	queueSize = 100
)

// cacheEntry stores a resolved hostname with its resolution timestamp.
type cacheEntry struct {
	hostname   string
	resolvedAt time.Time
}

// Resolver performs background reverse DNS lookups for client IPs.
type Resolver struct {
	cache sync.Map // map[string]cacheEntry
	queue chan string
}

// New creates a new Resolver instance.
func New() *Resolver {
	return &Resolver{
		queue: make(chan string, queueSize),
	}
}

// Start launches the background worker goroutine for reverse DNS lookups.
func (r *Resolver) Start(ctx context.Context) {
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case ip := <-r.queue:
				r.lookup(ip)
			}
		}
	}()
	logger.Info("Reverse DNS resolver started")
}

// Queue adds an IP address to the lookup work queue.
// If the queue is full, the lookup is silently dropped.
func (r *Resolver) Queue(ip string) {
	// Skip if already cached and not expired
	if val, ok := r.cache.Load(ip); ok {
		entry := val.(cacheEntry)
		if time.Since(entry.resolvedAt) < cacheTTL {
			return
		}
	}
	select {
	case r.queue <- ip:
	default:
		// Queue full, drop silently
		logger.Debug("Reverse DNS lookup queue full, dropping IP: %s", ip)
	}
}

// GetHostname returns the cached hostname for an IP, or empty string if not resolved.
func (r *Resolver) GetHostname(ip string) string {
	val, ok := r.cache.Load(ip)
	if !ok {
		// Not cached — queue for lookup
		r.Queue(ip)
		return ""
	}
	entry := val.(cacheEntry)
	if time.Since(entry.resolvedAt) >= cacheTTL {
		// Expired — re-queue and return stale value for now
		r.Queue(ip)
	}
	return entry.hostname
}

// lookup performs the actual reverse DNS lookup for an IP.
func (r *Resolver) lookup(ip string) {
	// Skip common non-routable addresses
	if ip == "127.0.0.1" || ip == "::1" || ip == "0.0.0.0" {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	names, err := net.DefaultResolver.LookupAddr(ctx, ip)
	if err != nil {
		logger.Debug("Reverse DNS lookup failed for %s: %v", ip, err)
		// Cache empty result to avoid repeated lookups
		r.cache.Store(ip, cacheEntry{hostname: "", resolvedAt: time.Now()})
		return
	}

	hostname := ""
	if len(names) > 0 {
		// Remove trailing dot from FQDN
		hostname = names[0]
		if len(hostname) > 0 && hostname[len(hostname)-1] == '.' {
			hostname = hostname[:len(hostname)-1]
		}
	}

	r.cache.Store(ip, cacheEntry{hostname: hostname, resolvedAt: time.Now()})
	if hostname != "" {
		logger.Debug("Reverse DNS: %s -> %s", ip, hostname)
	}
}

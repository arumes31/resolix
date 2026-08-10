package resolver

import (
	"context"
	"net"
	"sync"
	"time"

	"tailscale-dnsrewrite/webgui/internal/logger"
)

const (
	positiveCacheTTL = 5 * time.Minute
	negativeCacheTTL = time.Minute
	maxCacheEntries  = 4096
	// queueSize is the buffer capacity of the work queue channel.
	queueSize = 100
	// workerCount is the number of concurrent lookup worker goroutines.
	workerCount = 4
	// lookupTimeout bounds a single reverse DNS lookup so stalled requests
	// do not occupy a worker for long.
	lookupTimeout = 2 * time.Second
)

// cacheEntry stores a resolved hostname with its resolution timestamp.
type cacheEntry struct {
	hostname   string
	resolvedAt time.Time
}

// Resolver performs background reverse DNS lookups for client IPs.
type Resolver struct {
	cacheMu sync.Mutex
	cache   map[string]cacheEntry
	pending sync.Map // map[string]struct{}
	queue   chan string
}

// New creates a new Resolver instance.
func New() *Resolver {
	return &Resolver{
		queue: make(chan string, queueSize),
		cache: make(map[string]cacheEntry),
	}
}

// Start launches the background worker goroutines for reverse DNS lookups.
func (r *Resolver) Start(ctx context.Context) {
	for i := 0; i < workerCount; i++ {
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
	}
	logger.Info("Reverse DNS resolver started (%d workers)", workerCount)
}

// Queue adds an IP address to the lookup work queue.
// If the queue is full, the lookup is silently dropped.
func (r *Resolver) Queue(ip string) {
	if net.ParseIP(ip) == nil {
		return
	}
	// Skip if already cached and not expired
	r.cacheMu.Lock()
	entry, ok := r.cache[ip]
	r.cacheMu.Unlock()
	if ok {
		if time.Since(entry.resolvedAt) < entryTTL(entry) {
			return
		}
	}
	if _, loaded := r.pending.LoadOrStore(ip, struct{}{}); loaded {
		return
	}
	select {
	case r.queue <- ip:
	default:
		r.pending.Delete(ip)
		// Queue full, drop silently
		logger.Debug("Reverse DNS lookup queue full, dropping IP: %s", ip)
	}
}

// GetHostname returns the cached hostname for an IP, or empty string if not resolved.
func (r *Resolver) GetHostname(ip string) string {
	if net.ParseIP(ip) == nil {
		return ""
	}
	r.cacheMu.Lock()
	entry, ok := r.cache[ip]
	r.cacheMu.Unlock()
	if !ok {
		// Not cached — queue for lookup
		r.Queue(ip)
		return ""
	}
	if time.Since(entry.resolvedAt) >= entryTTL(entry) {
		// Expired — re-queue and return stale value for now
		r.Queue(ip)
	}
	return entry.hostname
}

// lookup performs the actual reverse DNS lookup for an IP.
func (r *Resolver) lookup(ip string) {
	defer r.pending.Delete(ip)
	// Skip common non-routable addresses
	if ip == "127.0.0.1" || ip == "::1" || ip == "0.0.0.0" {
		r.store(ip, "")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), lookupTimeout)
	defer cancel()

	names, err := net.DefaultResolver.LookupAddr(ctx, ip)
	if err != nil {
		logger.Debug("Reverse DNS lookup failed for %s: %v", ip, err)
		// Cache empty result to avoid repeated lookups
		r.store(ip, "")
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

	r.store(ip, hostname)
	if hostname != "" {
		logger.Debug("Reverse DNS: %s -> %s", ip, hostname)
	}
}

func entryTTL(entry cacheEntry) time.Duration {
	if entry.hostname == "" {
		return negativeCacheTTL
	}
	return positiveCacheTTL
}

func (r *Resolver) store(ip, hostname string) {
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()
	if _, exists := r.cache[ip]; !exists && len(r.cache) >= maxCacheEntries {
		oldestIP := ""
		var oldest time.Time
		for candidate, entry := range r.cache {
			if oldestIP == "" || entry.resolvedAt.Before(oldest) {
				oldestIP = candidate
				oldest = entry.resolvedAt
			}
		}
		delete(r.cache, oldestIP)
	}
	r.cache[ip] = cacheEntry{hostname: hostname, resolvedAt: time.Now()}
}

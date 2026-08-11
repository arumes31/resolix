package dnsserver

import (
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

const maxRateLimitBuckets = 65536

// parseCIDRList parses a comma/space-separated list of IPs and CIDRs.
// Invalid entries are skipped with a warning.
func parseCIDRList(raw string) []*net.IPNet {
	var out []*net.IPNet
	for _, part := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	}) {
		if !strings.Contains(part, "/") {
			if ip := net.ParseIP(part); ip != nil {
				if ip.To4() != nil {
					part += "/32"
				} else {
					part += "/128"
				}
			}
		}
		_, n, err := net.ParseCIDR(part)
		if err != nil {
			// Do not echo an environment-supplied value into the log.
			log.Printf("[WARN] Ignoring invalid client CIDR")
			continue
		}
		out = append(out, n)
	}
	return out
}

// cidrListContains reports whether ipStr is covered by any network.
func cidrListContains(nets []*net.IPNet, ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// aclDrop reports whether the client is on the disallowed list (drop
// silently — anti-amplification convention).
func (s *Server) aclDrop(clientIP string) bool {
	return cidrListContains(s.disallowed, clientIP)
}

// aclAllowlistDrop reports whether the client is outside a non-empty allowed
// list and must receive no response.
func (s *Server) aclAllowlistDrop(clientIP string) bool {
	return s.allowedConfigured && !cidrListContains(s.allowed, clientIP)
}

// rateBucket is a per-client-IP token bucket.
type rateBucket struct {
	tokens float64
	last   time.Time
}

// rateLimiter is a bounded per-client-IP token-bucket limiter.
type rateLimiter struct {
	mu         sync.Mutex
	qps        float64
	maxBuckets int
	buckets    map[string]*rateBucket
}

func newRateLimiter(qps int) *rateLimiter {
	return &rateLimiter{
		qps:        float64(qps),
		maxBuckets: maxRateLimitBuckets,
		buckets:    make(map[string]*rateBucket),
	}
}

// clientKey returns a canonical per-IP rate-limit bucket key.
func clientKey(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}

// allow consumes one token for the client using the default rate.
func (rl *rateLimiter) allow(ipStr string) bool {
	return rl.allowAtRate(ipStr, int(rl.qps))
}

// allowAtRate consumes one token for the client using qps as the refill rate
// and one-second burst capacity. A non-positive rate disables limiting.
func (rl *rateLimiter) allowAtRate(ipStr string, qps int) bool {
	if qps <= 0 {
		return true
	}
	key := clientKey(ipStr)
	if key == "" {
		return true
	}
	limit := float64(qps)
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	b, ok := rl.buckets[key]
	if !ok {
		if len(rl.buckets) >= rl.maxBuckets {
			oldestKey := ""
			var oldest time.Time
			for candidate, bucket := range rl.buckets {
				if oldestKey == "" || bucket.last.Before(oldest) {
					oldestKey = candidate
					oldest = bucket.last
				}
			}
			delete(rl.buckets, oldestKey)
		}
		b = &rateBucket{tokens: limit, last: now}
		rl.buckets[key] = b
	}
	// Refill (burst capacity = one second of qps).
	elapsed := now.Sub(b.last).Seconds()
	b.tokens += elapsed * limit
	if b.tokens > limit {
		b.tokens = limit
	}
	b.last = now

	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// isInternalClientIP reports whether a source belongs to loopback, LAN,
// link-local, or the Tailscale IPv4 CGNAT range. IPv6 ULA includes Tailscale.
func isInternalClientIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		return true
	}
	v4 := ip.To4()
	return v4 != nil && v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127
}

// cleanup evicts buckets idle longer than the given duration.
func (rl *rateLimiter) cleanup(maxIdle time.Duration) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	cutoff := time.Now().Add(-maxIdle)
	for key, b := range rl.buckets {
		if b.last.Before(cutoff) {
			delete(rl.buckets, key)
		}
	}
}

// bucketCount returns the number of tracked subnets (used by tests).
func (rl *rateLimiter) bucketCount() int {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	return len(rl.buckets)
}

// rateLimitCleanupLoop periodically evicts idle rate-limit buckets.
func (rl *rateLimiter) rateLimitCleanupLoop(ctxDone <-chan struct{}) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctxDone:
			return
		case <-ticker.C:
			rl.cleanup(10 * time.Minute)
		}
	}
}

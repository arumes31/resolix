package dnsserver

import (
	"container/list"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// cacheKey identifies a cached DNS response by question name, type, and class.
// group discriminates the shared cache for clients with custom upstreams
// (empty for the global pool), so client-specific answers never pollute the
// global cache space.
type cacheKey struct {
	name   string
	qtype  uint16
	qclass uint16
	group  string
}

// cacheEntry holds a cached response with its clamped TTL and insertion time
// so TTLs can be decremented on each cache hit.
type cacheEntry struct {
	answers           []dns.RR
	authority         []dns.RR
	rcode             int
	authenticatedData bool
	storedAt          time.Time
	ttl               uint32 // clamped TTL in seconds captured at store time
}

// remainingTTL returns the seconds until expiry; <= 0 means expired.
func (e *cacheEntry) remainingTTL(now time.Time) int64 {
	return int64(e.ttl) - int64(now.Sub(e.storedAt).Seconds())
}

// cache is a bounded in-memory DNS response cache with LRU eviction,
// mirroring the dnsmasq cache-size=25000 behavior.
type cache struct {
	mu         sync.Mutex
	cap        int
	minTTL     uint32
	maxTTL     uint32
	optimistic bool
	ll         *list.List // front = most recently used
	items      map[cacheKey]*list.Element
	hits       atomic.Int64
	misses     atomic.Int64
	staleHits  atomic.Int64
	evictions  atomic.Int64
	cleared    atomic.Int64
	refreshes  atomic.Int64
}

func newCache(capacity int, minTTL, maxTTL uint32) *cache {
	if capacity <= 0 {
		capacity = defaultCacheSize
	}
	if minTTL == 0 {
		minTTL = minCacheTTL
	}
	if maxTTL == 0 {
		maxTTL = maxCacheTTL
	}
	if minTTL > maxTTL {
		minTTL, maxTTL = maxTTL, minTTL
	}
	return &cache{
		cap:    capacity,
		minTTL: minTTL,
		maxTTL: maxTTL,
		ll:     list.New(),
		items:  make(map[cacheKey]*list.Element),
	}
}

// clamp bounds a TTL to the cache's [minTTL, maxTTL] range.
func (c *cache) clamp(ttl uint32) uint32 {
	if ttl < c.minTTL {
		return c.minTTL
	}
	if ttl > c.maxTTL {
		return c.maxTTL
	}
	return ttl
}

// get returns a fresh copy of the cached entry with its remaining TTL, or
// (nil, 0, false) when the entry is absent or expired. Per-hit TTL
// decrements never mutate the stored entry.
func (c *cache) get(key cacheKey) (*cacheEntry, uint32, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	el, ok := c.items[key]
	if !ok {
		c.misses.Add(1)
		return nil, 0, false
	}
	en := el.Value.(entry)
	ent := en.value
	remaining := ent.remainingTTL(time.Now())
	if remaining <= 0 {
		// Optimistic mode keeps expired entries so getStale can serve them
		// while a background refresh repopulates the cache.
		if !c.optimistic {
			c.removeElement(el)
		}
		c.misses.Add(1)
		return nil, 0, false
	}
	c.hits.Add(1)
	c.ll.MoveToFront(el)

	out := &cacheEntry{
		answers:           copyRRs(ent.answers),
		authority:         copyRRs(ent.authority),
		rcode:             ent.rcode,
		authenticatedData: ent.authenticatedData,
		storedAt:          ent.storedAt,
		ttl:               ent.ttl,
	}
	// remaining <= int64(ent.ttl), so the conversion cannot overflow; the
	// explicit clamp keeps gosec G115 satisfied.
	if remaining > math.MaxUint32 {
		remaining = math.MaxUint32
	}
	return out, uint32(remaining), true
}

// getStale returns a copy of the entry regardless of expiry (for optimistic
// caching), or (nil, false) when the key is absent entirely.
func (c *cache) getStale(key cacheKey) (*cacheEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.items[key]
	if !ok {
		return nil, false
	}
	ent := el.Value.(entry).value
	if ent.remainingTTL(time.Now()) <= 0 {
		c.staleHits.Add(1)
	}
	return &cacheEntry{
		answers:           copyRRs(ent.answers),
		authority:         copyRRs(ent.authority),
		rcode:             ent.rcode,
		authenticatedData: ent.authenticatedData,
		storedAt:          ent.storedAt,
		ttl:               ent.ttl,
	}, true
}

// set stores an entry, evicting the least recently used entry when full.
func (c *cache) set(key cacheKey, ent *cacheEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if el, ok := c.items[key]; ok {
		c.ll.MoveToFront(el)
		el.Value = entry{key: key, value: ent}
		return
	}
	if len(c.items) >= c.cap {
		c.evictions.Add(1)
		c.removeElement(c.ll.Back())
	}
	c.items[key] = c.ll.PushFront(entry{key: key, value: ent})
}

func (c *cache) removeElement(el *list.Element) {
	if el == nil {
		return
	}
	c.ll.Remove(el)
	delete(c.items, el.Value.(entry).key)
}

// len returns the number of cached entries (used by tests).
func (c *cache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.items)
}

// clear removes every cached response and returns the number removed.
func (c *cache) clear() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := len(c.items)
	c.ll.Init()
	c.items = make(map[cacheKey]*list.Element)
	c.cleared.Add(int64(n))
	return n
}

// CacheStats is a point-in-time snapshot of cache usage and counters.
type CacheStats struct {
	Entries   int
	Capacity  int
	Hits      int64
	Misses    int64
	StaleHits int64
	Evictions int64
	Cleared   int64
	Refreshes int64
}

func (c *cache) stats() CacheStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	return CacheStats{
		Entries: len(c.items), Capacity: c.cap, Hits: c.hits.Load(),
		Misses: c.misses.Load(), StaleHits: c.staleHits.Load(),
		Evictions: c.evictions.Load(), Cleared: c.cleared.Load(),
		Refreshes: c.refreshes.Load(),
	}
}

// entry bundles the list key with the entry value for LRU bookkeeping.
type entry struct {
	key   cacheKey
	value *cacheEntry
}

func copyRRs(rrs []dns.RR) []dns.RR {
	if len(rrs) == 0 {
		return nil
	}
	out := make([]dns.RR, len(rrs))
	for i, rr := range rrs {
		out[i] = dns.Copy(rr)
	}
	return out
}

// clampTTL bounds a TTL to [minCacheTTL, maxCacheTTL], mirroring the dnsmasq
// local-ttl=60 / max-ttl=600 behavior.
func clampTTL(ttl uint32) uint32 {
	if ttl < minCacheTTL {
		return minCacheTTL
	}
	if ttl > maxCacheTTL {
		return maxCacheTTL
	}
	return ttl
}

// minAnswerTTL returns the smallest TTL across answer records (0 when empty).
func minAnswerTTL(rrs []dns.RR) uint32 {
	var minimum uint32
	initialized := false
	for _, rr := range rrs {
		if ttl := rr.Header().Ttl; !initialized || ttl < minimum {
			minimum = ttl
			initialized = true
		}
	}
	return minimum
}

// soaTTL extracts the TTL of the first SOA record in the authority section.
func soaTTL(rrs []dns.RR) (uint32, bool) {
	for _, rr := range rrs {
		if _, ok := rr.(*dns.SOA); ok {
			return rr.Header().Ttl, true
		}
	}
	return 0, false
}

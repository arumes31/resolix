package dnsserver

import (
	"container/list"
	"math"
	"sort"
	"strconv"
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
	do     bool
	cd     bool
	ecs    string
	policy string
	route  string
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
	hits              uint32
	negative          bool
	negativeSOA       string
	servfail          bool
	prefetched        bool
	expiredObserved   bool
}

// remainingTTL returns the seconds until expiry; <= 0 means expired.
func (e *cacheEntry) remainingTTL(now time.Time) int64 {
	return int64(e.ttl) - int64(now.Sub(e.storedAt).Seconds())
}

// cache is a bounded in-memory DNS response cache with LRU eviction,
// mirroring the dnsmasq cache-size=25000 behavior.
type cache struct {
	mu             sync.Mutex
	cap            int
	minTTL         uint32
	maxTTL         uint32
	optimistic     bool
	ll             *list.List // front = most recently used
	items          map[cacheKey]*list.Element
	hits           atomic.Int64
	freshHits      atomic.Int64
	negativeHits   atomic.Int64
	prefetchedHits atomic.Int64
	servfailHits   atomic.Int64
	misses         atomic.Int64
	staleHits      atomic.Int64
	evictions      atomic.Int64
	cleared        atomic.Int64
	refreshes      atomic.Int64
	prefetches     atomic.Int64
	coalesced      atomic.Int64
	invalidated    atomic.Int64
	perQType       map[uint16]CacheQTypeStats
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
		cap:      capacity,
		minTTL:   minTTL,
		maxTTL:   maxTTL,
		ll:       list.New(),
		items:    make(map[cacheKey]*list.Element),
		perQType: make(map[uint16]CacheQTypeStats),
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
		c.addQTypeMiss(key.qtype)
		return nil, 0, false
	}
	en := el.Value.(entry)
	ent := en.value
	remaining := ent.remainingTTL(time.Now())
	if remaining <= 0 {
		if !ent.expiredObserved {
			ent.expiredObserved = true
			c.addQTypeExpiration(key.qtype)
		}
		// Optimistic mode keeps expired entries so getStale can serve them
		// while a background refresh repopulates the cache.
		if !c.optimistic {
			c.removeElement(el)
		}
		c.misses.Add(1)
		c.addQTypeMiss(key.qtype)
		return nil, 0, false
	}
	c.hits.Add(1)
	if ent.prefetched {
		c.prefetchedHits.Add(1)
	}
	if ent.negative {
		c.negativeHits.Add(1)
	}
	if ent.servfail {
		c.servfailHits.Add(1)
	}
	if !ent.prefetched && !ent.negative && !ent.servfail {
		c.freshHits.Add(1)
	}
	c.addQTypeHit(key.qtype)
	ent.hits++
	c.ll.MoveToFront(el)

	out := copyCacheEntry(ent)
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
	return copyCacheEntry(ent), true
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
		victim := c.ll.Back()
		if victim != nil {
			c.addQTypeEviction(victim.Value.(entry).key.qtype)
		}
		c.removeElement(victim)
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

// reconfigure changes capacity and TTL bounds under the cache lock. Entries
// are cleared because their stored TTLs were computed under the old policy.
func (c *cache) reconfigure(capacity int, minTTL, maxTTL uint32, optimistic bool) {
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
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cap = capacity
	c.minTTL = minTTL
	c.maxTTL = maxTTL
	c.optimistic = optimistic
	removed := len(c.items)
	c.ll.Init()
	c.items = make(map[cacheKey]*list.Element)
	c.cleared.Add(int64(removed))
}

// invalidate removes entries matching predicate and returns the number
// removed. The predicate runs while the cache lock is held and must not call
// back into cache methods.
func (c *cache) invalidate(predicate func(cacheKey) bool) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	removed := 0
	for key, el := range c.items {
		if !predicate(key) {
			continue
		}
		c.removeElement(el)
		removed++
	}
	c.invalidated.Add(int64(removed))
	return removed
}

// CacheStats is a point-in-time snapshot of cache usage and counters.
type CacheStats struct {
	Entries         int                        `json:"entries"`
	Capacity        int                        `json:"capacity"`
	Utilization     float64                    `json:"utilization"`
	NegativeEntries int                        `json:"negative_entries"`
	Hits            int64                      `json:"hits"`
	FreshHits       int64                      `json:"fresh_hits"`
	NegativeHits    int64                      `json:"negative_hits"`
	PrefetchedHits  int64                      `json:"prefetched_hits"`
	SERVFAILHits    int64                      `json:"servfail_hits"`
	Misses          int64                      `json:"misses"`
	StaleHits       int64                      `json:"stale_hits"`
	Evictions       int64                      `json:"evictions"`
	Expirations     int64                      `json:"expirations"`
	Cleared         int64                      `json:"cleared"`
	Invalidated     int64                      `json:"invalidated"`
	Refreshes       int64                      `json:"refreshes"`
	Prefetches      int64                      `json:"prefetches"`
	Coalesced       int64                      `json:"coalesced"`
	InFlight        int                        `json:"in_flight"`
	ByQType         map[string]CacheQTypeStats `json:"by_qtype"`
}

// CacheQTypeStats contains cache counters for one DNS question type.
type CacheQTypeStats struct {
	Hits        int64 `json:"hits"`
	Misses      int64 `json:"misses"`
	Evictions   int64 `json:"evictions"`
	Expirations int64 `json:"expirations"`
}

func (c *cache) stats() CacheStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	byQType := make(map[string]CacheQTypeStats, len(c.perQType))
	var expirations int64
	for qtype, counters := range c.perQType {
		name := dns.TypeToString[qtype]
		if name == "" {
			name = strconv.FormatUint(uint64(qtype), 10)
		}
		byQType[name] = counters
		expirations += counters.Expirations
	}
	negativeEntries := 0
	for _, el := range c.items {
		if el.Value.(entry).value.negative {
			negativeEntries++
		}
	}
	utilization := 0.0
	if c.cap > 0 {
		utilization = float64(len(c.items)) / float64(c.cap)
	}
	return CacheStats{
		Entries: len(c.items), Capacity: c.cap, Utilization: utilization,
		NegativeEntries: negativeEntries, Hits: c.hits.Load(),
		FreshHits: c.freshHits.Load(), NegativeHits: c.negativeHits.Load(),
		PrefetchedHits: c.prefetchedHits.Load(), SERVFAILHits: c.servfailHits.Load(),
		Misses: c.misses.Load(), StaleHits: c.staleHits.Load(),
		Evictions: c.evictions.Load(), Expirations: expirations,
		Cleared: c.cleared.Load(), Invalidated: c.invalidated.Load(),
		Refreshes: c.refreshes.Load(), Prefetches: c.prefetches.Load(),
		Coalesced: c.coalesced.Load(),
		ByQType:   byQType,
	}
}

// CacheEntryStatus is a read-only cache entry summary suitable for status
// endpoints. Answers are intentionally omitted; negative entries expose the
// remaining TTL and SOA requested for operational diagnosis.
type CacheEntryStatus struct {
	Name         string `json:"name"`
	QType        string `json:"qtype"`
	Group        string `json:"group,omitempty"`
	RemainingTTL uint32 `json:"remaining_ttl"`
	Negative     bool   `json:"negative"`
	SOA          string `json:"soa,omitempty"`
}

func (c *cache) entryStatuses() []CacheEntryStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	statuses := make([]CacheEntryStatus, 0, len(c.items))
	for key, el := range c.items {
		ent := el.Value.(entry).value
		remaining := ent.remainingTTL(now)
		if remaining < 0 {
			remaining = 0
		}
		if remaining > math.MaxUint32 {
			remaining = math.MaxUint32
		}
		qtype := dns.TypeToString[key.qtype]
		if qtype == "" {
			qtype = strconv.FormatUint(uint64(key.qtype), 10)
		}
		status := CacheEntryStatus{
			Name: key.name, QType: qtype, Group: key.group,
			RemainingTTL: uint32(remaining), Negative: ent.negative,
		}
		if ent.negative {
			status.SOA = ent.negativeSOA
		}
		statuses = append(statuses, status)
	}
	sort.Slice(statuses, func(i, j int) bool {
		if statuses[i].Name != statuses[j].Name {
			return statuses[i].Name < statuses[j].Name
		}
		return statuses[i].QType < statuses[j].QType
	})
	return statuses
}

func (c *cache) addQTypeHit(qtype uint16) {
	stats := c.perQType[qtype]
	stats.Hits++
	c.perQType[qtype] = stats
}

func (c *cache) addQTypeMiss(qtype uint16) {
	stats := c.perQType[qtype]
	stats.Misses++
	c.perQType[qtype] = stats
}

func (c *cache) addQTypeEviction(qtype uint16) {
	stats := c.perQType[qtype]
	stats.Evictions++
	c.perQType[qtype] = stats
}

func (c *cache) addQTypeExpiration(qtype uint16) {
	stats := c.perQType[qtype]
	stats.Expirations++
	c.perQType[qtype] = stats
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

func copyCacheEntry(ent *cacheEntry) *cacheEntry {
	return &cacheEntry{
		answers: copyRRs(ent.answers), authority: copyRRs(ent.authority),
		rcode: ent.rcode, authenticatedData: ent.authenticatedData,
		storedAt: ent.storedAt, ttl: ent.ttl, hits: ent.hits,
		negative: ent.negative, servfail: ent.servfail,
		negativeSOA: ent.negativeSOA,
		prefetched:  ent.prefetched, expiredObserved: ent.expiredObserved,
	}
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

// soaMetadata returns the RFC 2308 negative TTL and owner of the first SOA.
// The negative TTL is the smaller of the SOA RR TTL and its MINIMUM field.
func soaMetadata(rrs []dns.RR) (ttl uint32, origin string, ok bool) {
	for _, rr := range rrs {
		if soa, isSOA := rr.(*dns.SOA); isSOA {
			ttl = soa.Hdr.Ttl
			if soa.Minttl < ttl {
				ttl = soa.Minttl
			}
			return ttl, soa.Hdr.Name, true
		}
	}
	return 0, "", false
}

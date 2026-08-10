package dnsserver

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func aRecord(name, ip string, ttl uint32) dns.RR {
	return &dns.A{
		Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
		A:   net.ParseIP(ip).To4(),
	}
}

func soaRecord(name string, ttl uint32) dns.RR {
	return &dns.SOA{
		Hdr:     dns.RR_Header{Name: name, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: ttl},
		Ns:      "ns1.example.org.",
		Mbox:    "hostmaster.example.org.",
		Serial:  1,
		Refresh: 7200,
		Retry:   3600,
		Expire:  1209600,
		Minttl:  60,
	}
}

func TestClampTTL(t *testing.T) {
	tests := []struct {
		in, want uint32
	}{
		{0, minCacheTTL},
		{30, minCacheTTL},
		{60, 60},
		{300, 300},
		{600, 600},
		{601, maxCacheTTL},
		{86400, maxCacheTTL},
	}
	for _, tt := range tests {
		if got := clampTTL(tt.in); got != tt.want {
			t.Errorf("clampTTL(%d) = %d, want %d", tt.in, got, tt.want)
		}
	}
}

func TestCacheSetGetExpiry(t *testing.T) {
	c := newCache(10, 0, 0)
	key := cacheKey{name: "example.com", qtype: dns.TypeA}

	if _, _, ok := c.get(key); ok {
		t.Fatal("expected cache miss for empty cache")
	}

	c.set(key, &cacheEntry{
		answers:  []dns.RR{aRecord("example.com.", "1.2.3.4", 300)},
		rcode:    dns.RcodeSuccess,
		storedAt: time.Now(),
		ttl:      300,
	})
	if c.len() != 1 {
		t.Fatalf("expected 1 entry, got %d", c.len())
	}

	ent, remaining, ok := c.get(key)
	if !ok {
		t.Fatal("expected cache hit")
	}
	if remaining <= 0 || remaining > 300 {
		t.Errorf("remaining TTL = %d, want in (0, 300]", remaining)
	}
	if ent.rcode != dns.RcodeSuccess || len(ent.answers) != 1 {
		t.Errorf("unexpected entry: %+v", ent)
	}
	// Returned copy must have original (undecremented) TTL; decrement happens
	// when building the response via withTTL.
	if ent.answers[0].Header().Ttl != 300 {
		t.Errorf("stored copy TTL mutated: %d", ent.answers[0].Header().Ttl)
	}

	// Force expiry by backdating.
	c.set(key, &cacheEntry{
		answers:  []dns.RR{aRecord("example.com.", "1.2.3.4", 60)},
		rcode:    dns.RcodeSuccess,
		storedAt: time.Now().Add(-2 * time.Minute),
		ttl:      60,
	})
	if _, _, ok := c.get(key); ok {
		t.Fatal("expected expired entry to be a miss")
	}
	if c.len() != 0 {
		t.Errorf("expired entry not evicted, len = %d", c.len())
	}
}

func TestCacheTTLDecrementOnResponse(t *testing.T) {
	rrs := withTTL([]dns.RR{aRecord("example.com.", "1.2.3.4", 300)}, 123)
	if got := rrs[0].Header().Ttl; got != 123 {
		t.Errorf("withTTL TTL = %d, want 123", got)
	}
}

func TestGetStaleCountsOnlyExpiredEntries(t *testing.T) {
	c := newCache(2, 0, 0)
	fresh := cacheKey{name: "fresh.test", qtype: dns.TypeA}
	expired := cacheKey{name: "expired.test", qtype: dns.TypeA}
	c.set(fresh, &cacheEntry{storedAt: time.Now(), ttl: 60})
	c.set(expired, &cacheEntry{storedAt: time.Now().Add(-time.Minute), ttl: 1})
	if _, ok := c.getStale(fresh); !ok {
		t.Fatal("fresh entry is missing")
	}
	if got := c.staleHits.Load(); got != 0 {
		t.Fatalf("stale hits after fresh lookup = %d, want 0", got)
	}
	if _, ok := c.getStale(expired); !ok {
		t.Fatal("expired entry is missing")
	}
	if got := c.staleHits.Load(); got != 1 {
		t.Fatalf("stale hits after expired lookup = %d, want 1", got)
	}
}

func TestMinAnswerTTLPreservesZero(t *testing.T) {
	records := []dns.RR{
		aRecord("zero.test.", "192.0.2.1", 0),
		aRecord("zero.test.", "192.0.2.2", 120),
	}
	if got := minAnswerTTL(records); got != 0 {
		t.Fatalf("minAnswerTTL() = %d, want 0", got)
	}
}

func TestCacheSeparatesQuestionClasses(t *testing.T) {
	internet := cacheKey{name: "class.test", qtype: dns.TypeA, qclass: dns.ClassINET}
	chaos := cacheKey{name: "class.test", qtype: dns.TypeA, qclass: dns.ClassCHAOS}
	if internet == chaos {
		t.Fatal("cache keys for different DNS classes are equal")
	}
}

func TestCacheLRUEviction(t *testing.T) {
	c := newCache(2, 0, 0)
	mk := func(name string) cacheKey { return cacheKey{name: name, qtype: dns.TypeA} }
	put := func(name string) {
		c.set(mk(name), &cacheEntry{
			rcode:    dns.RcodeSuccess,
			storedAt: time.Now(),
			ttl:      300,
		})
	}
	put("a.com")
	put("b.com")
	if _, _, ok := c.get(mk("a.com")); !ok { // touch a.com → b.com is LRU
		t.Fatal("expected hit for a.com")
	}
	put("c.com") // evicts b.com
	if _, _, ok := c.get(mk("b.com")); ok {
		t.Error("expected b.com to be evicted (LRU)")
	}
	if _, _, ok := c.get(mk("a.com")); !ok {
		t.Error("expected a.com to survive eviction")
	}
	if _, _, ok := c.get(mk("c.com")); !ok {
		t.Error("expected c.com to be cached")
	}
}

func TestStoreInCacheNegative(t *testing.T) {
	s := New(Config{Addr: "127.0.0.1", Port: 0}, nil)
	key := cacheKey{name: "nx.example.org", qtype: dns.TypeA}

	// NXDOMAIN with SOA → cached with SOA TTL clamped to max 600.
	nx := new(dns.Msg)
	nx.Rcode = dns.RcodeNameError
	nx.Ns = []dns.RR{soaRecord("example.org.", 1200)}
	s.storeInCache(key, nx)

	ent, _, ok := s.cache.get(key)
	if !ok {
		t.Fatal("expected NXDOMAIN to be cached")
	}
	if ent.ttl != maxCacheTTL {
		t.Errorf("negative TTL = %d, want clamped %d", ent.ttl, maxCacheTTL)
	}
	if ent.rcode != dns.RcodeNameError {
		t.Errorf("cached rcode = %d, want NXDOMAIN", ent.rcode)
	}

	// NXDOMAIN without SOA → not cached.
	key2 := cacheKey{name: "nosoa.example.org", qtype: dns.TypeA}
	nx2 := new(dns.Msg)
	nx2.Rcode = dns.RcodeNameError
	s.storeInCache(key2, nx2)
	if _, _, ok := s.cache.get(key2); ok {
		t.Error("expected NXDOMAIN without SOA not to be cached")
	}

	// NODATA (NOERROR, no answers) with SOA → cached.
	key3 := cacheKey{name: "nodata.example.org", qtype: dns.TypeAAAA}
	nodata := new(dns.Msg)
	nodata.Rcode = dns.RcodeSuccess
	nodata.Ns = []dns.RR{soaRecord("example.org.", 300)}
	s.storeInCache(key3, nodata)
	ent3, _, ok := s.cache.get(key3)
	if !ok {
		t.Fatal("expected NODATA to be cached")
	}
	if ent3.ttl != 300 {
		t.Errorf("NODATA TTL = %d, want 300", ent3.ttl)
	}

	// SERVFAIL → not cached.
	key4 := cacheKey{name: "fail.example.org", qtype: dns.TypeA}
	fail := new(dns.Msg)
	fail.Rcode = dns.RcodeServerFailure
	s.storeInCache(key4, fail)
	if _, _, ok := s.cache.get(key4); ok {
		t.Error("expected SERVFAIL not to be cached")
	}
}

func TestStoreInCachePositiveTTLClamp(t *testing.T) {
	s := New(Config{Addr: "127.0.0.1", Port: 0}, nil)
	tests := []struct {
		name    string
		ttl     uint32
		wantTTL uint32
	}{
		{"low.example.com", 10, minCacheTTL},
		{"mid.example.com", 300, 300},
		{"high.example.com", 86400, maxCacheTTL},
	}
	for _, tt := range tests {
		m := new(dns.Msg)
		m.Rcode = dns.RcodeSuccess
		m.Answer = []dns.RR{aRecord(tt.name+".", "1.2.3.4", tt.ttl)}
		s.storeInCache(cacheKey{name: tt.name, qtype: dns.TypeA}, m)

		ent, _, ok := s.cache.get(cacheKey{name: tt.name, qtype: dns.TypeA})
		if !ok {
			t.Fatalf("expected %s to be cached", tt.name)
		}
		if ent.ttl != tt.wantTTL {
			t.Errorf("%s: cached TTL = %d, want %d", tt.name, ent.ttl, tt.wantTTL)
		}
	}
}

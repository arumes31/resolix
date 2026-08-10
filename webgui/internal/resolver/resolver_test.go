package resolver

import "testing"

func TestResolverRejectsInvalidIPAndCachesNegativeResult(t *testing.T) {
	r := New()
	r.Queue("not-an-ip")
	if _, ok := r.pending.Load("not-an-ip"); ok {
		t.Fatal("invalid IP entered the pending queue")
	}
	r.lookup("127.0.0.1")
	r.cacheMu.Lock()
	entry, ok := r.cache["127.0.0.1"]
	r.cacheMu.Unlock()
	if !ok || entry.hostname != "" {
		t.Fatalf("loopback negative cache entry = %+v, %v", entry, ok)
	}
}

func TestResolverCacheIsBounded(t *testing.T) {
	r := New()
	for i := 0; i < maxCacheEntries+20; i++ {
		r.store(string(rune(i+1)), "host")
	}
	r.cacheMu.Lock()
	count := len(r.cache)
	r.cacheMu.Unlock()
	if count != maxCacheEntries {
		t.Fatalf("cache entries = %d, want %d", count, maxCacheEntries)
	}
}

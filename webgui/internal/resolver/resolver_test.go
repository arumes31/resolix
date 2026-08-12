package resolver

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

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

func TestResolverStartProcessesQueueAndStops(t *testing.T) {
	r := New()
	ctx, cancel := context.WithCancel(context.Background())
	r.Start(ctx)
	r.Queue("127.0.0.1")

	deadline := time.Now().Add(time.Second)
	for {
		r.cacheMu.Lock()
		_, cached := r.cache["127.0.0.1"]
		r.cacheMu.Unlock()
		if cached {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("worker did not process queued lookup")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
}

func TestResolverQueueDeduplicatesAndDropsWhenFull(t *testing.T) {
	r := New()
	r.Queue("192.0.2.1")
	r.Queue("192.0.2.1")
	if got := len(r.queue); got != 1 {
		t.Fatalf("deduplicated queue length = %d, want 1", got)
	}

	for i := 2; i <= queueSize; i++ {
		r.Queue(fmt.Sprintf("2001:db8::%x", i))
	}
	dropped := "198.51.100.1"
	r.Queue(dropped)
	if _, pending := r.pending.Load(dropped); pending {
		t.Fatal("dropped queue entry remained pending")
	}
}

func TestResolverQueueUsesFreshCacheAndRefreshesExpiredCache(t *testing.T) {
	r := New()
	r.store("192.0.2.1", "client.example")
	r.Queue("192.0.2.1")
	if got := len(r.queue); got != 0 {
		t.Fatalf("fresh cache queued %d lookups, want 0", got)
	}

	r.cacheMu.Lock()
	entry := r.cache["192.0.2.1"]
	entry.resolvedAt = time.Now().Add(-positiveCacheTTL)
	r.cache["192.0.2.1"] = entry
	r.cacheMu.Unlock()

	if got := r.GetHostname("192.0.2.1"); got != "client.example" {
		t.Fatalf("stale hostname = %q, want client.example", got)
	}
	if got := len(r.queue); got != 1 {
		t.Fatalf("expired cache queued %d lookups, want 1", got)
	}
}

func TestResolverGetHostnameValidationAndCacheMiss(t *testing.T) {
	r := New()
	if got := r.GetHostname("not-an-ip"); got != "" {
		t.Fatalf("invalid IP hostname = %q, want empty", got)
	}
	if got := r.GetHostname("192.0.2.3"); got != "" {
		t.Fatalf("cache miss hostname = %q, want empty", got)
	}
	if got := len(r.queue); got != 1 {
		t.Fatalf("cache miss queued %d lookups, want 1", got)
	}
}

func TestResolverLookupSuccessAndFailure(t *testing.T) {
	original := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			return nil, &net.DNSError{Err: "fixture failure", IsTemporary: true}
		},
	}
	t.Cleanup(func() { net.DefaultResolver = original })

	r := New()
	r.pending.Store("192.0.2.10", struct{}{})
	r.lookup("192.0.2.10")
	if _, pending := r.pending.Load("192.0.2.10"); pending {
		t.Fatal("failed lookup remained pending")
	}
	if got := r.GetHostname("192.0.2.10"); got != "" {
		t.Fatalf("failed lookup hostname = %q, want empty", got)
	}

	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &dns.Server{PacketConn: packetConn, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(request)
		if len(request.Question) > 0 && request.Question[0].Qtype == dns.TypePTR {
			response.Answer = []dns.RR{&dns.PTR{
				Hdr: dns.RR_Header{
					Name: request.Question[0].Name, Rrtype: dns.TypePTR,
					Class: dns.ClassINET, Ttl: 60,
				},
				Ptr: "client.example.",
			}}
		}
		_ = w.WriteMsg(response)
	})}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			return net.Dial("udp", packetConn.LocalAddr().String())
		},
	}
	r.lookup("192.0.2.20")
	if got := r.GetHostname("192.0.2.20"); got != "client.example" {
		t.Fatalf("successful lookup hostname = %q, want client.example", got)
	}
}

func TestEntryTTLAndStoreUpdate(t *testing.T) {
	if got := entryTTL(cacheEntry{}); got != negativeCacheTTL {
		t.Fatalf("negative TTL = %s, want %s", got, negativeCacheTTL)
	}
	if got := entryTTL(cacheEntry{hostname: "client.example"}); got != positiveCacheTTL {
		t.Fatalf("positive TTL = %s, want %s", got, positiveCacheTTL)
	}

	r := New()
	r.store("192.0.2.1", "first.example")
	first := r.cache["192.0.2.1"]
	r.store("192.0.2.1", "second.example")
	updated := r.cache["192.0.2.1"]
	if updated.hostname != "second.example" {
		t.Fatalf("updated hostname = %q, want second.example", updated.hostname)
	}
	if updated.order != first.order || updated.resolvedAt.Before(first.resolvedAt) {
		t.Fatal("cache update did not preserve LRU node and refresh timestamp")
	}
}

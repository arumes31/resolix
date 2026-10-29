package storage

import (
	"fmt"
	"testing"
	"time"

	"github.com/arumes31/resolix/webgui/internal/models"
)

func TestAddEventBoundsPerClientStats(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()

	now := time.Now().Unix()
	s.statsMu.Lock()
	for i := 0; i < maxClientStats; i++ {
		client := fmt.Sprintf("10.0.%d.%d", i/256, i%256)
		s.clientRPMBuckets[client] = &[60]int{}
		s.clientRPMTimes[client] = &[60]int64{}
		s.clientRPHBuckets[client] = &[60]int{}
		s.clientRPHTimes[client] = &[60]int64{}
		// The first identity is the least recently seen.
		s.clientLastSeen[client] = now - int64(maxClientStats-i)
	}
	s.statsMu.Unlock()

	s.AddEvent(models.QueryEvent{Domain: "example.com", ClientIP: "192.0.2.1", UnixTime: now, Type: "A"})

	s.statsMu.RLock()
	defer s.statsMu.RUnlock()
	if got := len(s.clientLastSeen); got > maxClientStats {
		t.Fatalf("client stats grew to %d, want <= %d", got, maxClientStats)
	}
	for _, m := range []int{len(s.clientRPMBuckets), len(s.clientRPMTimes), len(s.clientRPHBuckets), len(s.clientRPHTimes)} {
		if m != len(s.clientLastSeen) {
			t.Fatalf("per-client maps out of sync: %d vs %d", m, len(s.clientLastSeen))
		}
	}
	if _, ok := s.clientLastSeen["192.0.2.1"]; !ok {
		t.Fatal("new client was not admitted")
	}
	if _, ok := s.clientLastSeen["10.0.0.0"]; ok {
		t.Fatal("least recently seen client was not evicted")
	}
	newest := fmt.Sprintf("10.0.%d.%d", (maxClientStats-1)/256, (maxClientStats-1)%256)
	if _, ok := s.clientLastSeen[newest]; !ok {
		t.Fatal("most recently seen client was evicted")
	}
}

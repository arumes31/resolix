// Package clients implements the per-client policy registry: JSON-persisted
// client profiles with longest-prefix IP/CIDR matching, hot-reload, and
// weekly blocking schedules.
package clients

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// TimeRange is a daily window in "HH:MM" 24h format. Overnight windows
// (end < start) wrap past midnight.
type TimeRange struct {
	Start string `json:"start"`
	End   string `json:"end"`
}

// Schedule limits blocked-service enforcement to weekly windows.
// Days keys are lowercase weekday abbreviations: mon, tue, wed, thu, fri, sat, sun.
type Schedule struct {
	Timezone string                 `json:"timezone,omitempty"` // IANA name; empty = local
	Days     map[string][]TimeRange `json:"days"`
}

// Active reports whether the schedule is active at the given time.
// A nil schedule is always active.
func (s *Schedule) Active(now time.Time) bool {
	if s == nil {
		return true
	}
	loc := time.Local
	if s.Timezone != "" {
		if l, err := time.LoadLocation(s.Timezone); err == nil {
			loc = l
		}
	}
	now = now.In(loc)
	day := strings.ToLower(now.Weekday().String()[:3])
	ranges, ok := s.Days[day]
	if !ok {
		return false
	}
	mins := now.Hour()*60 + now.Minute()
	for _, r := range ranges {
		start, err1 := parseHHMM(r.Start)
		end, err2 := parseHHMM(r.End)
		if err1 != nil || err2 != nil {
			continue
		}
		if end <= start { // overnight window
			if mins >= start || mins < end {
				return true
			}
		} else if mins >= start && mins < end {
			return true
		}
	}
	return false
}

func parseHHMM(s string) (int, error) {
	var h, m int
	if _, err := fmt.Sscanf(s, "%d:%d", &h, &m); err != nil {
		return 0, err
	}
	if h < 0 || h > 23 || m < 0 || m > 59 {
		return 0, fmt.Errorf("invalid time %q", s)
	}
	return h*60 + m, nil
}

// Client is a per-client policy profile.
type Client struct {
	Name string   `json:"name"`
	IDs  []string `json:"ids"` // IPv4/IPv6 addresses or CIDRs
	Tags []string `json:"tags,omitempty"`

	// UseGlobalSettings (default true): inherit filtering, safe search,
	// blocked services, and upstreams from the global configuration.
	UseGlobalSettings bool `json:"use_global_settings"`
	// FilteringEnabled applies the filter engine to this client.
	FilteringEnabled bool `json:"filtering_enabled"`
	// SafeSearchEnabled applies safe-search rewrites to this client.
	SafeSearchEnabled bool `json:"safe_search_enabled"`
	// SafeSearchEngines overrides the global engine list when non-empty.
	SafeSearchEngines []string `json:"safe_search_engines,omitempty"`
	// BlockedServices overrides the global blocked-service list when
	// UseGlobalSettings is false.
	BlockedServices []string `json:"blocked_services,omitempty"`
	// Schedule limits blocked-service enforcement windows (nil = always).
	Schedule *Schedule `json:"schedule,omitempty"`
	// Upstreams overrides the global pool when non-empty.
	Upstreams []string `json:"upstreams,omitempty"`
	// ExcludeFromLog skips event emission entirely.
	ExcludeFromLog bool `json:"exclude_from_log"`
	// ExcludeFromStats emits to SSE but skips Store/forwarder persistence.
	ExcludeFromStats bool `json:"exclude_from_stats"`

	nets []cidrEntry // parsed IDs, longest-prefix first
}

// cidrEntry is one parsed client ID.
type cidrEntry struct {
	net  *net.IPNet
	bits int // prefix bits for longest-prefix ordering
}

// compile parses IDs into CIDR entries sorted longest-prefix first.
func (c *Client) compile() error {
	c.nets = nil
	for _, raw := range c.IDs {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if !strings.Contains(raw, "/") {
			ip := net.ParseIP(raw)
			if ip == nil {
				return fmt.Errorf("invalid client ID %q", raw)
			}
			if ip.To4() != nil {
				raw += "/32"
			} else {
				raw += "/128"
			}
		}
		_, n, err := net.ParseCIDR(raw)
		if err != nil {
			return fmt.Errorf("invalid client ID %q: %w", raw, err)
		}
		bits, _ := n.Mask.Size()
		c.nets = append(c.nets, cidrEntry{net: n, bits: bits})
	}
	sort.Slice(c.nets, func(i, j int) bool { return c.nets[i].bits > c.nets[j].bits })
	return nil
}

// Registry is a thread-safe client store with JSON persistence and
// hot-reload.
type Registry struct {
	mu      sync.RWMutex
	writeMu sync.Mutex
	path    string
	clients []*Client
}

// Find returns the client profile covering the given IP string, using
// longest-prefix matching; nil when no client matches.
func (r *Registry) Find(ipStr string) *Client {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	var best *Client
	bestBits := -1
	for _, c := range r.clients {
		for _, e := range c.nets {
			if e.net.Contains(ip) && e.bits > bestBits {
				best = c
				bestBits = e.bits
			}
		}
	}
	return best
}

// List returns all clients (sorted by name).
func (r *Registry) List() []Client {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Client, len(r.clients))
	for i, c := range r.clients {
		out[i] = *c
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Add validates and adds a client, persisting the registry.
func (r *Registry) Add(c Client) error {
	r.writeMu.Lock()
	defer r.writeMu.Unlock()

	r.mu.RLock()
	for _, existing := range r.clients {
		if existing.Name == c.Name {
			r.mu.RUnlock()
			return fmt.Errorf("client %q already exists", c.Name)
		}
	}
	r.mu.RUnlock()

	if err := c.compile(); err != nil {
		return err
	}
	r.mu.Lock()
	r.clients = append(r.clients, &c)
	r.mu.Unlock()
	return r.save()
}

// Update replaces the client with the same name, persisting the registry.
func (r *Registry) Update(c Client) error {
	r.writeMu.Lock()
	defer r.writeMu.Unlock()

	if err := c.compile(); err != nil {
		return err
	}
	r.mu.Lock()
	for i, existing := range r.clients {
		if existing.Name == c.Name {
			r.clients[i] = &c
			r.mu.Unlock()
			return r.save()
		}
	}
	r.mu.Unlock()
	return fmt.Errorf("client %q not found", c.Name)
}

// Delete removes a client by name, persisting the registry.
func (r *Registry) Delete(name string) bool {
	r.writeMu.Lock()
	defer r.writeMu.Unlock()

	r.mu.Lock()
	for i, existing := range r.clients {
		if existing.Name == name {
			r.clients = append(r.clients[:i], r.clients[i+1:]...)
			r.mu.Unlock()
			return r.save() == nil
		}
	}
	r.mu.Unlock()
	return false
}

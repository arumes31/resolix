// Package clients implements the per-client policy registry: JSON-persisted
// client profiles with longest-prefix IP/CIDR matching, hot-reload, and
// weekly blocking schedules.
package clients

import (
	"encoding/json"
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
	mins := now.Hour()*60 + now.Minute()
	day := strings.ToLower(now.Weekday().String()[:3])
	for _, r := range s.Days[day] {
		start, err1 := parseHHMM(r.Start)
		end, err2 := parseHHMM(r.End)
		if err1 != nil || err2 != nil {
			continue
		}
		if end == start {
			continue
		}
		if end < start {
			if mins >= start || mins < end {
				return true
			}
		} else if mins >= start && mins < end {
			return true
		}
	}
	previous := strings.ToLower(now.AddDate(0, 0, -1).Weekday().String()[:3])
	for _, r := range s.Days[previous] {
		start, err1 := parseHHMM(r.Start)
		end, err2 := parseHHMM(r.End)
		if err1 == nil && err2 == nil && end < start && mins < end {
			return true
		}
	}
	return false
}

func parseHHMM(s string) (int, error) {
	parsed, err := time.Parse("15:04", s)
	if err != nil {
		return 0, err
	}
	return parsed.Hour()*60 + parsed.Minute(), nil
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

// UnmarshalJSON preserves the documented true default when older client
// files omit use_global_settings.
func (c *Client) UnmarshalJSON(data []byte) error {
	type plain Client
	*c = Client{UseGlobalSettings: true}
	return json.Unmarshal(data, (*plain)(c))
}

// cidrEntry is one parsed client ID.
type cidrEntry struct {
	net  *net.IPNet
	bits int // prefix bits for longest-prefix ordering
}

// compile parses IDs into CIDR entries sorted longest-prefix first.
func (c *Client) compile() error {
	if strings.TrimSpace(c.Name) == "" {
		return fmt.Errorf("client name is required")
	}
	if len(c.IDs) == 0 {
		return fmt.Errorf("client %q requires at least one ID", c.Name)
	}
	c.nets = nil
	for _, raw := range c.IDs {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return fmt.Errorf("client %q contains an empty ID", c.Name)
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
	if err := validateSchedule(c.Schedule); err != nil {
		return fmt.Errorf("client %q schedule: %w", c.Name, err)
	}
	return nil
}

func validateSchedule(schedule *Schedule) error {
	if schedule == nil {
		return nil
	}
	if schedule.Timezone != "" {
		if _, err := time.LoadLocation(schedule.Timezone); err != nil {
			return fmt.Errorf("invalid timezone")
		}
	}
	validDays := map[string]bool{"mon": true, "tue": true, "wed": true, "thu": true, "fri": true, "sat": true, "sun": true}
	for day, ranges := range schedule.Days {
		if !validDays[strings.ToLower(day)] {
			return fmt.Errorf("invalid weekday %q", day)
		}
		for _, timeRange := range ranges {
			start, err := parseHHMM(timeRange.Start)
			if err != nil {
				return fmt.Errorf("invalid start time")
			}
			end, err := parseHHMM(timeRange.End)
			if err != nil || start == end {
				return fmt.Errorf("invalid end time")
			}
		}
	}
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
	if best == nil {
		return nil
	}
	copy := cloneClient(*best)
	return &copy
}

// List returns all clients (sorted by name).
func (r *Registry) List() []Client {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Client, len(r.clients))
	for i, c := range r.clients {
		out[i] = cloneClient(*c)
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
	r.mu.RLock()
	proposed := cloneClientPointers(r.clients)
	r.mu.RUnlock()
	if err := validateConflicts(proposed, &c); err != nil {
		return err
	}
	proposed = append(proposed, &c)
	if err := r.saveClients(proposed); err != nil {
		return err
	}
	r.mu.Lock()
	r.clients = proposed
	r.mu.Unlock()
	return nil
}

// Update replaces the client with the same name, persisting the registry.
func (r *Registry) Update(c Client) error {
	r.writeMu.Lock()
	defer r.writeMu.Unlock()

	if err := c.compile(); err != nil {
		return err
	}
	r.mu.RLock()
	proposed := cloneClientPointers(r.clients)
	r.mu.RUnlock()
	for i, existing := range proposed {
		if existing.Name == c.Name {
			withoutCurrent := append(cloneClientPointers(proposed[:i]), cloneClientPointers(proposed[i+1:])...)
			if err := validateConflicts(withoutCurrent, &c); err != nil {
				return err
			}
			proposed[i] = &c
			if err := r.saveClients(proposed); err != nil {
				return err
			}
			r.mu.Lock()
			r.clients = proposed
			r.mu.Unlock()
			return nil
		}
	}
	return fmt.Errorf("client %q not found", c.Name)
}

// Delete removes a client by name, persisting the registry.
func (r *Registry) Delete(name string) bool {
	r.writeMu.Lock()
	defer r.writeMu.Unlock()

	r.mu.RLock()
	proposed := cloneClientPointers(r.clients)
	r.mu.RUnlock()
	for i, existing := range proposed {
		if existing.Name == name {
			proposed = append(proposed[:i], proposed[i+1:]...)
			if r.saveClients(proposed) != nil {
				return false
			}
			r.mu.Lock()
			r.clients = proposed
			r.mu.Unlock()
			return true
		}
	}
	return false
}

func cloneClient(client Client) Client {
	client.IDs = append([]string(nil), client.IDs...)
	client.Tags = append([]string(nil), client.Tags...)
	client.SafeSearchEngines = append([]string(nil), client.SafeSearchEngines...)
	client.BlockedServices = append([]string(nil), client.BlockedServices...)
	client.Upstreams = append([]string(nil), client.Upstreams...)
	client.nets = append([]cidrEntry(nil), client.nets...)
	if client.Schedule != nil {
		schedule := *client.Schedule
		schedule.Days = make(map[string][]TimeRange, len(client.Schedule.Days))
		for day, ranges := range client.Schedule.Days {
			schedule.Days[day] = append([]TimeRange(nil), ranges...)
		}
		client.Schedule = &schedule
	}
	return client
}

func cloneClientPointers(clients []*Client) []*Client {
	out := make([]*Client, len(clients))
	for i, client := range clients {
		copy := cloneClient(*client)
		out[i] = &copy
	}
	return out
}

func validateConflicts(existing []*Client, candidate *Client) error {
	for _, client := range existing {
		for _, current := range client.nets {
			for _, next := range candidate.nets {
				if current.bits == next.bits && current.net.String() == next.net.String() {
					return fmt.Errorf("client ID conflicts with client %q", client.Name)
				}
			}
		}
	}
	return nil
}

// Package rewrites implements typed DNS rewrites with JSON persistence —
// a superset of the dnsmasq address= semantics (apex + all subdomains,
// label-boundary safe). Supported record types: A, AAAA, CNAME, PTR, MX,
// TXT, SRV, plus RCODE rewrites (NXDOMAIN, REFUSED, NOERROR-empty).
package rewrites

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Rewrite record types.
const (
	TypeA     = "A"
	TypeAAAA  = "AAAA"
	TypeCNAME = "CNAME"
	TypePTR   = "PTR"
	TypeMX    = "MX"
	TypeTXT   = "TXT"
	TypeSRV   = "SRV"
	// RCODE rewrites (no value needed).
	TypeNXDOMAIN = "NXDOMAIN" // respond NXDOMAIN
	TypeREFUSED  = "REFUSED"  // respond REFUSED
	TypeNOERROR  = "NOERROR"  // respond NOERROR with an empty answer (NODATA)
)

// AnswerTTL is the TTL applied to rewrite answers (dnsmasq local-ttl convention).
const AnswerTTL = 60

// Rewrite is a single typed DNS rewrite rule.
type Rewrite struct {
	ID             string   `json:"id"`
	Domain         string   `json:"domain"` // normalized: lowercase, no leading/trailing dot
	Type           string   `json:"type"`
	Value          string   `json:"value,omitempty"`
	SourceCIDRs    []string `json:"source_cidrs,omitempty"`
	sourcePrefixes []netip.Prefix
}

// String returns a compact human-readable form used as MatchedRule on events.
func (rw Rewrite) String() string {
	if rw.Value == "" {
		return fmt.Sprintf("%s %s", rw.Domain, rw.Type)
	}
	return fmt.Sprintf("%s %s %s", rw.Domain, rw.Type, rw.Value)
}

// matches reports whether the rewrite applies to the domain (apex + all
// subdomains, label-boundary safe).
func (rw Rewrite) matches(domain string) bool {
	return domain == rw.Domain || strings.HasSuffix(domain, "."+rw.Domain)
}

func (rw Rewrite) allowsSource(addr netip.Addr) bool {
	if len(rw.sourcePrefixes) == 0 {
		return len(rw.SourceCIDRs) == 0
	}
	if !addr.IsValid() {
		return false
	}
	for _, prefix := range rw.sourcePrefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// BuildRR constructs the DNS record for this rewrite. name is the original
// question name (with trailing dot). It returns nil when the rewrite type
// does not match the question type or the value is invalid.
func (rw Rewrite) BuildRR(name string, qtype uint16) dns.RR {
	hdr := dns.RR_Header{Name: name, Class: dns.ClassINET, Ttl: AnswerTTL}
	switch rw.Type {
	case TypeA:
		if qtype != dns.TypeA {
			return nil
		}
		ip := net.ParseIP(rw.Value)
		if ip == nil || ip.To4() == nil {
			return nil
		}
		hdr.Rrtype = dns.TypeA
		return &dns.A{Hdr: hdr, A: ip.To4()}
	case TypeAAAA:
		if qtype != dns.TypeAAAA {
			return nil
		}
		ip := net.ParseIP(rw.Value)
		if ip == nil || ip.To4() != nil {
			return nil
		}
		hdr.Rrtype = dns.TypeAAAA
		return &dns.AAAA{Hdr: hdr, AAAA: ip}
	case TypeCNAME:
		if qtype != dns.TypeA && qtype != dns.TypeAAAA && qtype != dns.TypeCNAME {
			return nil
		}
		hdr.Rrtype = dns.TypeCNAME
		return &dns.CNAME{Hdr: hdr, Target: dns.Fqdn(rw.Value)}
	case TypePTR:
		if qtype != dns.TypePTR {
			return nil
		}
		hdr.Rrtype = dns.TypePTR
		return &dns.PTR{Hdr: hdr, Ptr: dns.Fqdn(rw.Value)}
	case TypeMX:
		if qtype != dns.TypeMX {
			return nil
		}
		pref, host, ok := parseMXValue(rw.Value)
		if !ok {
			return nil
		}
		hdr.Rrtype = dns.TypeMX
		return &dns.MX{Hdr: hdr, Preference: pref, Mx: dns.Fqdn(host)}
	case TypeTXT:
		if qtype != dns.TypeTXT {
			return nil
		}
		hdr.Rrtype = dns.TypeTXT
		return &dns.TXT{Hdr: hdr, Txt: []string{rw.Value}}
	case TypeSRV:
		if qtype != dns.TypeSRV {
			return nil
		}
		prio, weight, port, target, ok := parseSRVValue(rw.Value)
		if !ok {
			return nil
		}
		hdr.Rrtype = dns.TypeSRV
		return &dns.SRV{Hdr: hdr, Priority: prio, Weight: weight, Port: port, Target: dns.Fqdn(target)}
	}
	return nil
}

// parseUint16 parses a non-negative integer that fits in a uint16.
func parseUint16(s string) (uint16, bool) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < 0 || n > math.MaxUint16 {
		return 0, false
	}
	return uint16(n), true
}

// parseMXValue parses "<preference> <host>".
func parseMXValue(value string) (pref uint16, host string, ok bool) {
	prefStr, host, found := strings.Cut(value, " ")
	if !found {
		return 0, "", false
	}
	pref, ok = parseUint16(prefStr)
	host = strings.TrimSpace(host)
	if !ok || host == "" {
		return 0, "", false
	}
	return pref, host, true
}

// parseSRVValue parses "<priority> <weight> <port> <target>".
func parseSRVValue(value string) (prio, weight, port uint16, target string, ok bool) {
	fields := strings.Fields(value)
	if len(fields) != 4 {
		return 0, 0, 0, "", false
	}
	var nums [3]uint16
	for i, f := range fields[:3] {
		nums[i], ok = parseUint16(f)
		if !ok {
			return 0, 0, 0, "", false
		}
	}
	if fields[3] == "" {
		return 0, 0, 0, "", false
	}
	return nums[0], nums[1], nums[2], fields[3], true
}

// Validate checks a rewrite for well-formedness (used by the API).
func Validate(domain, typ, value string) error {
	domain = NormalizeDomain(domain)
	if domain == "" || !strings.Contains(domain, ".") && domain != "localhost" {
		return fmt.Errorf("invalid domain %q", domain)
	}
	switch typ {
	case TypeA:
		if ip := net.ParseIP(value); ip == nil || ip.To4() == nil {
			return fmt.Errorf("type A requires an IPv4 address value")
		}
	case TypeAAAA:
		if ip := net.ParseIP(value); ip == nil || ip.To4() != nil {
			return fmt.Errorf("type AAAA requires an IPv6 address value")
		}
	case TypeCNAME, TypePTR:
		if NormalizeDomain(value) == "" {
			return fmt.Errorf("type %s requires a target domain value", typ)
		}
	case TypeMX:
		rw := Rewrite{Type: typ, Value: value}
		if rw.BuildRR("example.com.", dns.TypeMX) == nil {
			return fmt.Errorf("type MX requires value '<preference> <host>'")
		}
	case TypeTXT:
		if value == "" {
			return fmt.Errorf("type TXT requires a non-empty value")
		}
		if len(value) > 255 {
			return fmt.Errorf("type TXT value must not exceed 255 bytes")
		}
	case TypeSRV:
		rw := Rewrite{Type: typ, Value: value}
		if rw.BuildRR("_sip._tcp.example.com.", dns.TypeSRV) == nil {
			return fmt.Errorf("type SRV requires value '<priority> <weight> <port> <target>'")
		}
	case TypeNXDOMAIN, TypeREFUSED, TypeNOERROR:
	default:
		return fmt.Errorf("unsupported rewrite type %q", typ)
	}
	return nil
}

// NormalizeDomain canonicalizes a rewrite domain.
func NormalizeDomain(d string) string {
	d = strings.ToLower(strings.TrimSpace(d))
	d = strings.TrimPrefix(d, ".")
	return strings.TrimSuffix(d, ".")
}

func prepareRewrite(item Rewrite) (Rewrite, error) {
	item.Domain = NormalizeDomain(item.Domain)
	item.Type = strings.ToUpper(strings.TrimSpace(item.Type))
	item.Value = strings.TrimSpace(item.Value)
	if err := Validate(item.Domain, item.Type, item.Value); err != nil {
		return Rewrite{}, err
	}

	const maxSourceCIDRs = 64
	if len(item.SourceCIDRs) > maxSourceCIDRs {
		return Rewrite{}, fmt.Errorf("source CIDRs must not exceed %d entries", maxSourceCIDRs)
	}
	normalized := make([]string, 0, len(item.SourceCIDRs))
	prefixes := make([]netip.Prefix, 0, len(item.SourceCIDRs))
	seen := make(map[netip.Prefix]struct{}, len(item.SourceCIDRs))
	for _, raw := range item.SourceCIDRs {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil {
			return Rewrite{}, fmt.Errorf("invalid source CIDR %q", raw)
		}
		prefix = prefix.Masked()
		if _, duplicate := seen[prefix]; duplicate {
			continue
		}
		seen[prefix] = struct{}{}
		normalized = append(normalized, prefix.String())
		prefixes = append(prefixes, prefix)
	}
	item.SourceCIDRs = normalized
	item.sourcePrefixes = prefixes
	if item.ID == "" {
		item.ID = newID()
	}
	return item, nil
}

func cloneRewrite(item Rewrite) Rewrite {
	item.SourceCIDRs = append([]string(nil), item.SourceCIDRs...)
	item.sourcePrefixes = append([]netip.Prefix(nil), item.sourcePrefixes...)
	return item
}

// Store is a thread-safe rewrite set with JSON persistence.
type Store struct {
	mu      sync.RWMutex
	writeMu sync.Mutex
	path    string
	items   []Rewrite
}

// Load opens the rewrites file at path. When the file does not exist (first
// boot), the store is seeded from the DOMAINS env value (comma-separated
// domain:ip pairs become A rewrites) and persisted; an existing file is
// never overwritten by seeding. An empty path yields an in-memory store
// still seeded from seedDomains.
func Load(path, seedDomains string) (*Store, error) {
	s := &Store{path: path}
	if path != "" {
		data, err := os.ReadFile(path) // #nosec G304 -- rewrites path comes from trusted config (env/defaults), not request input
		if err == nil {
			if err := json.Unmarshal(data, &s.items); err != nil {
				return nil, fmt.Errorf("parse rewrites file %s: %w", path, err)
			}
			for i, item := range s.items {
				prepared, err := prepareRewrite(item)
				if err != nil {
					return nil, fmt.Errorf("validate rewrite %d in %s: %w", i+1, path, err)
				}
				s.items[i] = prepared
			}
			return s, nil
		}
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("read rewrites file %s: %w", path, err)
		}
	}

	// First boot: seed from DOMAINS env (dnsmasq address=/ semantics).
	for _, pair := range strings.Split(seedDomains, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		domain, ip, ok := strings.Cut(pair, ":")
		if !ok {
			continue
		}
		domain = NormalizeDomain(domain)
		ip = strings.TrimSpace(ip)
		if domain == "" || net.ParseIP(ip) == nil || net.ParseIP(ip).To4() == nil {
			continue
		}
		s.items = append(s.items, Rewrite{ID: newID(), Domain: domain, Type: TypeA, Value: ip})
	}
	if err := s.save(); err != nil {
		return nil, err
	}
	return s, nil
}

// Lookup returns all rewrites matching the domain.
func (s *Store) Lookup(domain string) []Rewrite {
	return s.lookup(domain, netip.Addr{}, false)
}

// LookupForClient returns rewrites matching both the domain and source IP.
func (s *Store) LookupForClient(domain, clientIP string) []Rewrite {
	addr, _ := netip.ParseAddr(strings.TrimSpace(clientIP))
	return s.lookup(domain, addr.Unmap(), true)
}

func (s *Store) lookup(domain string, sourceAddr netip.Addr, filterSource bool) []Rewrite {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Rewrite, 0)
	for _, rw := range s.items {
		if !rw.matches(domain) {
			continue
		}
		if filterSource && !rw.allowsSource(sourceAddr) {
			continue
		}
		out = append(out, cloneRewrite(rw))
	}
	return out
}

// List returns all rewrites, sorted by domain then type.
func (s *Store) List() []Rewrite {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Rewrite, len(s.items))
	for i, item := range s.items {
		out[i] = cloneRewrite(item)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Domain != out[j].Domain {
			return out[i].Domain < out[j].Domain
		}
		return out[i].Type < out[j].Type
	})
	return out
}

// Replace validates and atomically persists a complete rewrite set.
func (s *Store) Replace(items []Rewrite) error {
	validated := make([]Rewrite, len(items))
	for i, item := range items {
		prepared, err := prepareRewrite(item)
		if err != nil {
			return fmt.Errorf("rewrite %d: %w", i+1, err)
		}
		validated[i] = prepared
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if err := s.saveItems(validated); err != nil {
		return err
	}
	s.mu.Lock()
	s.items = validated
	s.mu.Unlock()
	return nil
}

// Add validates and stores a new rewrite, persisting the store.
func (s *Store) Add(domain, typ, value string, sourceCIDRs ...string) (Rewrite, error) {
	rw, err := prepareRewrite(Rewrite{Domain: domain, Type: typ, Value: value, SourceCIDRs: sourceCIDRs})
	if err != nil {
		return Rewrite{}, err
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.mu.Lock()
	s.items = append(s.items, rw)
	s.mu.Unlock()
	if err := s.save(); err != nil {
		s.mu.Lock()
		s.items = s.items[:len(s.items)-1]
		s.mu.Unlock()
		return Rewrite{}, err
	}
	return rw, nil
}

// Update replaces an existing rewrite by ID. The validated replacement is
// persisted before it becomes visible to DNS lookups.
func (s *Store) Update(id, domain, typ, value string, sourceCIDRs ...string) (updated Rewrite, found bool, err error) {
	rw, err := prepareRewrite(Rewrite{
		ID:          id,
		Domain:      domain,
		Type:        typ,
		Value:       value,
		SourceCIDRs: sourceCIDRs,
	})
	if err != nil {
		return Rewrite{}, false, err
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	s.mu.RLock()
	items := make([]Rewrite, len(s.items))
	for i, item := range s.items {
		items[i] = cloneRewrite(item)
	}
	s.mu.RUnlock()

	idx := -1
	for i, item := range items {
		if item.ID == id {
			idx = i
			break
		}
	}
	if idx < 0 {
		return Rewrite{}, false, nil
	}
	items[idx] = rw
	if err := s.saveItems(items); err != nil {
		return Rewrite{}, true, err
	}

	s.mu.Lock()
	s.items = items
	s.mu.Unlock()
	return cloneRewrite(rw), true, nil
}

// Delete removes a rewrite by ID, persisting the store. found is false when
// the ID does not exist; persistence failures are returned separately.
func (s *Store) Delete(id string) (found bool, err error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	s.mu.Lock()
	idx := -1
	for i, rw := range s.items {
		if rw.ID == id {
			idx = i
			break
		}
	}
	if idx < 0 {
		s.mu.Unlock()
		return false, nil
	}
	removed := s.items[idx]
	s.items = append(s.items[:idx], s.items[idx+1:]...)
	s.mu.Unlock()

	if err := s.save(); err != nil {
		// Roll back the in-memory delete to stay consistent with the file.
		// writeMu guarantees no concurrent mutation, so idx is still valid.
		s.mu.Lock()
		if idx > len(s.items) {
			idx = len(s.items)
		}
		s.items = append(s.items[:idx], append([]Rewrite{removed}, s.items[idx:]...)...)
		s.mu.Unlock()
		return true, err
	}
	return true, nil
}

// save persists the store atomically (temp file + rename). No-op for
// in-memory stores (empty path).
func (s *Store) save() error {
	s.mu.RLock()
	items := append([]Rewrite(nil), s.items...)
	s.mu.RUnlock()
	return s.saveItems(items)
}

func (s *Store) saveItems(items []Rewrite) error {
	if s.path == "" {
		return nil
	}
	data, err := json.MarshalIndent(items, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(s.path, data, 0o600)
}

// writeFileAtomic writes data to path via a temp file + rename.
func writeFileAtomic(path string, data []byte, mode os.FileMode) (err error) {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".rewrites-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = tmp.Close()
		if err != nil {
			_ = os.Remove(tmpPath)
		}
	}()
	if err = tmp.Chmod(mode); err != nil {
		return err
	}
	if _, err = tmp.Write(data); err != nil {
		return err
	}
	if err = tmp.Sync(); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmpPath, path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer func() { _ = dir.Close() }()
	if err = dir.Sync(); err != nil && runtime.GOOS != "windows" {
		return err
	}
	return nil
}

// newID returns a short random hex ID.
func newID() string {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failure is non-fatal for an ID; fall back to time.
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

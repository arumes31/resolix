// Package policy implements DNS policy features: safe-search CNAME
// rewrites, bogus-NXDOMAIN conversion, AAAA disable, and refuse-ANY.
package policy

import (
	"log"
	"net"
	"strings"

	"github.com/miekg/dns"
)

// Safe-search engine identifiers and their restricted targets.
const (
	ReasonSafeSearch   = "SafeSearch"
	ReasonBogusNX      = "BogusNXDOMAIN"
	ReasonRefusedANY   = "RefusedANY"
	ReasonAAAADisabled = "AAAADisabled"

	googleTarget  = "forcesafesearch.google.com"
	bingTarget    = "strict.bing.com"
	ddgTarget     = "safe.duckduckgo.com"
	youtubeTarget = "restrict.youtube.com" // "restrict" (not moderate) by default
)

// youtubeHosts are the YouTube frontends redirected to the restricted mode.
var youtubeHosts = map[string]string{
	"youtube.com":              youtubeTarget,
	"www.youtube.com":          youtubeTarget,
	"m.youtube.com":            youtubeTarget,
	"youtubei.googleapis.com":  youtubeTarget,
	"youtube.googleapis.com":   youtubeTarget,
	"www.youtube-nocookie.com": youtubeTarget,
	"youtube-nocookie.com":     youtubeTarget,
}

// Config holds policy settings.
type Config struct {
	// SafeSearch lists enabled engines: google, bing, ddg, youtube.
	SafeSearch []string
	// BogusNets lists CIDRs/IPs considered bogus upstream answers.
	BogusNets []string
	// AAAADisabled makes AAAA queries return NOERROR-empty (NODATA).
	AAAADisabled bool
	// RefuseANY refuses QTYPE ANY queries.
	RefuseANY bool
}

// Policy evaluates DNS policy rules.
type Policy struct {
	engines      map[string]bool
	bogusNets    []*net.IPNet
	AAAADisabled bool
	RefuseANY    bool
}

// New builds a Policy from the configuration. Invalid bogus CIDR entries are
// skipped with a warning.
func New(cfg Config) *Policy {
	p := &Policy{
		engines:      make(map[string]bool),
		AAAADisabled: cfg.AAAADisabled,
		RefuseANY:    cfg.RefuseANY,
	}
	for _, eng := range cfg.SafeSearch {
		eng = strings.ToLower(strings.TrimSpace(eng))
		switch eng {
		case "":
		case "google", "bing", "ddg", "youtube":
			p.engines[eng] = true
		default:
			log.Printf("[WARN] Unknown SAFE_SEARCH engine: %q", eng)
		}
	}
	for _, raw := range cfg.BogusNets {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		cidr := raw
		if !strings.Contains(cidr, "/") {
			if ip := net.ParseIP(raw); ip != nil {
				if ip.To4() != nil {
					cidr = raw + "/32"
				} else {
					cidr = raw + "/128"
				}
			}
		}
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Printf("[WARN] Invalid BOGUS_NXDOMAIN entry: %q", raw)
			continue
		}
		p.bogusNets = append(p.bogusNets, network)
	}
	return p
}

// Enabled reports whether any policy feature is active.
func (p *Policy) Enabled() bool {
	return len(p.engines) > 0 || len(p.bogusNets) > 0 || p.AAAADisabled || p.RefuseANY
}

// RefuseANYEnabled reports whether QTYPE ANY should be refused.
func (p *Policy) RefuseANYEnabled() bool { return p != nil && p.RefuseANY }

// AAAADisabledEnabled reports whether AAAA queries get NODATA answers.
func (p *Policy) AAAADisabledEnabled() bool { return p != nil && p.AAAADisabled }

// SafeSearchTarget returns the restricted-variant CNAME target for the
// domain, or "" when no enabled engine matches. domain must be normalized
// (lowercase, no trailing dot).
func (p *Policy) SafeSearchTarget(domain string) string {
	if p == nil || len(p.engines) == 0 {
		return ""
	}
	if p.engines["google"] {
		// google.com and every www.google.<TLD> / google.<TLD> variant.
		if domain == "google.com" || strings.HasPrefix(domain, "www.google.") || strings.HasPrefix(domain, "google.") {
			return googleTarget
		}
	}
	if p.engines["bing"] && (domain == "bing.com" || domain == "www.bing.com") {
		return bingTarget
	}
	if p.engines["ddg"] && (domain == "duckduckgo.com" || domain == "www.duckduckgo.com") {
		return ddgTarget
	}
	if p.engines["youtube"] {
		if target, ok := youtubeHosts[domain]; ok {
			return target
		}
	}
	return ""
}

// IsBogusAnswer reports whether every A/AAAA record in the answer section
// falls within the configured bogus ranges (anti-poisoning). Answers without
// any A/AAAA records are never bogus.
func (p *Policy) IsBogusAnswer(answers []dns.RR) bool {
	if p == nil || len(p.bogusNets) == 0 {
		return false
	}
	seen := false
	for _, rr := range answers {
		var ip net.IP
		switch v := rr.(type) {
		case *dns.A:
			ip = v.A
		case *dns.AAAA:
			ip = v.AAAA
		default:
			continue
		}
		seen = true
		if !p.inBogusNets(ip) {
			return false
		}
	}
	return seen
}

func (p *Policy) inBogusNets(ip net.IP) bool {
	for _, n := range p.bogusNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

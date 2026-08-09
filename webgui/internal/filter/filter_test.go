package filter

import (
	"strings"
	"testing"
)

func TestParseLineFormats(t *testing.T) {
	tests := []struct {
		name        string
		line        string
		wantOK      bool
		wantExcept  bool
		wantDomain  string // expected domain for domain rules
		wantMatches []string
		wantMisses  []string
	}{
		{name: "adblock block", line: "||ads.example.com^", wantOK: true, wantDomain: "ads.example.com",
			wantMatches: []string{"ads.example.com", "www.ads.example.com", "deep.sub.ads.example.com"},
			wantMisses:  []string{"example.com", "notads.example.com", "ads.example.com.evil.net"}},
		{name: "adblock block no caret", line: "||ads.example.com", wantOK: true, wantDomain: "ads.example.com",
			wantMatches: []string{"ads.example.com", "x.ads.example.com"}},
		{name: "exception", line: "@@||good.example.com^", wantOK: true, wantExcept: true, wantDomain: "good.example.com",
			wantMatches: []string{"good.example.com", "api.good.example.com"}},
		{name: "plain domain", line: "tracker.example.org", wantOK: true, wantDomain: "tracker.example.org",
			wantMatches: []string{"tracker.example.org", "cdn.tracker.example.org"},
			wantMisses:  []string{"nottracker.example.org"}},
		{name: "hosts format zeros", line: "0.0.0.0 malware.example.net", wantOK: true, wantDomain: "malware.example.net",
			wantMatches: []string{"malware.example.net", "dl.malware.example.net"}},
		{name: "hosts format localhost ip", line: "127.0.0.1 bad.example.net", wantOK: true, wantDomain: "bad.example.net"},
		{name: "hosts format ipv6", line: "::1 v6.example.net", wantOK: true, wantDomain: "v6.example.net"},
		{name: "regex", line: "/^ads[0-9]+\\./", wantOK: true,
			wantMatches: []string{"ads1.example.com", "ads42.foo.net"},
			wantMisses:  []string{"ads.example.com", "example.com"}},
		{name: "regex exception", line: "@@/^trusted\\./", wantOK: true, wantExcept: true,
			wantMatches: []string{"trusted.example.com"}},
		{name: "single-pipe anchor", line: "|anchored.example.com", wantOK: true, wantDomain: "anchored.example.com"},
		{name: "trailing pipe anchor", line: "tail.example.com|", wantOK: true, wantDomain: "tail.example.com"},
		{name: "options stripped", line: "||opt.example.com^$third-party", wantOK: true, wantDomain: "opt.example.com"},

		{name: "comment bang", line: "! comment", wantOK: false},
		{name: "comment hash", line: "# comment", wantOK: false},
		{name: "header", line: "[Adblock Plus 2.0]", wantOK: false},
		{name: "cosmetic", line: "example.com##.ad-banner", wantOK: false},
		{name: "cosmetic exception", line: "example.com#@#.ad-banner", wantOK: false},
		{name: "cosmetic scriptlet", line: "example.com#?#.ad-banner", wantOK: false},
		{name: "wildcard unsupported", line: "||ads.*.example.com^", wantOK: false},
		{name: "empty", line: "   ", wantOK: false},
		{name: "not a domain", line: "###", wantOK: false},
		{name: "single label", line: "localhost", wantOK: false},
		{name: "hosts localhost entry", line: "127.0.0.1 localhost", wantOK: false},
		{name: "bad regex", line: "/[unclosed/", wantOK: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule, exception, ok := parseLine(tt.line)
			if ok != tt.wantOK {
				t.Fatalf("parseLine(%q) ok = %v, want %v", tt.line, ok, tt.wantOK)
			}
			if !ok {
				return
			}
			if exception != tt.wantExcept {
				t.Errorf("parseLine(%q) exception = %v, want %v", tt.line, exception, tt.wantExcept)
			}
			if tt.wantDomain != "" && rule.domain != tt.wantDomain {
				t.Errorf("parseLine(%q) domain = %q, want %q", tt.line, rule.domain, tt.wantDomain)
			}
			if rule.Raw != strings.TrimSpace(tt.line) {
				t.Errorf("Raw = %q, want original line %q", rule.Raw, tt.line)
			}
			for _, m := range tt.wantMatches {
				if !rule.matches(m) {
					t.Errorf("rule %q should match %q", tt.line, m)
				}
			}
			for _, m := range tt.wantMisses {
				if rule.matches(m) {
					t.Errorf("rule %q should NOT match %q", tt.line, m)
				}
			}
		})
	}
}

func TestParseRulesAllowOnly(t *testing.T) {
	content := "||ads.example.com^\nplain.example.org\n0.0.0.0 hosts.example.net\n"

	block, allow := parseRules(strings.NewReader(content), false)
	if len(block) != 3 || len(allow) != 0 {
		t.Errorf("normal parse: block=%d allow=%d, want 3/0", len(block), len(allow))
	}

	block, allow = parseRules(strings.NewReader(content), true)
	if len(block) != 0 || len(allow) != 3 {
		t.Errorf("allowOnly parse: block=%d allow=%d, want 0/3", len(block), len(allow))
	}
}

func TestEngineMatchPrecedence(t *testing.T) {
	e := New()
	src := e.AddFileSource(writeTempList(t, "||ads.example.com^\n||tracker.example.org^\n"), false)
	allowSrc := e.AddFileSource(writeTempList(t, "@@||good.ads.example.com^\n"), true)
	_ = src
	_ = allowSrc

	tests := []struct {
		domain      string
		wantBlocked bool
		wantAllowed bool
	}{
		{"ads.example.com", true, false},
		{"sub.ads.example.com", true, false},
		{"good.ads.example.com", false, true}, // exception wins
		{"tracker.example.org", true, false},
		{"example.com", false, false},
	}
	for _, tt := range tests {
		res := e.Match(tt.domain)
		if res.Blocked != tt.wantBlocked || res.Allowed != tt.wantAllowed {
			t.Errorf("Match(%q) = blocked:%v allowed:%v, want %v/%v",
				tt.domain, res.Blocked, res.Allowed, tt.wantBlocked, tt.wantAllowed)
		}
	}

	// Matched rule and source are reported.
	res := e.Match("ads.example.com")
	if res.Rule != "||ads.example.com^" {
		t.Errorf("matched rule = %q", res.Rule)
	}
	if res.Source == "" || res.Reason != ReasonBlocklist {
		t.Errorf("result metadata: %+v", res)
	}

	// 3 blocked matches from the table + 1 from the metadata probe above.
	blocked, allowed := e.Stats()
	if blocked != 4 || allowed != 1 {
		t.Errorf("stats = %d/%d, want 4/1", blocked, allowed)
	}
}

func TestEngineRegexReason(t *testing.T) {
	e := New()
	e.AddFileSource(writeTempList(t, "/^ads[0-9]+\\./\n"), false)
	res := e.Match("ads7.example.com")
	if !res.Blocked || res.Reason != ReasonRegex {
		t.Errorf("regex match = %+v", res)
	}
}

func TestEnginePauseResume(t *testing.T) {
	e := New()
	if e.Paused() {
		t.Fatal("new engine must not be paused")
	}
	e.Pause(5)
	if !e.Paused() {
		t.Fatal("engine must be paused after Pause(5)")
	}
	if e.PausedUntil().IsZero() {
		t.Error("PausedUntil must report the deadline")
	}
	e.Pause(0) // resume now
	if e.Paused() {
		t.Fatal("Pause(0) must resume")
	}
	if !e.PausedUntil().IsZero() {
		t.Error("PausedUntil must be zero after resume")
	}
}

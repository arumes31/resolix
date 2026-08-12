// Package filter implements the DNS filtering rule engine: Adblock-syntax
// subset, hosts-file and plain domain-list formats, /regex/ rules, exception
// (@@) handling, local files, and remote URL subscriptions with conditional
// (ETag/Last-Modified) auto-updates.
package filter

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"regexp"
	"strings"
)

// RuleDiagnostic identifies a custom-rule line that will not become an
// active DNS rule.
type RuleDiagnostic struct {
	Line     int    `json:"line"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

// MaxRuleDiagnostics bounds validation responses for large invalid rule sets.
const MaxRuleDiagnostics = 100

// ValidateRuleText reports actionable syntax diagnostics with stable line
// numbers while accepting comments, headers, and blank lines.
func ValidateRuleText(text string) (accepted int, diagnostics []RuleDiagnostic) {
	appendDiagnostic := func(diagnostic RuleDiagnostic) {
		if len(diagnostics) < MaxRuleDiagnostics {
			diagnostics = append(diagnostics, diagnostic)
		}
	}
	scanner := bufio.NewScanner(strings.NewReader(text))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		raw := strings.TrimSpace(scanner.Text())
		if raw == "" || strings.HasPrefix(raw, "#") || strings.HasPrefix(raw, "!") ||
			(strings.HasPrefix(raw, "[") && strings.HasSuffix(raw, "]")) {
			continue
		}
		if strings.Contains(raw, "##") || strings.Contains(raw, "#?#") || strings.Contains(raw, "#@#") {
			appendDiagnostic(RuleDiagnostic{Line: lineNumber, Severity: "warning", Message: "cosmetic rules do not affect DNS and will be ignored"})
			continue
		}
		body := strings.TrimPrefix(raw, "@@")
		if strings.HasPrefix(body, "/") && strings.HasSuffix(body, "/") {
			pattern := body[1 : len(body)-1]
			if pattern == "" {
				appendDiagnostic(RuleDiagnostic{Line: lineNumber, Severity: "error", Message: "regular expression may not be empty"})
				continue
			}
			if _, err := regexp.Compile(pattern); err != nil {
				appendDiagnostic(RuleDiagnostic{Line: lineNumber, Severity: "error", Message: fmt.Sprintf("invalid RE2 expression: %v", err)})
				continue
			}
			accepted++
			continue
		}
		if i := strings.Index(body, "$"); i >= 0 {
			body = body[:i]
		}
		if strings.Contains(body, "*") {
			appendDiagnostic(RuleDiagnostic{Line: lineNumber, Severity: "error", Message: "wildcards are unsupported; use a domain suffix or /RE2/ expression"})
			continue
		}
		if _, _, ok := parseLine(raw); !ok {
			appendDiagnostic(RuleDiagnostic{Line: lineNumber, Severity: "error", Message: "unsupported or invalid DNS filter rule"})
			continue
		}
		accepted++
	}
	if err := scanner.Err(); err != nil {
		appendDiagnostic(RuleDiagnostic{Line: lineNumber + 1, Severity: "error", Message: fmt.Sprintf("read rules: %v", err)})
	}
	return accepted, diagnostics
}

// ruleKind distinguishes domain-suffix rules from regex rules.
type ruleKind int

const (
	kindDomain ruleKind = iota
	kindRegex
)

// Rule is a single parsed filter rule. Raw preserves the original line for
// query-log parity (MatchedRule).
type Rule struct {
	Raw    string
	kind   ruleKind
	domain string
	re     *regexp.Regexp
}

// matches reports whether the rule matches the given normalized domain
// (lowercase, no trailing dot).
func (r Rule) matches(domain string) bool {
	if r.kind == kindRegex {
		return r.re.MatchString(domain)
	}
	return matchDomainSuffix(r.domain, domain)
}

// matchDomainSuffix matches the apex and any subdomain at label boundaries
// (badexample.com does NOT match example.com).
func matchDomainSuffix(ruleDomain, domain string) bool {
	return domain == ruleDomain || strings.HasSuffix(domain, "."+ruleDomain)
}

// parseLine parses a single rule line. It returns the parsed rule, whether
// it is an exception (allow) rule, and whether the line was a usable rule at
// all (comments, cosmetic rules, and unsupported syntax return ok == false).
//
// Supported syntax (documented subset):
//   - ||domain^ and ||domain — block domain + all subdomains
//   - @@<rule> — exception (allow) for any supported rule form
//   - |domain / domain| — anchors, treated as plain domain rules
//   - plain domain.com — block domain + all subdomains
//   - hosts format: "0.0.0.0 domain", "127.0.0.1 domain", "::1 domain"
//   - /REGEX/ — RE2 regular expression against the full domain
//
// Explicitly skipped: cosmetic rules (##, #?#, #@#), comments (#, !),
// [Adblock Plus] headers, option lists after '$' (stripped and ignored),
// and rules containing '*' wildcards.
func parseLine(line string) (rule Rule, exception, ok bool) {
	raw := strings.TrimSpace(line)
	if raw == "" {
		return Rule{}, false, false
	}
	// Comments (adblock '!', hosts '#') and section headers.
	if strings.HasPrefix(raw, "#") || strings.HasPrefix(raw, "!") {
		return Rule{}, false, false
	}
	if strings.HasPrefix(raw, "[") && strings.HasSuffix(raw, "]") {
		return Rule{}, false, false
	}
	// Cosmetic/element-hiding rules are not DNS rules.
	if strings.Contains(raw, "##") || strings.Contains(raw, "#?#") || strings.Contains(raw, "#@#") {
		return Rule{}, false, false
	}

	body := raw
	if strings.HasPrefix(body, "@@") {
		exception = true
		body = body[2:]
	}

	// Regex rule (with optional @@ prefix).
	if len(body) >= 2 && strings.HasPrefix(body, "/") && strings.HasSuffix(body, "/") {
		pattern := body[1 : len(body)-1]
		if pattern == "" {
			return Rule{}, false, false
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			log.Printf("[DEBUG] filter: skipping invalid regex rule %q: %v", raw, err)
			return Rule{}, false, false
		}
		return Rule{Raw: raw, kind: kindRegex, re: re}, exception, true
	}

	// Adblock option list ($third-party etc.) — unsupported, ignored.
	if i := strings.Index(body, "$"); i >= 0 {
		body = body[:i]
	}

	// Hosts-file format: leading IP field.
	if fields := strings.Fields(body); len(fields) >= 2 && net.ParseIP(fields[0]) != nil {
		domain := normalizeDomain(fields[1])
		if !validDomain(domain) {
			return Rule{}, false, false
		}
		return Rule{Raw: raw, kind: kindDomain, domain: domain}, exception, true
	}

	// Adblock anchors: ||domain, |domain, trailing ^ separator, trailing |.
	body = strings.TrimPrefix(body, "||")
	body = strings.TrimPrefix(body, "|")
	body = strings.TrimSuffix(body, "^")
	body = strings.TrimSuffix(body, "|")

	// Wildcards are not supported in this subset.
	if strings.Contains(body, "*") {
		return Rule{}, false, false
	}

	domain := normalizeDomain(body)
	if !validDomain(domain) {
		return Rule{}, false, false
	}
	return Rule{Raw: raw, kind: kindDomain, domain: domain}, exception, true
}

// normalizeDomain lowercases a domain and strips leading/trailing dots and
// whitespace.
func normalizeDomain(d string) string {
	d = strings.ToLower(strings.TrimSpace(d))
	d = strings.TrimPrefix(d, ".")
	return strings.TrimSuffix(d, ".")
}

// validDomain reports whether d is a plausible domain name: contains a dot,
// and only letters, digits, hyphen, underscore, and dot.
func validDomain(d string) bool {
	if len(d) < 3 || !strings.Contains(d, ".") {
		return false
	}
	for _, c := range d {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '_' && c != '.' {
			return false
		}
	}
	return true
}

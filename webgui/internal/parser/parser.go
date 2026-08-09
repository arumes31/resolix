// Package parser handles the logic of extracting DNS events from raw
// dnsmasq log lines. It uses a sync.Pool for byte buffers to reduce
// GC pressure under high log ingestion rates.
package parser

import (
	"bytes"
	"log"
	"strings"
	"sync"
	"time"

	"tailscale-dnsrewrite/webgui/internal/models"
	"tailscale-dnsrewrite/webgui/internal/storage"
)

// bufPool is a sync.Pool for byte buffers used during log parsing.
// Reusing buffers reduces GC pressure under high log ingestion rates.
var bufPool = sync.Pool{
	New: func() interface{} {
		return bytes.NewBuffer(make([]byte, 0, 4096))
	},
}

// getBuffer retrieves a buffer from the pool.
func getBuffer() *bytes.Buffer {
	return bufPool.Get().(*bytes.Buffer)
}

// putBuffer resets and returns a buffer to the pool.
func putBuffer(b *bytes.Buffer) {
	b.Reset()
	bufPool.Put(b)
}

// Parser handles the logic of extracting DNS events from raw log lines.
type Parser struct {
	store *storage.Store
	Debug bool
}

// NewParser creates a new log parser instance.
func NewParser(store *storage.Store, debug bool) *Parser {
	return &Parser{store: store, Debug: debug}
}

// ParseLogBytes parses a raw dnsmasq log line and updates the store.
//
//nolint:gocyclo
func (p *Parser) ParseLogBytes(line []byte, node string) *models.QueryEvent {
	now := time.Now()
	if bytes.Contains(line, []byte("validation|")) {
		p.parseDNSSECPipe(line, node)
		return nil
	}
	parts := bytes.Fields(line)
	if len(parts) < 2 {
		return nil
	}

	actionIdx := -1
	for i, pt := range parts {
		if bytes.HasPrefix(pt, []byte("query[")) ||
			bytes.Equal(pt, []byte("forwarded")) ||
			bytes.Equal(pt, []byte("reply")) ||
			bytes.Equal(pt, []byte("config")) ||
			bytes.Equal(pt, []byte("cached")) ||
			bytes.Equal(pt, []byte("validation")) {
			actionIdx = i
			break
		}
	}

	if actionIdx == -1 {
		return nil
	}

	action := parts[actionIdx]

	normalize := func(d string) string {
		return strings.ToLower(strings.TrimSuffix(d, "."))
	}

	// --- DNSSEC validation lines ---
	// dnsmasq logs: "validation|dnsmasq.org|IN|secure" or similar patterns
	// Also: "dnsmasq: validation dnsmasq.org IN secure"
	if bytes.Equal(action, []byte("validation")) {
		p.parseDNSSEC(parts, actionIdx, node)
		return nil
	}

	if bytes.HasPrefix(action, []byte("query[")) {
		if len(action) < 8 { // Must be at least query[A]
			return nil
		}
		qType := string(action[6 : len(action)-1])

		// Items 69 & 70: AAAA, SRV, TXT are handled naturally by extracting qType
		// The parser already handles any query type inside brackets: query[AAAA], query[SRV], query[TXT]
		if len(parts) < actionIdx+4 || string(parts[actionIdx+2]) != "from" {
			return nil
		}
		domain := normalize(string(parts[actionIdx+1]))
		clientIP := string(parts[actionIdx+3])

		var parsedTime time.Time
		if actionIdx >= 3 {
			// Use pooled buffer for timestamp joining
			buf := getBuffer()
			for i, pt := range parts[:3] {
				if i > 0 {
					buf.WriteByte(' ')
				}
				buf.Write(pt)
			}
			tsStr := buf.String()
			putBuffer(buf)

			t, err := time.Parse(time.Stamp, tsStr)
			if err == nil {
				nowYear := now.Year()
				parsedTime = time.Date(nowYear, t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), 0, time.Local)
				if parsedTime.After(now) {
					parsedTime = parsedTime.AddDate(-1, 0, 0)
				}
			} else {
				parsedTime = now
			}
		} else {
			parsedTime = now
		}

		event := models.QueryEvent{
			UnixTime: parsedTime.Unix(),
			Type:     qType,
			Domain:   domain,
			ClientIP: clientIP,
			Node:     node,
			Alias:    p.store.GetAlias(clientIP),
		}

		p.store.SetPending(node, domain, parsedTime)
		p.store.AddEvent(event)
		return &event
	}

	if bytes.Equal(action, []byte("forwarded")) {
		if len(parts) >= actionIdx+4 && string(parts[actionIdx+2]) == "to" {
			domain := normalize(string(parts[actionIdx+1]))
			upstream := string(parts[actionIdx+3])
			p.store.SetUpstream(node, domain, upstream)
		}
		return nil
	}

	if bytes.Equal(action, []byte("reply")) || bytes.Equal(action, []byte("cached")) || bytes.Equal(action, []byte("config")) {
		if len(parts) >= actionIdx+2 {
			domain := normalize(string(parts[actionIdx+1]))
			startTime, pendingUpstream, ok := p.store.GetPending(node, domain)
			upstream := ""
			switch {
			case bytes.Equal(action, []byte("reply")):
				upstream = pendingUpstream
				// Feature #200: Recognize internal override instance
				if upstream == "127.0.0.1#5353" {
					upstream = "Local Override"
				}
			case bytes.Equal(action, []byte("cached")):
				upstream = "System Cache"
			case bytes.Equal(action, []byte("config")):
				upstream = "Local Override"
			default:
				upstream = string(action)
			}

			// Item 64: Parse DNS response codes from reply lines
			responseCode := parseResponseCode(actionIdx, parts)

			if ok {
				latency := float64(now.Sub(startTime).Microseconds()) / 1000.0
				if latency < 0 {
					latency = 0
				}
				return p.store.UpdateEvent(node, domain, latency, upstream, responseCode)
			} else if bytes.Equal(action, []byte("reply")) {
				// Debug: why was it not found?
				if p.Debug {
					log.Printf("[DEBUG] No pending query found for domain=%s node=%s", domain, node)
				}
			}
		}
		return nil
	}
	return nil
}

// parseDNSSEC handles space-delimited DNSSEC validation log lines.
// Format: "validation <domain> <class> <result>"
func (p *Parser) parseDNSSEC(parts [][]byte, actionIdx int, node string) {
	// Expected: validation <domain> <class> <result>
	// e.g., "validation dnsmasq.org IN secure"
	if len(parts) < actionIdx+4 {
		return
	}
	domain := strings.ToLower(strings.TrimSuffix(string(parts[actionIdx+1]), "."))
	result := strings.ToLower(string(parts[actionIdx+3]))

	// Validate DNSSEC result
	switch result {
	case "secure", "insecure", "bogus", "indeterminate":
		p.store.SetDNSSEC(node, domain, result)
	default:
		if p.Debug {
			log.Printf("[DEBUG] Unknown DNSSEC result: %s for domain=%s", result, domain)
		}
	}
}

// parseDNSSECPipe handles pipe-delimited DNSSEC validation log lines.
// Format: "validation|domain|IN|secure"
func (p *Parser) parseDNSSECPipe(line []byte, node string) {
	// Find the validation| part
	idx := bytes.Index(line, []byte("validation|"))
	if idx == -1 {
		return
	}
	after := line[idx+len("validation|"):]
	pipeParts := bytes.Split(after, []byte("|"))
	if len(pipeParts) < 3 {
		return
	}
	domain := strings.ToLower(strings.TrimSuffix(string(pipeParts[0]), "."))
	result := strings.ToLower(string(pipeParts[2]))

	switch result {
	case "secure", "insecure", "bogus", "indeterminate":
		p.store.SetDNSSEC(node, domain, result)
	default:
		if p.Debug {
			log.Printf("[DEBUG] Unknown DNSSEC pipe result: %s for domain=%s", result, domain)
		}
	}
}

// parseResponseCode extracts DNS response codes from dnsmasq reply log lines.
// Common codes: NXDOMAIN, SERVFAIL, REFUSED, NOERROR, TIMEOUT
func parseResponseCode(actionIdx int, parts [][]byte) string {
	if actionIdx < 0 || len(parts) <= actionIdx+2 {
		return ""
	}
	payload := strings.ToLower(string(bytes.Join(parts[actionIdx+2:], []byte(" "))))
	switch {
	case strings.Contains(payload, "nxdomain"):
		return "NXDOMAIN"
	case strings.Contains(payload, "servfail"):
		return "SERVFAIL"
	case strings.Contains(payload, "refused"):
		return "REFUSED"
	case strings.Contains(payload, "timeout") || strings.Contains(payload, "timed out"):
		return "TIMEOUT"
	}

	// If it's a reply/cached/config action with no error, it's NOERROR
	if bytes.Equal(parts[actionIdx], []byte("reply")) ||
		bytes.Equal(parts[actionIdx], []byte("cached")) ||
		bytes.Equal(parts[actionIdx], []byte("config")) {
		return "NOERROR"
	}

	return ""
}

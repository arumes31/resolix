package parser

import (
	"bytes"
	"log"
	"strings"
	"time"

	"tailscale-dnsrewrite/webgui/internal/models"
	"tailscale-dnsrewrite/webgui/internal/storage"
)

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
			bytes.Equal(pt, []byte("cached")) {
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

	if bytes.HasPrefix(action, []byte("query[")) {
		if len(action) < 8 { // Must be at least query[A]
			return nil
		}
		qType := string(action[6 : len(action)-1])
		if len(parts) < actionIdx+4 || string(parts[actionIdx+2]) != "from" {
			return nil
		}
		domain := normalize(string(parts[actionIdx+1]))
		clientIP := string(parts[actionIdx+3])

		var parsedTime time.Time
		if actionIdx >= 3 {
			tsStr := string(bytes.Join(parts[:3], []byte(" ")))
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

			if ok {
				latency := float64(now.Sub(startTime).Microseconds()) / 1000.0
				if latency < 0 {
					latency = 0
				}
				return p.store.UpdateEvent(node, domain, latency, upstream)
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

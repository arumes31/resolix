package main

import (
	"fmt"
	"strings"
	"time"
)

type QueryEvent struct {
	Timestamp string  `json:"timestamp"`
	UnixTime  int64   `json:"unix_time"`
	Type      string  `json:"type"`
	Domain    string  `json:"domain"`
	ClientIP  string  `json:"client_ip"`
	Latency   float64 `json:"latency_ms,omitempty"`
	Upstream  string  `json:"upstream,omitempty"`
}

var (
	events    []QueryEvent
	maxEvents = 1000
	head      = 0
	count     = 0
)

func parseLogLine(line string) {
	now := time.Now()
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return
	}

	actionIdx := -1
	for i, p := range parts {
		if strings.HasPrefix(p, "query[") || p == "forwarded" || p == "reply" || p == "config" || p == "cached" {
			actionIdx = i
			break
		}
	}

	if actionIdx == -1 {
		return
	}

	action := parts[actionIdx]

	if strings.HasPrefix(action, "query[") {
		qType := action[6 : len(action)-1]
		if len(parts) < actionIdx+4 {
			return
		}
		domain := parts[actionIdx+1]
		clientIP := parts[actionIdx+3]

		tsStr := now.Format("Jan _2 15:04:05")
		if actionIdx >= 3 {
			tsStr = strings.Join(parts[:3], " ")
		}

		event := QueryEvent{
			Timestamp: tsStr,
			UnixTime:  now.Unix(),
			Type:      qType,
			Domain:    domain,
			ClientIP:  clientIP,
		}
		events = append(events, event)
		fmt.Printf("Added event: %+v\n", event)
	}
}

func main() {
	logs := []string{
		"dnsmasq[142]: cached discord.com is 162.159.138.232",
		"dnsmasq[142]: query[AAAA] sel-c11.vpn.wlvpn.com from 100.108.57.88",
		"dnsmasq[142]: query[A] sel-c11.vpn.wlvpn.com from 100.108.57.88",
		"dnsmasq[142]: query[AAAA] fortisafe-db from 100.77.35.105",
	}

	for _, log := range logs {
		fmt.Printf("Parsing: %s\n", log)
		parseLogLine(log)
	}
	fmt.Printf("Total events: %d\n", len(events))
}

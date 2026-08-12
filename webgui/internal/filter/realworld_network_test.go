//go:build integration

package filter

import (
	"context"
	"testing"
	"time"
)

func TestRecommendedRealWorldSubscriptions(t *testing.T) {
	t.Parallel()
	sources := []struct {
		name      string
		url       string
		allowOnly bool
	}{
		{name: "AdGuard DNS filter", url: "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt"},
		{name: "AdAway", url: "https://adguardteam.github.io/HostlistsRegistry/assets/filter_2.txt"},
		{name: "Windows Spy Blocker", url: "https://adguardteam.github.io/HostlistsRegistry/assets/filter_23.txt"},
		{name: "Phishing URL Blocklist", url: "https://adguardteam.github.io/HostlistsRegistry/assets/filter_30.txt"},
		{name: "1Hosts Lite", url: "https://adguardteam.github.io/HostlistsRegistry/assets/filter_24.txt"},
		{name: "Malicious URL Blocklist", url: "https://adguardteam.github.io/HostlistsRegistry/assets/filter_11.txt"},
		{name: "Scam Blocklist", url: "https://adguardteam.github.io/HostlistsRegistry/assets/filter_10.txt"},
		{name: "Someone Who Cares", url: "https://someonewhocares.org/hosts/hosts"},
		{name: "OISD Small", url: "https://small.oisd.nl/"},
		{name: "Firebog Suspicious", url: "https://raw.githubusercontent.com/KnightmareVIIVIIXC/AIO-Firebog-Blocklists/main/lists/firebogsus.txt"},
		{name: "Firebog Malicious", url: "https://raw.githubusercontent.com/KnightmareVIIVIIXC/AIO-Firebog-Blocklists/main/lists/firebogmal.txt"},
		{name: "Phishing Army", url: "https://adguardteam.github.io/HostlistsRegistry/assets/filter_18.txt"},
		{name: "EasyList", url: "https://v.firebog.net/hosts/Easylist.txt"},
		{
			name:      "Anudeep whitelist",
			url:       "https://raw.githubusercontent.com/anudeepND/whitelist/master/domains/whitelist.txt",
			allowOnly: true,
		},
	}
	engine := New()
	for index, source := range sources {
		engine.AddURLSourceWithOptions(Subscription{
			ID:             source.name,
			Name:           source.name,
			URL:            source.url,
			AllowOnly:      source.allowOnly,
			Enabled:        true,
			TimeoutSeconds: 120,
			RedirectLimit:  10,
		})
		if !engine.Sources()[index].validURL {
			t.Fatalf("source %q was rejected during URL validation", source.name)
		}
	}

	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	start := time.Now()
	engine.UpdateAll(ctx)
	totalRules := 0
	truncated := 0
	for _, source := range engine.Sources() {
		if source.LastError != "" {
			t.Errorf("%s: %s", source.Title, source.LastError)
		}
		totalRules += source.RuleCount + source.AllowRuleCount
		if source.Truncated {
			truncated++
		}
	}
	if t.Failed() {
		return
	}
	if totalRules < 2_000_000 {
		t.Fatalf("active rules = %d, want at least 2,000,000", totalRules)
	}
	if truncated != 0 {
		t.Fatalf("truncated sources = %d, want 0", truncated)
	}
	if result := engine.Match("github.com"); !result.Allowed {
		t.Fatalf("allowlist did not allow github.com: %+v", result)
	}
	if result := engine.Match("doubleclick.net"); !result.Blocked {
		t.Fatalf("blocklists did not block doubleclick.net: %+v", result)
	}
	t.Logf("loaded %d active rules from %d live sources in %s", totalRules, len(sources), time.Since(start))
}

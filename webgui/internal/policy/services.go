package policy

import (
	"sort"
	"strings"
)

// serviceCatalog maps well-known blocked-service IDs to their domains
// (apex + all subdomains match). Keep entries to the canonical domains of
// each service.
var serviceCatalog = map[string][]string{
	"facebook":  {"facebook.com", "fb.com", "fbcdn.net", "messenger.com"},
	"instagram": {"instagram.com", "cdninstagram.com"},
	"tiktok":    {"tiktok.com", "tiktokcdn.com", "tiktokv.com", "musical.ly", "byteoversea.com", "tiktokd.org"},
	"youtube":   {"youtube.com", "youtube-nocookie.com", "youtubei.googleapis.com", "youtube.googleapis.com", "ytimg.com", "ggpht.com"},
	"twitter":   {"twitter.com", "x.com", "t.co", "twimg.com"},
	"netflix":   {"netflix.com", "nflxvideo.net", "nflximg.net", "nflxext.com", "nflxso.net"},
	"twitch":    {"twitch.tv", "ttvnw.net", "jtvnw.net"},
	"discord":   {"discord.com", "discord.gg", "discordapp.com", "discordapp.net", "discord.media"},
	"reddit":    {"reddit.com", "redd.it", "redditmedia.com", "redditstatic.com"},
	"snapchat":  {"snapchat.com", "snap.com", "sc-cdn.net"},
	"whatsapp":  {"whatsapp.com", "whatsapp.net", "wa.me"},
	"telegram":  {"telegram.org", "t.me", "telegram.me", "telegram.dog"},
	"steam":     {"steampowered.com", "steamcontent.com", "steamcommunity.com", "steamstatic.com"},
	"roblox":    {"roblox.com", "rbxcdn.com", "robloxqq.com"},
}

// ServiceIDs returns all known blocked-service IDs.
func ServiceIDs() []string {
	ids := make([]string, 0, len(serviceCatalog))
	for id := range serviceCatalog {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// MatchService reports whether the (normalized) domain belongs to any of the
// given enabled services. It returns the matching service ID. Matching is
// apex + subdomains, label-boundary safe.
func MatchService(domain string, services []string) (string, bool) {
	for _, id := range services {
		domains, ok := serviceCatalog[strings.ToLower(strings.TrimSpace(id))]
		if !ok {
			continue
		}
		for _, d := range domains {
			if domain == d || strings.HasSuffix(domain, "."+d) {
				return strings.ToLower(strings.TrimSpace(id)), true
			}
		}
	}
	return "", false
}

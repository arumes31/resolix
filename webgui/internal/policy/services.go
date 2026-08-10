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

var domainToService = func() map[string]string {
	index := make(map[string]string)
	for service, domains := range serviceCatalog {
		for _, domain := range domains {
			index[domain] = service
		}
	}
	return index
}()

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
	enabled := make(map[string]bool, len(services))
	for _, id := range services {
		normalized := strings.ToLower(strings.TrimSpace(id))
		if _, ok := serviceCatalog[normalized]; ok {
			enabled[normalized] = true
		}
	}
	for candidate := domain; candidate != ""; {
		if service, ok := domainToService[candidate]; ok && enabled[service] {
			return service, true
		}
		dot := strings.IndexByte(candidate, '.')
		if dot < 0 {
			break
		}
		candidate = candidate[dot+1:]
	}
	return "", false
}

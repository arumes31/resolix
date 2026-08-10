package policy

import "testing"

func TestMatchService(t *testing.T) {
	tests := []struct {
		domain   string
		services []string
		wantID   string
		wantHit  bool
	}{
		{"facebook.com", []string{"facebook"}, "facebook", true},
		{"www.facebook.com", []string{"facebook"}, "facebook", true},
		{"deep.sub.tiktok.com", []string{"tiktok"}, "tiktok", true},
		{"deep.sub.tiktok.com", []string{"  TiKToK  "}, "tiktok", true},
		{"facebook.com", []string{"FACEBOOK"}, "facebook", true},
		{"x.com", []string{"twitter"}, "twitter", true},
		{"cdn.discordapp.com", []string{"discord"}, "discord", true},
		{"steampowered.com", []string{"steam"}, "steam", true},
		{"facebook.com", []string{"tiktok"}, "", false},        // service not enabled
		{"facebook.com", []string{"nosuchservice"}, "", false}, // unknown ID ignored
		{"notfacebook.com", []string{"facebook"}, "", false},   // label boundary
		{"facebook.com.evil.net", []string{"facebook"}, "", false},
		{"reddit.com", nil, "", false},
	}
	for _, tt := range tests {
		id, ok := MatchService(tt.domain, tt.services)
		if ok != tt.wantHit || id != tt.wantID {
			t.Errorf("MatchService(%q, %v) = (%q, %v), want (%q, %v)",
				tt.domain, tt.services, id, ok, tt.wantID, tt.wantHit)
		}
	}
}

func TestServiceCatalogCoversRequiredIDs(t *testing.T) {
	required := []string{
		"facebook", "instagram", "tiktok", "youtube", "twitter", "netflix",
		"twitch", "discord", "reddit", "snapchat", "whatsapp", "telegram",
		"steam", "roblox",
	}
	ids := make(map[string]bool)
	for _, id := range ServiceIDs() {
		ids[id] = true
	}
	for _, want := range required {
		if !ids[want] {
			t.Errorf("catalog missing service %q", want)
		}
	}
}

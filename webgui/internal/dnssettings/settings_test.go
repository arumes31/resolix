package dnssettings

import (
	"path/filepath"
	"reflect"
	"testing"
)

func testSettings() Settings {
	return Settings{
		UpstreamMode:          "load_balance",
		BlockingMode:          "nxdomain",
		BlockCustomIPv4:       "0.0.0.0",
		BlockCustomIPv6:       "::",
		BlockedResponseTTL:    60,
		RefuseANY:             true,
		PrivatePTR:            true,
		CacheSize:             25000,
		CacheMinTTL:           60,
		CacheMaxTTL:           600,
		CachePrefetchWindowMS: 30000,
		CachePrefetchHits:     3,
	}
}

func TestSettingsValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Settings)
		wantErr bool
	}{
		{name: "valid", mutate: func(*Settings) {}},
		{name: "invalid mode", mutate: func(s *Settings) { s.UpstreamMode = "fastest" }, wantErr: true},
		{name: "invalid fallback", mutate: func(s *Settings) { s.FallbackDNS = []string{"ftp://dns.test"} }, wantErr: true},
		{name: "invalid access CIDR", mutate: func(s *Settings) { s.AllowedClients = []string{"not-an-ip"} }, wantErr: true},
		{name: "invalid cache bounds", mutate: func(s *Settings) { s.CacheMinTTL, s.CacheMaxTTL = 600, 60 }, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			settings := testSettings()
			test.mutate(&settings)
			if err := settings.Validate(); (err != nil) != test.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
}

func TestStoreReplacePersistsAndDefensivelyCopies(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "dns-settings.json")
	store, err := Load(path, testSettings())
	if err != nil {
		t.Fatal(err)
	}
	settings := testSettings()
	settings.FallbackDNS = []string{"1.1.1.1"}
	settings.AllowedClients = []string{"100.64.0.0/10"}
	if err := store.Replace(settings); err != nil {
		t.Fatal(err)
	}
	settings.FallbackDNS[0] = "9.9.9.9"

	reloaded, err := Load(path, testSettings())
	if err != nil {
		t.Fatal(err)
	}
	want := testSettings().Normalize()
	want.FallbackDNS = []string{"1.1.1.1"}
	want.AllowedClients = []string{"100.64.0.0/10"}
	if got := reloaded.Get(); !reflect.DeepEqual(got, want) {
		t.Fatalf("Get() = %+v, want %+v", got, want)
	}
}

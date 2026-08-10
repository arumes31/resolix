package upstream

import "testing"

func FuzzParse(f *testing.F) {
	for _, seed := range []string{"1.1.1.1", "tcp://1.1.1.1:53", "tls://dns.example:853", "https://dns.example/dns-query"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		spec, err := Parse(raw)
		if err == nil && spec.Host == "" {
			t.Fatal("successful parse returned empty host")
		}
	})
}

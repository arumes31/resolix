package filter

import "testing"

func FuzzParseLine(f *testing.F) {
	for _, seed := range []string{"||example.com^", "@@||allowed.test^", "/tracker[0-9]+/", "0.0.0.0 ads.test"} {
		f.Add(seed)
	}
	f.Fuzz(func(_ *testing.T, line string) {
		_, _, _ = parseLine(line)
	})
}

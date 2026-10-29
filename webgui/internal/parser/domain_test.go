package parser

import (
	"strings"
	"testing"
)

func TestValidDomain(t *testing.T) {
	for _, test := range []struct {
		domain string
		want   bool
	}{
		{"", true},
		{"example.com", true},
		{"example.com.", true},
		{strings.Repeat("a", 63) + ".test", true},
		{strings.Repeat("a", 64) + ".test", false},
		{"a..test", false},
		{strings.Repeat("a.", 127) + "test", false},
		{strings.Repeat("abcd.", 51) + "test", false},
	} {
		if got := ValidDomain(test.domain); got != test.want {
			t.Errorf("ValidDomain(len %d) = %t, want %t", len(test.domain), got, test.want)
		}
	}
}

package api

import (
	"encoding/base64"
	"testing"

	"github.com/miekg/dns"
)

func FuzzDoHGETPayload(f *testing.F) {
	query := new(dns.Msg)
	query.SetQuestion("example.test.", dns.TypeAAAA)
	wire, _ := query.Pack()
	f.Add(base64.RawURLEncoding.EncodeToString(wire))
	f.Fuzz(func(_ *testing.T, encoded string) {
		data, err := base64.RawURLEncoding.DecodeString(encoded)
		if err != nil {
			return
		}
		message := new(dns.Msg)
		_ = message.Unpack(data)
	})
}

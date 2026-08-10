package dnsserver

import (
	"testing"

	"github.com/miekg/dns"
)

func FuzzDNSWireUnpack(f *testing.F) {
	seed := new(dns.Msg)
	seed.SetQuestion("example.test.", dns.TypeA)
	wire, _ := seed.Pack()
	f.Add(wire)
	f.Fuzz(func(_ *testing.T, data []byte) {
		message := new(dns.Msg)
		if err := message.Unpack(data); err == nil {
			_, _ = message.Pack()
		}
	})
}

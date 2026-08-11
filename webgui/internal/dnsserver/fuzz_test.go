package dnsserver

import (
	"testing"

	"github.com/miekg/dns"
)

func FuzzDNSWireUnpack(f *testing.F) {
	seed := new(dns.Msg)
	seed.SetQuestion("example.test.", dns.TypeA)
	seed.Compress = true
	wire, _ := seed.Pack()
	f.Add(wire)

	edns := new(dns.Msg)
	edns.SetQuestion("edns.example.test.", dns.TypeAAAA)
	edns.SetEdns0(4096, true)
	edns.IsEdns0().Option = append(edns.IsEdns0().Option, &dns.EDNS0_SUBNET{
		Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: 24,
		Address: []byte{192, 0, 2, 99},
	}, &dns.EDNS0_EDE{InfoCode: dns.ExtendedErrorCodeNetworkError, ExtraText: "seed"})
	ednsWire, _ := edns.Pack()
	f.Add(ednsWire)
	if len(ednsWire) > 0 {
		// Truncated EDNS option/RR data exercises malformed rdlength handling.
		f.Add(ednsWire[:len(ednsWire)-1])
	}

	// A question name whose compression pointer references itself. Unpack must
	// reject the loop without recursing indefinitely or panicking.
	f.Add([]byte{
		0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0xc0, 0x0c, 0x00, 0x01,
		0x00, 0x01,
	})
	// Out-of-range pointer and an overlong label are separate parser paths.
	f.Add([]byte{0, 2, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 0xff, 0, 1, 0, 1})
	f.Add(append([]byte{0, 3, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 64}, make([]byte, 64)...))
	// The answer advertises four A bytes but supplies only two.
	f.Add([]byte{
		0, 4, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0,
		1, 'a', 0, 0, 1, 0, 1,
		0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0,
	})

	multipleQuestions := seed.Copy()
	multipleQuestions.Question = append(multipleQuestions.Question, dns.Question{
		Name: "second.test.", Qtype: dns.TypeAAAA, Qclass: dns.ClassINET,
	})
	multipleWire, _ := multipleQuestions.Pack()
	f.Add(multipleWire)

	server := New(Config{}, nil)
	f.Fuzz(func(_ *testing.T, data []byte) {
		message := new(dns.Msg)
		if err := message.Unpack(data); err == nil {
			response, dropped := server.Resolve(message, "192.0.2.1")
			if !dropped && response != nil {
				_, _ = response.Pack()
			}
		}
	})
}

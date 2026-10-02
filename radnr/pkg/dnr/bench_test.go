//nolint:misspell // ADN: RFC 9463 Authentication Domain Name, not a typo for AND
package dnr

import (
	"net/netip"
	"testing"

	"github.com/puredevotion/coredns-plugins/radnr/pkg/svcparams"
)

// alpnDoT is the RFC 7858 ALPN, repeated across the test fixtures.
const alpnDoT = "dot"

// benchOption is a representative production option: an ADN, two resolver
// addresses and the alpn/port/dohpath SvcParams a DoT+DoH+DoQ resolver
// advertises.
func benchOption(b *testing.B) EncryptedDNS {
	b.Helper()
	sp, err := svcparams.Encode(svcparams.Params{ALPN: []string{alpnDoT, "doq", "h2", "h3"}, Port: 853, DohPath: "/dns-query{?dns}"})
	if err != nil {
		b.Fatal(err)
	}
	return EncryptedDNS{
		ServicePriority: 1,
		Lifetime:        3600,
		ADN:             testADN,
		Addrs:           []netip.Addr{netip.MustParseAddr("2001:db8::53"), netip.MustParseAddr("2001:db8::1:53")},
		SvcParams:       sp,
	}
}

// BenchmarkMarshal is a cold path in production (one RA every few minutes),
// benchmarked so a regression in the codec is visible rather than because
// the nanoseconds matter.
func BenchmarkMarshal(b *testing.B) {
	opt := benchOption(b)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := opt.Marshal(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkUnmarshal(b *testing.B) {
	wire, err := benchOption(b).Marshal()
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Unmarshal(wire); err != nil {
			b.Fatal(err)
		}
	}
}

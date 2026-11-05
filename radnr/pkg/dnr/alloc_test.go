//go:build !race

//nolint:misspell // ADN: RFC 9463 Authentication Domain Name, not AND
package dnr

import (
	"net/netip"
	"testing"
)

// Unmarshal allocates the ADN string, the address slice and the SvcParams copy
// and nothing else. The race detector adds allocations, hence the build tag.
func TestUnmarshalAllocs(t *testing.T) {
	o := EncryptedDNS{
		ADN:             MustParseDomainName(testADN),
		Addrs:           []netip.Addr{netip.MustParseAddr("2001:db8::1")},
		SvcParams:       []byte{0, 1, 0, 3, 2, 'h', '2'},
		ServicePriority: 1,
		Lifetime:        300,
	}
	b, err := o.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	const budget = 3
	if got := testing.AllocsPerRun(100, func() {
		if _, err := Unmarshal(b); err != nil {
			t.Fatal(err)
		}
	}); got > budget {
		t.Errorf("Unmarshal = %v allocs, budget %d", got, budget)
	}
}

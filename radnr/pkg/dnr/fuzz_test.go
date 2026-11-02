//nolint:misspell // ADN/adn throughout this file: RFC 9463 Authentication Domain Name, not a typo for AND
package dnr

import (
	"bytes"
	"net/netip"
	"slices"
	"testing"
)

// FuzzUnmarshal feeds arbitrary bytes, as an RA option would arrive off the
// link, to Unmarshal. No panic; whatever decodes and can be re-encoded must
// decode again to the same option (Marshal/Unmarshal consistency); and
// Marshal output is always a whole number of 8-octet units with the right
// header.
func FuzzUnmarshal(f *testing.F) {
	seed := EncryptedDNS{
		ADN:             testADN,
		Addrs:           []netip.Addr{netip.MustParseAddr("2001:db8::1")},
		SvcParams:       []byte{0, 1, 0, 3, 2, 'h', '2'},
		ServicePriority: 1,
		Lifetime:        300,
	}
	good, err := seed.Marshal()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(good)
	f.Add(good[:len(good)-1])
	f.Add([]byte{})
	f.Add([]byte{OptionType, 1, 0, 0, 0, 0, 0, 0})

	f.Fuzz(func(t *testing.T, b []byte) {
		o, err := Unmarshal(b)
		if err != nil {
			return
		}
		// Unmarshal only accepts what Marshal can express, so a decoded
		// option must always re-encode.
		enc, err := o.Marshal()
		if err != nil {
			t.Fatalf("Unmarshal accepted an option Marshal rejects: %v\n%+v", err, o)
		}
		if enc[0] != OptionType || len(enc)%octetUnit != 0 || int(enc[1])*octetUnit != len(enc) {
			t.Fatalf("Marshal produced a malformed header/length: % x", enc)
		}
		o2, err := Unmarshal(enc)
		if err != nil {
			t.Fatalf("Marshal output does not decode: %v\n% x", err, enc)
		}
		if o2.ADN != o.ADN || o2.ServicePriority != o.ServicePriority || o2.Lifetime != o.Lifetime ||
			!bytes.Equal(o2.SvcParams, o.SvcParams) || !slices.Equal(o2.Addrs, o.Addrs) {
			t.Fatalf("round trip mismatch:\n%+v\n%+v", o, o2)
		}
	})
}

// FuzzMarshalUnmarshal builds an option from arbitrary fields. Marshal either
// refuses or produces bytes Unmarshal turns back into the same option.
func FuzzMarshalUnmarshal(f *testing.F) {
	f.Add(testADN, []byte("\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"), []byte{0, 1, 0, 3, 2, 'h', '2'}, uint16(1), uint32(300))
	f.Add("", []byte{}, []byte{}, uint16(0), uint32(0))
	f.Add("a..b", []byte{1}, []byte(nil), uint16(65535), uint32(1<<32-1))
	for _, s := range stringSeeds(f) {
		f.Add(s, []byte(nil), []byte(nil), uint16(1), uint32(300))
	}
	f.Fuzz(func(t *testing.T, adn string, addrBytes, svc []byte, prio uint16, life uint32) {
		o := EncryptedDNS{ADN: adn, SvcParams: svc, ServicePriority: prio, Lifetime: life}
		for ; len(addrBytes) >= ipv6Size; addrBytes = addrBytes[ipv6Size:] {
			o.Addrs = append(o.Addrs, netip.AddrFrom16([ipv6Size]byte(addrBytes[:ipv6Size])))
		}
		enc, err := o.Marshal()
		if err != nil {
			return
		}
		got, err := Unmarshal(enc)
		if err != nil {
			t.Fatalf("Marshal output does not decode: %v\n% x", err, enc)
		}
		wantADN := o.ADN
		if n := len(wantADN); n > 0 && wantADN[n-1] == '.' {
			wantADN = wantADN[:n-1]
		}
		if got.ADN != wantADN || got.ServicePriority != prio || got.Lifetime != life ||
			!bytes.Equal(got.SvcParams, svc) || !slices.Equal(got.Addrs, o.Addrs) {
			t.Fatalf("round trip mismatch:\n%+v\n%+v", o, got)
		}
	})
}

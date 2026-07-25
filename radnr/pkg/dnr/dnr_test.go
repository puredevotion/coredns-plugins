package dnr

import (
	"bytes"
	"net/netip"
	"testing"

	"github.com/puredevotion/coredns-plugins/radnr/pkg/svcparams"
)

// RFC 9463 §6.1 — RA Encrypted DNS Option (type 144) wire layout:
//   Type(1)=144 | Length(1, units of 8) | ServicePriority(2) | Lifetime(4) |
//   ADNLength(2) | ADN(DNS wire labels) | AddrLength(2, mult of 16) |
//   IPv6 addrs(16 each) | SvcParamsLength(2) | SvcParams | zero-pad to mult of 8

func TestMarshal_GoldenBytes_ADNOnly(t *testing.T) {
	// Scenario: minimal valid option — priority + lifetime + ADN, no addrs, no svcparams.
	opt := EncryptedDNS{
		ServicePriority: 1,
		Lifetime:        3600,
		ADN:             "dns.example.com",
	}
	got, err := opt.Marshal()
	if err != nil {
		t.Fatalf("Marshal: unexpected error: %v", err)
	}
	// ADN wire: \x03dns\x07example\x03com\x00 = 17 octets
	adn := []byte{3, 'd', 'n', 's', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}
	// header: type,len, prio(2), lifetime(4), adnlen(2) = 10 octets
	// body so far: 10 + 17 = 27; + addrlen(2) + svcparamslen(2) = 31; pad to 32 (len=4)
	var want bytes.Buffer
	want.WriteByte(144)                        // Type
	want.WriteByte(4)                          // Length in units of 8 (32 octets)
	want.Write([]byte{0x00, 0x01})             // ServicePriority = 1
	want.Write([]byte{0x00, 0x00, 0x0e, 0x10}) // Lifetime = 3600
	want.Write([]byte{0x00, 0x11})             // ADNLength = 17
	want.Write(adn)
	want.Write([]byte{0x00, 0x00}) // AddrLength = 0
	want.Write([]byte{0x00, 0x00}) // SvcParamsLength = 0
	want.Write([]byte{0x00})       // pad 1 to reach 32
	if !bytes.Equal(got, want.Bytes()) {
		t.Fatalf("golden mismatch:\n got=%x\nwant=%x", got, want.Bytes())
	}
	if len(got)%8 != 0 {
		t.Fatalf("option length %d not a multiple of 8", len(got))
	}
}

func TestMarshal_WithAddrsAndSvcParams(t *testing.T) {
	sp, err := svcparams.Encode(svcparams.Params{ALPN: []string{"dot", "doq"}, Port: 853})
	if err != nil {
		t.Fatalf("svcparams.Encode: %v", err)
	}
	opt := EncryptedDNS{
		ServicePriority: 1,
		Lifetime:        3600,
		ADN:             "dns.example.com",
		Addrs:           []netip.Addr{netip.MustParseAddr("fde3:6ad1:6501::240")},
		SvcParams:       sp,
	}
	got, err := opt.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if got[0] != 144 {
		t.Fatalf("Type = %d, want 144", got[0])
	}
	if len(got)%8 != 0 {
		t.Fatalf("length %d not multiple of 8", len(got))
	}
	if int(got[1])*8 != len(got) {
		t.Fatalf("Length field %d*8 != actual %d", got[1], len(got))
	}
	// AddrLength must be 16 (one address)
	// locate: 2(hdr)+2(prio)+4(life)+2(adnlen)+17(adn) = 27 -> AddrLength at [27:29]
	if al := int(got[27])<<8 | int(got[28]); al != 16 {
		t.Fatalf("AddrLength = %d, want 16", al)
	}
}

func TestMarshalUnmarshal_RoundTrip(t *testing.T) {
	sp, _ := svcparams.Encode(svcparams.Params{ALPN: []string{"dot"}, Port: 853})
	in := EncryptedDNS{
		ServicePriority: 2,
		Lifetime:        7200,
		ADN:             "dns.example.com",
		Addrs:           []netip.Addr{netip.MustParseAddr("fde3:6ad1:6501::240")},
		SvcParams:       sp,
	}
	b, err := in.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	out, err := Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if out.ServicePriority != in.ServicePriority || out.Lifetime != in.Lifetime || out.ADN != in.ADN {
		t.Fatalf("round-trip scalar mismatch: %+v vs %+v", out, in)
	}
	if len(out.Addrs) != 1 || out.Addrs[0] != in.Addrs[0] {
		t.Fatalf("round-trip addr mismatch: %v", out.Addrs)
	}
	if !bytes.Equal(out.SvcParams, in.SvcParams) {
		t.Fatalf("round-trip svcparams mismatch")
	}
}

func TestMarshal_MultipleAddrs(t *testing.T) {
	opt := EncryptedDNS{
		ServicePriority: 1, Lifetime: 60, ADN: "a.b",
		Addrs: []netip.Addr{
			netip.MustParseAddr("fde3:6ad1:6501::240"),
			netip.MustParseAddr("fde3:6ad1:6501::241"),
		},
	}
	got, err := opt.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	// adn "a.b" wire = \x01a\x01b\x00 = 5 octets; AddrLength at 2+2+4+2+5 = 15
	if al := int(got[15])<<8 | int(got[16]); al != 32 {
		t.Fatalf("AddrLength = %d, want 32 (2 addrs)", al)
	}
}

func TestMarshal_Errors(t *testing.T) {
	cases := []struct {
		name string
		opt  EncryptedDNS
	}{
		{"empty ADN", EncryptedDNS{ServicePriority: 1, Lifetime: 1, ADN: ""}},
		{"label too long", EncryptedDNS{ADN: string(make([]byte, 64)) + ".com", Lifetime: 1}},
		{"ipv4 addr rejected", EncryptedDNS{ADN: "a.b", Lifetime: 1, Addrs: []netip.Addr{netip.MustParseAddr("192.0.2.1")}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := c.opt.Marshal(); err == nil {
				t.Fatalf("expected error for %s, got nil", c.name)
			}
		})
	}
}

func TestUnmarshal_Errors(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
	}{
		{"empty", []byte{}},
		{"wrong type", []byte{99, 1, 0, 0, 0, 0, 0, 0}},
		{"truncated header", []byte{144, 4, 0}},
		{"length field lies", []byte{144, 9, 0, 0, 0, 0, 0, 0}}, // says 72 octets, only 8 present
		{"addrlen not mult of 16", func() []byte {
			b := []byte{144, 4, 0, 1, 0, 0, 0, 1, 0, 3, 1, 'a', 1, 'b', 0, 0, 0, 15, 0, 0, 0, 0, 0, 0}
			return b
		}()},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := Unmarshal(c.in); err == nil {
				t.Fatalf("expected error for %s, got nil", c.name)
			}
		})
	}
}

func TestEncodeADN_MoreErrors(t *testing.T) {
	cases := []struct{ name, adn string }{
		{"empty label (double dot)", "a..b"},
		{"name too long", longName()},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o := EncryptedDNS{ServicePriority: 1, Lifetime: 1, ADN: c.adn}
			if _, err := o.Marshal(); err == nil {
				t.Fatalf("expected error for %s", c.name)
			}
		})
	}
}

func longName() string {
	lab := ""
	for i := 0; i < 60; i++ {
		lab += "a"
	}
	return lab + "." + lab + "." + lab + "." + lab + "." + lab
}

func TestMarshal_TrailingDotADN(t *testing.T) {
	o := EncryptedDNS{ServicePriority: 1, Lifetime: 1, ADN: "dns.example.com."}
	if _, err := o.Marshal(); err != nil {
		t.Fatalf("trailing dot should be accepted: %v", err)
	}
}

func TestUnmarshal_MoreTruncations(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
	}{
		{"truncated lifetime", []byte{144, 1, 0, 1, 0, 0, 0, 0}},
		{"adn len exceeds", []byte{144, 2, 0, 1, 0, 0, 0, 1, 0, 99, 1, 'a', 0, 0, 0, 0}},
		{"adn not root-terminated", []byte{144, 3, 0, 1, 0, 0, 0, 1, 0, 2, 1, 'a', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
		{"svcparams len exceeds", func() []byte {
			b := []byte{144, 3, 0, 1, 0, 0, 0, 1, 0, 5, 1, 'a', 1, 'b', 0, 0, 0, 0, 99}
			for len(b) < 24 {
				b = append(b, 0)
			}
			return b
		}()},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := Unmarshal(c.in); err == nil {
				t.Fatalf("expected error for %s", c.name)
			}
		})
	}
}

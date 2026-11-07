package zoneversion

import (
	"bytes"
	"context"
	"testing"

	"github.com/miekg/dns"
)

// FuzzDecode: whatever the bytes, Decode either refuses them or returns a
// valid Version that encodes back to exactly those bytes (ZoneVersion.lean
// encode_decode), and the only six-octet SOA-SERIAL inputs refused are the
// ones with an impossible label count.
func FuzzDecode(f *testing.F) {
	for _, s := range []string{"", "\x02\x00\x78\x95\xa4\xe9", "\x00\x00\x00\x00\x00\x00", "\x7f\x00\xff\xff\xff\xff", "\x80\x00\x00\x00\x00\x01", "\x02\x01abcd", "\x02\x00abc"} {
		f.Add([]byte(s))
	}
	for _, s := range stringSeeds(f) {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		v, err := Decode(b)
		if err != nil {
			if len(b) == wireLen && b[1] == typeSOASerial && b[0] >= 1 && b[0] <= maxLabels {
				t.Fatalf("Decode(% x) refused a valid option: %v", b, err)
			}
			return
		}
		if v.Validate() != nil {
			t.Fatalf("Decode(% x) returned an invalid Version %+v", b, v)
		}
		if enc := v.Encode(); !bytes.Equal(enc[:], b) {
			t.Fatalf("Encode(Decode(% x)) = % x", b, enc)
		}
	})
}

// FuzzNewVersion: an accepted (zone, qname) pair gives a Version whose label
// count is the zone's and at most QNAME's (RFC 9660 §2.1), and which
// survives Encode then Decode unchanged (ZoneVersion.lean decode_encode).
func FuzzNewVersion(f *testing.F) {
	for _, s := range [][2]string{
		{testApex, wwwName},
		{".", "a."},
		{"Example.COM", "x.example.com"},
		{"a.b.", "b."},
		{"\\.", "x.\\."},
		{testApex, testApex},
	} {
		f.Add(s[0], s[1], uint32(1))
	}
	for _, s := range stringSeeds(f) {
		f.Add(s, "www."+s, uint32(2023073001))
	}
	f.Fuzz(func(t *testing.T, zone, qname string, serial uint32) {
		v, err := NewVersion(zone, qname, serial)
		if err != nil {
			return
		}
		if int(v.LabelCount()) != dns.CountLabel(dns.Fqdn(zone)) {
			t.Fatalf("NewVersion(%q, %q): %d labels, zone has %d", zone, qname, v.LabelCount(), dns.CountLabel(dns.Fqdn(zone)))
		}
		if int(v.LabelCount()) > dns.CountLabel(dns.Fqdn(qname)) {
			t.Fatalf("NewVersion(%q, %q): LABELCOUNT %d exceeds QNAME's", zone, qname, v.LabelCount())
		}
		enc := v.Encode()
		back, err := Decode(enc[:])
		if err != nil || back != v || back.Serial() != serial {
			t.Fatalf("round trip of %+v: %+v, %v", v, back, err)
		}
	})
}

// FuzzOptions returns the option shapes FuzzServeDNS puts on a query, picked by the low bits of mode.
func fuzzOptions(mode uint8) []dns.EDNS0 {
	switch mode % 5 {
	case 1:
		return []dns.EDNS0{emptyOption()}
	case 2:
		return []dns.EDNS0{&dns.EDNS0_ZONEVERSION{}}
	case 3:
		return []dns.EDNS0{emptyOption(), emptyOption()}
	case 4:
		return []dns.EDNS0{&dns.EDNS0_NSID{Code: dns.EDNS0NSID}, emptyOption()}
	default:
		return nil
	}
}

// FuzzServeDNS: a query for any name, with any option shape, through the
// plugin in front of the test zone, with the zone optionally reloading
// between the answer and the plugin's own SOA lookup. Invariants:
//
//   - at most one ZONEVERSION option, and none unless the query asked
//     correctly (§3.2, §3.2.2), or FORMERR if it asked wrongly (§3.2.1);
//   - an option decodes, its LABELCOUNT is at most QNAME's (§2.1);
//   - the advertised serial is the one the answer was built from, never
//     the serial the zone moved to afterwards (guarantee G2);
//   - a query that did not ask causes no SOA lookups.
func FuzzServeDNS(f *testing.F) {
	for _, s := range []string{wwwName, "nx.example.com.", "a.child.example.com.", cnameName, fwdName, "x.wild.example.com.", testApex, "www.example.net.", "WWW.EXAMPLE.COM."} {
		f.Add(s, dns.TypeA, uint8(1), false)
	}
	for _, s := range stringSeeds(f) {
		f.Add(s+".example.com", dns.TypeA, uint8(1), true)
	}
	f.Fuzz(func(t *testing.T, name string, qtype uint16, mode uint8, reload bool) {
		qname := dns.Fqdn(name)
		if _, ok := dns.IsDomainName(qname); !ok {
			return
		}
		zone := newFakeZone()
		if reload {
			zone.afterAnswer = func() { zone.setSerial(testSerial + 1) }
		}
		r := query(qname, qtype, fuzzOptions(mode)...)
		a := classify(r.IsEdns0())
		w := &recorder{}
		if _, err := newTestPlugin(zone).ServeDNS(context.Background(), w, r); err != nil {
			t.Fatalf("ServeDNS: %v", err)
		}
		checkFuzzResponse(t, w.msgs, a, qname)
		if _, soa := zone.counts(); a == askNone && soa != 0 {
			t.Fatalf("%d SOA lookups for a query that did not ask", soa)
		}
	})
}

func checkFuzzResponse(t *testing.T, msgs []*dns.Msg, a ask, qname string) {
	t.Helper()
	inZone := dns.IsSubDomain(testApex, qname)
	for _, m := range msgs {
		got := versionOf(m)
		if len(got) > 1 {
			t.Fatalf("%d ZONEVERSION options", len(got))
		}
		if a == askMalformed && inZone && m.Rcode != dns.RcodeFormatError {
			t.Fatalf("malformed request answered %s", dns.RcodeToString[m.Rcode])
		}
		if len(got) == 0 {
			continue
		}
		if a != askVersion || !inZone {
			t.Fatalf("option on a response to a query that did not ask (ask %d, in zone %v)", a, inZone)
		}
		v, err := Decode(optionData(got[0]))
		if err != nil {
			t.Fatalf("option does not decode: %v", err)
		}
		if int(v.LabelCount()) > dns.CountLabel(qname) {
			t.Fatalf("LABELCOUNT %d exceeds QNAME %q", v.LabelCount(), qname)
		}
		if v.Serial() != testSerial {
			t.Fatalf("advertised %d, but the answer came from %d", v.Serial(), testSerial)
		}
	}
}

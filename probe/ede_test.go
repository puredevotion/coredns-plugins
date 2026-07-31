package probe

import (
	"testing"

	"github.com/miekg/dns"
)

func responseEDE(m *dns.Msg) *dns.EDNS0_EDE {
	opt := m.IsEdns0()
	if opt == nil {
		return nil
	}
	for _, o := range opt.Option {
		if e, ok := o.(*dns.EDNS0_EDE); ok {
			return e
		}
	}
	return nil
}

// TestEDEForModifiers pins the mapping from deliberate failure to reported code.
// This is the ground truth the RFC 9567 receiver compares resolver diagnoses
// against, so a wrong code here does not merely mislabel a response — it corrupts
// the measurement in a way that looks like a resolver bug.
func TestEDEForModifiers(t *testing.T) {
	for _, tc := range []struct {
		name string
		mods Modifier
		want uint16 // 0xFFFF sentinel for "no EDE at all"
	}{
		{"expired", ModExpiredSig, dns.ExtendedErrorCodeSignatureExpired},
		{"future", ModFutureSig, dns.ExtendedErrorCodeSignatureNotYetValid},
		{"unsigned", ModUnsigned, dns.ExtendedErrorCodeRRSIGsMissing},
		{"badsig", ModBadSig, dns.ExtendedErrorCodeDNSBogus},
		// A synthetic SERVFAIL is not a validation failure. Labelling it with a
		// DNSSEC code would inject a false one into the resolver's telemetry.
		{"servfail", ModServfail, dns.ExtendedErrorCodeOther},

		// Nothing is wrong with these, so nothing is claimed.
		{"truncate", ModTruncate, 0xFFFF},
		{"big", ModBig, 0xFFFF},
		{"none", 0, 0xFFFF},
		// The unprovable-denial experiment: whether it is bogus is the RESOLVER's
		// judgement, and that judgement is the thing being measured. Pre-empting it
		// with our own code would contaminate the result.
		{"nxdomain", ModNXDOMAIN, 0xFFFF},
		{"nxname", ModNXNAME, 0xFFFF},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := edeFor(tc.mods)
			if tc.want == 0xFFFF {
				if got != nil {
					t.Errorf("edeFor = code %d, want no EDE", got.InfoCode)
				}
				return
			}
			if got == nil {
				t.Fatalf("edeFor = nil, want code %d", tc.want)
			}
			if got.InfoCode != tc.want {
				t.Errorf("InfoCode = %d, want %d", got.InfoCode, tc.want)
			}
			if got.ExtraText == "" {
				t.Error("ExtraText empty; a bare code does not say this was deliberate")
			}
		})
	}
}

// TestEDESpecificBeatsGeneral — modifiers can combine, and a resolver told
// "bogus" when we could have said "expired" learns strictly less.
func TestEDESpecificBeatsGeneral(t *testing.T) {
	for _, tc := range []struct {
		name string
		mods Modifier
		want uint16
	}{
		{"expired+badsig", ModExpiredSig | ModBadSig, dns.ExtendedErrorCodeSignatureExpired},
		{"future+badsig", ModFutureSig | ModBadSig, dns.ExtendedErrorCodeSignatureNotYetValid},
		{"unsigned+badsig", ModUnsigned | ModBadSig, dns.ExtendedErrorCodeRRSIGsMissing},
		{"badsig+big", ModBadSig | ModBig, dns.ExtendedErrorCodeDNSBogus},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := edeFor(tc.mods)
			if got == nil || got.InfoCode != tc.want {
				t.Errorf("edeFor(%s) = %v, want code %d", tc.name, got, tc.want)
			}
		})
	}
}

// TestEDEOnlyWithEDNS — RFC 8914 §3 permits EDE only in response to a query that
// itself carried an OPT. A querier with no EDNS has not opted in.
func TestEDEOnlyWithEDNS(t *testing.T) {
	p := newTestProbe(t, true)

	// do=false in this harness still sends no OPT at all.
	plain := query(t, p, "_badsig.deadbeef."+testZone, dns.TypeTXT, false)
	if e := responseEDE(plain); e != nil {
		t.Errorf("EDE sent to a querier with no OPT record: code %d", e.InfoCode)
	}

	withEdns := query(t, p, "_badsig.deadbeef."+testZone, dns.TypeTXT, true)
	if e := responseEDE(withEdns); e == nil {
		t.Error("no EDE for _badsig on an EDNS query")
	}
}

// TestEDEEndToEndPerModifier drives real queries through ServeDNS. The signature
// modifiers all land on the ordinary NOERROR answer path rather than in the
// modifier switch, which is exactly why this is checked end to end rather than on
// edeFor alone — an EDE computed correctly and attached at the wrong callsite is
// invisible to a unit test.
func TestEDEEndToEndPerModifier(t *testing.T) {
	p := newTestProbe(t, true)

	for _, tc := range []struct {
		mod  string
		want uint16
	}{
		{"_expiredsig", dns.ExtendedErrorCodeSignatureExpired},
		{"_futuresig", dns.ExtendedErrorCodeSignatureNotYetValid},
		{"_unsigned", dns.ExtendedErrorCodeRRSIGsMissing},
		{"_badsig", dns.ExtendedErrorCodeDNSBogus},
		{"_servfail", dns.ExtendedErrorCodeOther},
	} {
		t.Run(tc.mod, func(t *testing.T) {
			m := query(t, p, tc.mod+".deadbeef."+testZone, dns.TypeTXT, true)
			e := responseEDE(m)
			if e == nil {
				t.Fatalf("no EDE in the response for %s", tc.mod)
			}
			if e.InfoCode != tc.want {
				t.Errorf("InfoCode = %d, want %d", e.InfoCode, tc.want)
			}
		})
	}

	// And the well-formed cases carry none.
	for _, mod := range []string{"_truncate", "_big"} {
		t.Run(mod+" carries none", func(t *testing.T) {
			m := query(t, p, mod+".deadbeef."+testZone, dns.TypeTXT, true)
			if e := responseEDE(m); e != nil {
				t.Errorf("EDE code %d attached to a well-formed %s response", e.InfoCode, mod)
			}
		})
	}
}

// TestEDENotDuplicated — RFC 8914 §2 permits repeated options, but a duplicate
// says nothing extra and costs bytes on a response whose size this zone also
// measures.
func TestEDENotDuplicated(t *testing.T) {
	m := new(dns.Msg)
	m.SetQuestion("deadbeef."+testZone, dns.TypeTXT)
	m.SetEdns0(1232, false)

	attachEDE(m, ede(dns.ExtendedErrorCodeDNSBogus))
	attachEDE(m, ede(dns.ExtendedErrorCodeSignatureExpired))

	opt := m.IsEdns0()
	var count int
	for _, o := range opt.Option {
		if _, ok := o.(*dns.EDNS0_EDE); ok {
			count++
		}
	}
	if count != 1 {
		t.Errorf("%d EDE options attached, want 1", count)
	}
	if e := responseEDE(m); e.InfoCode != dns.ExtendedErrorCodeDNSBogus {
		t.Errorf("second attach overwrote the first: code %d", e.InfoCode)
	}
}

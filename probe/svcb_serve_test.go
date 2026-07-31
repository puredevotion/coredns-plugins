package probe

import (
	"bytes"
	"testing"

	"github.com/miekg/dns"
)

// probeWithECH builds a test probe with the ECH canary populated the way setup
// does, since newTestProbe predates it.
func probeWithECH(t *testing.T) *Probe {
	t.Helper()
	p := newTestProbe(t, true)
	list, err := BuildECHConfigList(echConfigID, testECHKey(), "check.example.com")
	if err != nil {
		t.Fatalf("BuildECHConfigList: %v", err)
	}
	p.ECHConfigList = list
	return p
}

func echFromRR(rr dns.RR) []byte {
	var params []dns.SVCBKeyValue
	switch v := rr.(type) {
	case *dns.HTTPS:
		params = v.Value
	case *dns.SVCB:
		params = v.Value
	default:
		return nil
	}
	for _, kv := range params {
		if e, ok := kv.(*dns.SVCBECHConfig); ok {
			return e.ECH
		}
	}
	return nil
}

// TestServesECHOverTheWire is the test that matters: RFC 9460 §7 requires SvcParams
// in strictly ascending key order on the wire, and miekg/dns enforces it at pack
// time. A record that looks right in Go and fails to pack would be answered as
// SERVFAIL in production while every unit test passed.
func TestServesECHOverTheWire(t *testing.T) {
	p := probeWithECH(t)

	for _, qtype := range []uint16{dns.TypeHTTPS, dns.TypeSVCB} {
		t.Run(dns.TypeToString[qtype], func(t *testing.T) {
			m := query(t, p, "deadbeef."+testZone, qtype, true)
			if m.Rcode != dns.RcodeSuccess {
				t.Fatalf("Rcode = %s", dns.RcodeToString[m.Rcode])
			}
			if len(m.Answer) == 0 {
				t.Fatal("no answer record")
			}

			// Round-trip through the wire, which is where param ordering is checked.
			wire, err := m.Pack()
			if err != nil {
				t.Fatalf("Pack: %v — SvcParams are probably out of ascending key order", err)
			}
			var got dns.Msg
			if err := got.Unpack(wire); err != nil {
				t.Fatalf("Unpack: %v", err)
			}
			if len(got.Answer) == 0 {
				t.Fatal("answer did not survive the round trip")
			}

			ech := echFromRR(got.Answer[0])
			if ech == nil {
				t.Fatal("no ech= parameter after the round trip")
			}
			if !bytes.Equal(ech, p.ECHConfigList) {
				t.Error("ech= bytes changed across the wire round trip")
			}
			// And it must still parse as a config list, not merely match.
			if _, _, _, err := ParseECHConfigList(ech); err != nil {
				t.Errorf("served ech= does not parse: %v", err)
			}
		})
	}
}

// TestNoECHRecordWithoutACanary — an HTTPS record with no ech= gives the
// measurement nothing to compare, so NODATA is the honest answer rather than a
// half-populated record.
func TestNoECHRecordWithoutACanary(t *testing.T) {
	p := newTestProbe(t, true) // ECHConfigList deliberately empty
	m := query(t, p, "deadbeef."+testZone, dns.TypeHTTPS, true)

	if m.Rcode != dns.RcodeSuccess {
		t.Errorf("Rcode = %s, want NOERROR/NODATA", dns.RcodeToString[m.Rcode])
	}
	if len(m.Answer) != 0 {
		t.Errorf("served %d HTTPS records with no ECH canary configured", len(m.Answer))
	}
}

// TestECHRecordIsObservable — the point of serving it is measuring who asks, and
// the query type is what records that.
func TestECHRecordIsObservable(t *testing.T) {
	p := probeWithECH(t)
	query(t, p, "deadbeef."+testZone, dns.TypeHTTPS, true)

	obs, err := p.Store.Lookup("deadbeef")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if len(obs) == 0 {
		t.Fatal("HTTPS query was not observed")
	}
	if obs[0].Qtype != "HTTPS" {
		t.Errorf("Qtype = %q, want HTTPS", obs[0].Qtype)
	}
}

package probe

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"
	"github.com/miekg/dns"
)

// test.ResponseWriter reports this as the source address, so it stands in for
// the resolver throughout: every A answer and every observation below should
// carry it, which is the point of the zone (the resolver's address, not the
// visitor's).
const testResolverIP = "10.240.0.1"

func newTestProbe(t *testing.T, signed bool) *Probe {
	t.Helper()
	p := &Probe{
		Zone:    testZone,
		TTL:     10,
		NSName:  "ns." + testZone,
		Mbox:    "hostmaster." + testZone,
		Store:   NewMemStore(time.Minute, 100, 8),
		BigSize: defaultBigSize,
	}
	if signed {
		p.Signer = newTestSigner(t, time.Hour)
	}
	return p
}

// query drives one request through ServeDNS and returns the written message.
func query(t *testing.T, p *Probe, qname string, qtype uint16, do bool) *dns.Msg {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(qname, qtype)
	if do {
		m.SetEdns0(1232, true)
	}
	rec := dnstest.NewRecorder(&test.ResponseWriter{})
	if _, err := p.ServeDNS(context.Background(), rec, m); err != nil {
		t.Fatalf("ServeDNS(%s %s): %v", qname, dns.TypeToString[qtype], err)
	}
	if rec.Msg == nil {
		t.Fatalf("ServeDNS(%s) wrote no message", qname)
	}
	return rec.Msg
}

func TestBaselineAReturnsResolverAddress(t *testing.T) {
	p := newTestProbe(t, false)
	m := query(t, p, "a1b2c3d4."+testZone, dns.TypeA, false)

	if m.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s, want NOERROR", dns.RcodeToString[m.Rcode])
	}
	if !m.Authoritative {
		t.Error("answer is not authoritative")
	}
	if len(m.Answer) != 1 {
		t.Fatalf("got %d answers, want 1: %v", len(m.Answer), m.Answer)
	}
	a, ok := m.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("answer is %T, want *dns.A", m.Answer[0])
	}
	if got := a.A.String(); got != testResolverIP {
		t.Errorf("A = %s, want the resolver's own address %s", got, testResolverIP)
	}
}

func TestTXTCarriesObservationInBand(t *testing.T) {
	p := newTestProbe(t, false)
	m := query(t, p, "a1b2c3d4."+testZone, dns.TypeTXT, true)

	if len(m.Answer) == 0 {
		t.Fatal("no TXT answer")
	}
	txt, ok := m.Answer[0].(*dns.TXT)
	if !ok {
		t.Fatalf("answer is %T, want *dns.TXT", m.Answer[0])
	}
	got := strings.Join(txt.Txt, "")

	// The in-band readout is the whole reason a bare `dig` is useful here, so
	// each field a page would show must actually be present.
	for _, want := range []string{
		"resolver=" + testResolverIP,
		"prefix=10.240.0.0/24", // /24 grouping, per response-rate-limiting convention
		"proto=udp",
		"edns=1",
		"do=1",
		"bufsize=1232",
		"seen=1",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("TXT payload missing %q; got %q", want, got)
		}
	}
}

func TestSignatureVariantsOverTheWire(t *testing.T) {
	tests := []struct {
		name      string
		qname     string
		wantRRSIG bool
		// verifies is whether the emitted RRSIG should verify against the key.
		verifies bool
		// currentlyValid is whether it should be inside its validity window.
		currentlyValid bool
	}{
		{
			name: "baseline is correctly signed", qname: "a1b2c3d4",
			wantRRSIG: true, verifies: true, currentlyValid: true,
		},
		{
			name: "unsigned omits the RRSIG", qname: "_unsigned.a1b2c3d4",
			wantRRSIG: false,
		},
		{
			name: "badsig is present but does not verify", qname: "_badsig.a1b2c3d4",
			wantRRSIG: true, verifies: false, currentlyValid: true,
		},
		{
			name: "expiredsig verifies but is out of window", qname: "_expiredsig.a1b2c3d4",
			wantRRSIG: true, verifies: true, currentlyValid: false,
		},
		{
			name: "futuresig verifies but is out of window", qname: "_futuresig.a1b2c3d4",
			wantRRSIG: true, verifies: true, currentlyValid: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := newTestProbe(t, true)
			m := query(t, p, tc.qname+"."+testZone, dns.TypeTXT, true)

			var sig *dns.RRSIG
			var covered []dns.RR
			for _, rr := range m.Answer {
				if s, ok := rr.(*dns.RRSIG); ok {
					sig = s
					continue
				}
				covered = append(covered, rr)
			}

			if !tc.wantRRSIG {
				if sig != nil {
					t.Fatalf("expected no RRSIG, got %v", sig)
				}
				if len(covered) == 0 {
					t.Error("unsigned variant should still return the record itself")
				}
				return
			}
			if sig == nil {
				t.Fatal("expected an RRSIG in the answer, got none")
			}

			err := sig.Verify(p.Signer.DNSKEY(), covered)
			if tc.verifies && err != nil {
				t.Errorf("signature should verify, got %v", err)
			}
			if !tc.verifies && err == nil {
				t.Error("signature should NOT verify, but it did")
			}
			if got := sig.ValidityPeriod(time.Now()); got != tc.currentlyValid {
				t.Errorf("ValidityPeriod = %v, want %v", got, tc.currentlyValid)
			}
		})
	}
}

func TestNoRRSIGWithoutDOBit(t *testing.T) {
	// A resolver that did not ask for DNSSEC must not be handed signatures: it
	// inflates the response for no reason, which on a public zone is free
	// amplification.
	p := newTestProbe(t, true)
	m := query(t, p, "a1b2c3d4."+testZone, dns.TypeTXT, false)
	for _, rr := range m.Answer {
		if _, ok := rr.(*dns.RRSIG); ok {
			t.Fatal("RRSIG returned to a client that did not set DO")
		}
	}
}

func TestRcodeAndTruncateVariants(t *testing.T) {
	tests := []struct {
		name        string
		qname       string
		wantRcode   int
		wantTC      bool
		wantNoAnswr bool
	}{
		{
			name: "malformed grammar is refused, not NXDOMAIN",
			// REFUSED distinguishes "this is not a valid probe request" from
			// "this name does not exist", which are different findings.
			qname: "notavalidtoken." + testZone, wantRcode: dns.RcodeRefused, wantNoAnswr: true,
		},
		{
			name:  "unknown modifier is refused",
			qname: "_bogusmod.a1b2c3d4." + testZone, wantRcode: dns.RcodeRefused, wantNoAnswr: true,
		},
		{
			name:  "conflicting modifiers are refused",
			qname: "_unsigned._badsig.a1b2c3d4." + testZone, wantRcode: dns.RcodeRefused, wantNoAnswr: true,
		},
		{
			name:  "nxdomain variant",
			qname: "_nxdomain.a1b2c3d4." + testZone, wantRcode: dns.RcodeNameError, wantNoAnswr: true,
		},
		{
			name:  "servfail variant",
			qname: "_servfail.a1b2c3d4." + testZone, wantRcode: dns.RcodeServerFailure, wantNoAnswr: true,
		},
		{
			name:  "truncate variant sets TC and drops the answer",
			qname: "_truncate.a1b2c3d4." + testZone,
			// TC=1 with an empty answer is exactly the shape rate limiting uses
			// when it slips a response.
			wantRcode: dns.RcodeSuccess, wantTC: true, wantNoAnswr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := newTestProbe(t, true)
			m := query(t, p, tc.qname, dns.TypeTXT, true)

			if m.Rcode != tc.wantRcode {
				t.Errorf("rcode = %s, want %s",
					dns.RcodeToString[m.Rcode], dns.RcodeToString[tc.wantRcode])
			}
			if m.Truncated != tc.wantTC {
				t.Errorf("TC = %v, want %v", m.Truncated, tc.wantTC)
			}
			if tc.wantNoAnswr && len(m.Answer) != 0 {
				t.Errorf("expected an empty answer section, got %v", m.Answer)
			}
		})
	}
}

func TestNodataReturnsSignedDenial(t *testing.T) {
	// The resolver reached us over IPv4, so AAAA is NODATA: NOERROR, no answer,
	// and a denial in the authority section that a validator can check.
	p := newTestProbe(t, true)
	m := query(t, p, "a1b2c3d4."+testZone, dns.TypeAAAA, true)

	if m.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s, want NOERROR for NODATA", dns.RcodeToString[m.Rcode])
	}
	if len(m.Answer) != 0 {
		t.Errorf("NODATA must have an empty answer section, got %v", m.Answer)
	}

	var haveSOA, haveNSEC, haveRRSIG bool
	for _, rr := range m.Ns {
		switch rr.(type) {
		case *dns.SOA:
			haveSOA = true
		case *dns.NSEC:
			haveNSEC = true
		case *dns.RRSIG:
			haveRRSIG = true
		}
	}
	if !haveSOA {
		t.Error("no SOA in the authority section")
	}
	if !haveNSEC {
		t.Error("no NSEC in the authority section, so the denial is unprovable")
	}
	if !haveRRSIG {
		t.Error("denial is unsigned")
	}
}

// queryBuf is like query but lets the test advertise a specific EDNS buffer,
// which for the oversized-answer variant is the whole point.
func queryBuf(t *testing.T, p *Probe, qname string, qtype uint16, bufsize uint16) *dns.Msg {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(qname, qtype)
	m.SetEdns0(bufsize, false)
	rec := dnstest.NewRecorder(&test.ResponseWriter{})
	if _, err := p.ServeDNS(context.Background(), rec, m); err != nil {
		t.Fatalf("ServeDNS(%s): %v", qname, err)
	}
	return rec.Msg
}

// TestBigVariantIsBoundedByClientBuffer is the amplification story in one test.
// The oversized answer is only delivered to a client that advertised room for
// it; a client with a small buffer gets TC=1 and has to come back over TCP,
// which is what keeps this modifier from being a free reflection amplifier.
func TestBigVariantIsBoundedByClientBuffer(t *testing.T) {
	p := newTestProbe(t, false)

	// Small buffer: the large answer must NOT be delivered over UDP.
	small := queryBuf(t, p, "_big.a1b2c3d5."+testZone, dns.TypeTXT, 512)
	if len(small.Answer) != 0 {
		t.Errorf("oversized answer was delivered to a 512-byte client: %d bytes",
			small.Len())
	}
	if !small.Truncated {
		t.Error("oversized answer to a small-buffer client should set TC=1")
	}

	// Large buffer: delivered intact.
	big := queryBuf(t, p, "_big.a1b2c3d6."+testZone, dns.TypeTXT, 4096)
	if len(big.Answer) == 0 {
		t.Fatal("big variant returned no answer to a 4096-byte client")
	}
	baseline := queryBuf(t, p, "a1b2c3d7."+testZone, dns.TypeTXT, 4096)
	bigTXT := big.Answer[0].(*dns.TXT)
	total := 0
	for _, s := range bigTXT.Txt {
		total += len(s)
		// TXT strings are length-prefixed with a single byte, so none may
		// exceed 255 or the message cannot be encoded at all.
		if len(s) > 255 {
			t.Errorf("TXT string of %d bytes exceeds the 255-byte limit", len(s))
		}
	}
	if total < p.BigSize {
		t.Errorf("big payload is %d bytes, want at least %d", total, p.BigSize)
	}
	if big.Len() <= baseline.Len() {
		t.Errorf("big response (%d bytes) is not larger than baseline (%d bytes)",
			big.Len(), baseline.Len())
	}
}

func TestApexRecords(t *testing.T) {
	p := newTestProbe(t, true)

	soa := query(t, p, testZone, dns.TypeSOA, false)
	if len(soa.Answer) != 1 {
		t.Fatalf("apex SOA: got %d answers, want 1", len(soa.Answer))
	}
	if _, ok := soa.Answer[0].(*dns.SOA); !ok {
		t.Errorf("apex SOA answer is %T", soa.Answer[0])
	}

	ns := query(t, p, testZone, dns.TypeNS, false)
	if len(ns.Answer) != 1 {
		t.Fatalf("apex NS: got %d answers, want 1", len(ns.Answer))
	}

	key := query(t, p, testZone, dns.TypeDNSKEY, true)
	var haveKey bool
	for _, rr := range key.Answer {
		if _, ok := rr.(*dns.DNSKEY); ok {
			haveKey = true
		}
	}
	if !haveKey {
		t.Error("apex DNSKEY query returned no DNSKEY")
	}
}

// TestApexSignaturesAreNeverSpoiled guards a deliberate design choice: if a
// modifier could break the apex SOA or DNSKEY, the whole zone would go bogus
// and every per-query variant beneath it would become unmeasurable.
func TestApexSignaturesAreNeverSpoiled(t *testing.T) {
	p := newTestProbe(t, true)
	m := query(t, p, testZone, dns.TypeSOA, true)

	var sig *dns.RRSIG
	var covered []dns.RR
	for _, rr := range m.Answer {
		if s, ok := rr.(*dns.RRSIG); ok {
			sig = s
			continue
		}
		covered = append(covered, rr)
	}
	if sig == nil {
		t.Fatal("apex SOA was not signed")
	}
	if err := sig.Verify(p.Signer.DNSKEY(), covered); err != nil {
		t.Errorf("apex signature must always verify, got %v", err)
	}
	if !sig.ValidityPeriod(time.Now()) {
		t.Error("apex signature must always be currently valid")
	}
}

func TestOutOfZoneFallsThrough(t *testing.T) {
	p := newTestProbe(t, false)
	var called bool
	p.Next = plugin.HandlerFunc(func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
		called = true
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeSuccess)
		return dns.RcodeSuccess, w.WriteMsg(m)
	})

	m := new(dns.Msg)
	m.SetQuestion("elsewhere.example.org.", dns.TypeA)
	rec := dnstest.NewRecorder(&test.ResponseWriter{})
	if _, err := p.ServeDNS(context.Background(), rec, m); err != nil {
		t.Fatalf("ServeDNS: %v", err)
	}
	if !called {
		t.Error("a name outside the zone was not passed to the next plugin")
	}
}

func TestObservationsAccumulatePerToken(t *testing.T) {
	p := newTestProbe(t, false)
	const token = "a1b2c3d4"

	// Different modifiers, same token: the whole point of the token is that a
	// page can correlate every query one visit provoked.
	query(t, p, token+"."+testZone, dns.TypeTXT, false)
	query(t, p, "_truncate."+token+"."+testZone, dns.TypeTXT, false)
	query(t, p, token+"."+testZone, dns.TypeA, true)

	obs, err := p.Store.Lookup(token)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if len(obs) != 3 {
		t.Fatalf("got %d observations, want 3", len(obs))
	}
	for i, o := range obs {
		if o.Seen != i+1 {
			t.Errorf("observation %d has Seen = %d, want %d", i, o.Seen, i+1)
		}
		if o.Token != token {
			t.Errorf("observation %d has token %q, want %q", i, o.Token, token)
		}
	}
	if obs[1].Mods != "truncate" {
		t.Errorf("second observation mods = %q, want \"truncate\"", obs[1].Mods)
	}
	// DO was only set on the third query.
	if obs[0].DO || !obs[2].DO {
		t.Errorf("DO bits = %v, %v, %v; want false, false, true", obs[0].DO, obs[1].DO, obs[2].DO)
	}
}

// TestCaseRandomizationIsObserved covers the one measurement that is impossible
// to make after normalisation: CoreDNS lowercases the name for matching, so the
// 0x20 signal only survives if the raw question is read.
func TestCaseRandomizationIsObserved(t *testing.T) {
	p := newTestProbe(t, false)
	query(t, p, "A1b2C3d4."+testZone, dns.TypeTXT, false)

	obs, err := p.Store.Lookup("a1b2c3d4")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if len(obs) != 1 {
		t.Fatalf("got %d observations, want 1", len(obs))
	}
	if !obs[0].CaseRandomized {
		t.Error("mixed-case query was not recorded as 0x20 randomized")
	}

	p2 := newTestProbe(t, false)
	query(t, p2, "a1b2c3d4."+testZone, dns.TypeTXT, false)
	obs2, _ := p2.Store.Lookup("a1b2c3d4")
	if obs2[0].CaseRandomized {
		t.Error("all-lowercase query was wrongly recorded as randomized")
	}
}

func TestUnsignedZoneStillAnswers(t *testing.T) {
	// Running without a key is a supported configuration (keys may not exist
	// yet); it must degrade to plain answers rather than failing.
	p := newTestProbe(t, false)
	m := query(t, p, "_unsigned.a1b2c3d4."+testZone, dns.TypeTXT, true)
	if m.Rcode != dns.RcodeSuccess {
		t.Errorf("rcode = %s, want NOERROR", dns.RcodeToString[m.Rcode])
	}
	if len(m.Answer) == 0 {
		t.Error("unsigned zone returned no answer")
	}
}

// nsecFrom pulls the NSEC out of an authority section, plus whatever RRSIG
// covers it, so the denial tests can assert on the proof rather than the rcode
// alone.
func nsecFrom(t *testing.T, m *dns.Msg) (*dns.NSEC, bool) {
	t.Helper()
	for _, rr := range m.Ns {
		if n, ok := rr.(*dns.NSEC); ok {
			return n, true
		}
	}
	return nil, false
}

func bitmapHas(n *dns.NSEC, t uint16) bool {
	for _, b := range n.TypeBitMap {
		if b == t {
			return true
		}
	}
	return false
}

// TestCompactDenialSetsNXNAME covers the RFC 9824 path. The NXNAME bit is the
// entire mechanism: it is what lets a resolver turn a provable NODATA into
// NXDOMAIN for its own client, which is the thing a synthesized zone cannot do
// with a traditional NSEC chain.
func TestCompactDenialSetsNXNAME(t *testing.T) {
	p := newTestProbe(t, true)
	m := query(t, p, "_nxname.a1b2c3d4."+testZone, dns.TypeTXT, true)

	// NOERROR, not NXDOMAIN — that is what makes it provable.
	if m.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s, want NOERROR for compact denial", dns.RcodeToString[m.Rcode])
	}
	if len(m.Answer) != 0 {
		t.Errorf("compact denial must have an empty answer section, got %v", m.Answer)
	}

	nsec, ok := nsecFrom(t, m)
	if !ok {
		t.Fatal("no NSEC in the authority section")
	}
	if !bitmapHas(nsec, dns.TypeNXNAME) {
		t.Errorf("NSEC bitmap lacks NXNAME: %v", nsec.TypeBitMap)
	}
	// RFC 9824 §3.1: only these three bits.
	for _, b := range nsec.TypeBitMap {
		switch b {
		case dns.TypeRRSIG, dns.TypeNSEC, dns.TypeNXNAME:
		default:
			t.Errorf("NSEC bitmap carries unexpected type %s", dns.TypeToString[b])
		}
	}
	// Black-lies next name: the immediate lexicographic successor of the qname.
	if want := "\\000._nxname.a1b2c3d4." + testZone; nsec.NextDomain != want {
		t.Errorf("NextDomain = %q, want %q", nsec.NextDomain, want)
	}

	var signed bool
	for _, rr := range m.Ns {
		if sig, isSig := rr.(*dns.RRSIG); isSig && sig.TypeCovered == dns.TypeNSEC {
			signed = true
			if err := sig.Verify(p.Signer.DNSKEY(), []dns.RR{nsec}); err != nil {
				t.Errorf("NSEC signature does not verify: %v", err)
			}
		}
	}
	if !signed {
		t.Error("the NSEC is unsigned, so the denial proves nothing")
	}
}

// TestNodataDenialOmitsNXNAME is the other half of the rule: NXNAME means "this
// name does not exist", so setting it for a name that DOES exist (and merely
// lacks the queried type) would be a lie a resolver could act on.
func TestNodataDenialOmitsNXNAME(t *testing.T) {
	p := newTestProbe(t, true)
	// The resolver reached us over IPv4, so AAAA is NODATA on an existing name.
	m := query(t, p, "a1b2c3d4."+testZone, dns.TypeAAAA, true)

	nsec, ok := nsecFrom(t, m)
	if !ok {
		t.Fatal("no NSEC in the authority section")
	}
	if bitmapHas(nsec, dns.TypeNXNAME) {
		t.Error("NODATA for an existing name must NOT set NXNAME")
	}
}

func TestLegacyNXDOMAINOmitsNXNAME(t *testing.T) {
	// _nxdomain is deliberately the legacy, unprovable shape. It must not
	// smuggle in the NXNAME signal, or the comparison between the two forms —
	// the reason both exist — would be meaningless.
	p := newTestProbe(t, true)
	m := query(t, p, "_nxdomain.a1b2c3d4."+testZone, dns.TypeTXT, true)

	if m.Rcode != dns.RcodeNameError {
		t.Fatalf("rcode = %s, want NXDOMAIN", dns.RcodeToString[m.Rcode])
	}
	if nsec, ok := nsecFrom(t, m); ok && bitmapHas(nsec, dns.TypeNXNAME) {
		t.Error("_nxdomain must not set NXNAME; that is what _nxname is for")
	}
}

// TestNXNAMEQueryIsFormErr covers RFC 9824's explicit requirement. NODATA would
// be wrong here: it would imply NXNAME is a real type this zone happens to have
// none of, when in fact it can never exist as a record at all.
func TestNXNAMEQueryIsFormErr(t *testing.T) {
	p := newTestProbe(t, true)
	for _, qname := range []string{
		"a1b2c3d4." + testZone,
		testZone,
		"_nxname.a1b2c3d4." + testZone,
	} {
		m := query(t, p, qname, dns.TypeNXNAME, true)
		if m.Rcode != dns.RcodeFormatError {
			t.Errorf("QTYPE=NXNAME for %s gave %s, want FORMERR",
				qname, dns.RcodeToString[m.Rcode])
		}
		if len(m.Answer) != 0 {
			t.Errorf("QTYPE=NXNAME for %s returned answers: %v", qname, m.Answer)
		}
	}
}

func TestNegativeModifiersConflict(t *testing.T) {
	// One rcode per answer, so any two of these together is a client error.
	for _, sub := range []string{
		"_nxdomain._nxname.a1b2c3d4",
		"_nxname._servfail.a1b2c3d4",
		"_nxdomain._servfail.a1b2c3d4",
	} {
		if _, ok := ParseQuery(sub); ok {
			t.Errorf("ParseQuery(%q) accepted conflicting negative modifiers", sub)
		}
	}
}

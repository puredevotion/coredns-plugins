package zoneversion

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/miekg/dns"
)

// Serve runs one query through a fresh plugin in front of zone.
func serve(t *testing.T, z *ZoneVersion, r *dns.Msg) *dns.Msg {
	t.Helper()
	w := &recorder{}
	rcode, err := z.ServeDNS(context.Background(), w, r)
	if err != nil {
		t.Fatalf("ServeDNS: %v", err)
	}
	if len(w.msgs) != 1 {
		if !plugin.ClientWrite(rcode) && len(w.msgs) == 0 {
			m := new(dns.Msg)
			m.SetRcode(r, rcode)
			return m // What the server would write.
		}
		t.Fatalf("%d messages written", len(w.msgs))
	}
	return w.msgs[0]
}

// WantVersion asserts exactly one ZONEVERSION option, for example.com (two
// labels) at serial.
func wantVersion(t *testing.T, m *dns.Msg, serial uint32) {
	t.Helper()
	got := versionOf(m)
	if len(got) != 1 {
		t.Fatalf("%d ZONEVERSION options, want 1:\n%v", len(got), m)
	}
	v, err := Decode(optionData(got[0]))
	if err != nil {
		t.Fatalf("option does not decode: %v", err)
	}
	if v.LabelCount() != 2 || v.Serial() != serial {
		t.Fatalf("version %d/%d, want 2/%d", v.LabelCount(), v.Serial(), serial)
	}
}

func wantNoVersion(t *testing.T, m *dns.Msg) {
	t.Helper()
	if got := versionOf(m); len(got) != 0 {
		t.Fatalf("%d ZONEVERSION options, want none:\n%v", len(got), m)
	}
}

// The response cases RFC 9660 §3.2 lists, and the ones it leaves to the
// server, each through the plugin.
func TestResponseCases(t *testing.T) {
	for _, tc := range []struct {
		name    string
		qname   string
		rcode   int
		qtype   uint16
		version bool
	}{
		{"positive answer", wwwName, dns.RcodeSuccess, dns.TypeA, true},
		{"NODATA", wwwName, dns.RcodeSuccess, dns.TypeTXT, true},
		{"NXDOMAIN", "nx.example.com.", dns.RcodeNameError, dns.TypeA, true},
		{"apex SOA", testApex, dns.RcodeSuccess, dns.TypeSOA, true},
		{"wildcard", "x.y.wild.example.com.", dns.RcodeSuccess, dns.TypeA, true},
		{"downward referral", "a.child.example.com.", dns.RcodeSuccess, dns.TypeA, true},
		{"referral at the cut", "child.example.com.", dns.RcodeSuccess, dns.TypeA, true},
		{"CNAME into another zone", cnameName, dns.RcodeNameError, dns.TypeA, true},
		{"not authoritative", fwdName, dns.RcodeSuccess, dns.TypeA, false},
		{"SERVFAIL", "fail.example.com.", dns.RcodeServerFailure, dns.TypeA, false},
		{"REFUSED", "refused.example.com.", dns.RcodeRefused, dns.TypeA, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			zone := newFakeZone()
			got := serve(t, newTestPlugin(zone), query(tc.qname, tc.qtype, emptyOption()))
			if got.Rcode != tc.rcode {
				t.Fatalf("rcode %s, want %s", dns.RcodeToString[got.Rcode], dns.RcodeToString[tc.rcode])
			}
			if tc.version {
				wantVersion(t, got, testSerial)
			} else {
				wantNoVersion(t, got)
			}
		})
	}
}

// §3.2.2: no request, no option, and the response is the zone's own.
func TestNoRequestNoOption(t *testing.T) {
	zone := newFakeZone()
	zone.echo = true // Even a stray one from elsewhere is not this plugin's to add.
	for _, r := range []*dns.Msg{query(wwwName, dns.TypeA), func() *dns.Msg {
		m := new(dns.Msg)
		m.SetQuestion(wwwName, dns.TypeA) // No EDNS at all.
		return m
	}()} {
		got := serve(t, newTestPlugin(zone), r)
		if r.IsEdns0() == nil && got.IsEdns0() != nil {
			t.Fatal("OPT added to a response to a query without EDNS")
		}
	}
	if _, soa := zone.counts(); soa != 0 {
		t.Fatalf("%d SOA lookups for queries that did not ask", soa)
	}
}

// §3.2.1: a non-empty option, or two, is FORMERR, and the zone never sees it.
func TestFormErr(t *testing.T) {
	for name, opts := range map[string][]dns.EDNS0{
		"two octets (miekg's empty struct)": {&dns.EDNS0_ZONEVERSION{}},
		"a full response option":            {&dns.EDNS0_ZONEVERSION{LabelCount: 2, Version: strayVersion}},
		"non-empty local form":              {&dns.EDNS0_LOCAL{Code: dns.EDNS0ZONEVERSION, Data: []byte{0}}},
		"two empty options":                 {emptyOption(), emptyOption()},
	} {
		t.Run(name, func(t *testing.T) {
			zone := newFakeZone()
			got := serve(t, newTestPlugin(zone), query(wwwName, dns.TypeA, opts...))
			if got.Rcode != dns.RcodeFormatError {
				t.Fatalf("rcode %s, want FORMERR", dns.RcodeToString[got.Rcode])
			}
			if got.IsEdns0() == nil {
				t.Fatal("FORMERR to an EDNS query without OPT")
			}
			wantNoVersion(t, got)
			if q, _ := zone.counts(); q != 0 {
				t.Fatalf("zone saw %d queries", q)
			}
		})
	}
}

// Outside the configured zones the plugin is not there: no FORMERR, no option.
func TestOtherZonesUntouched(t *testing.T) {
	zone := newFakeZone()
	z := newTestPlugin(zone)
	got := serve(t, z, query("www.example.net.", dns.TypeA, &dns.EDNS0_ZONEVERSION{}))
	if got.Rcode == dns.RcodeFormatError {
		t.Fatal("FORMERR for a zone this plugin does not serve")
	}
	got = serve(t, z, query("www.example.net.", dns.TypeA, emptyOption()))
	wantNoVersion(t, got)
}

// The race the bracket exists for: the zone reloads after the answer is built
// and before the plugin's own SOA lookup. Advertising the new serial would
// attribute the old answer to the new zone; the option is withheld.
func TestSerialChangesAfterAnswer(t *testing.T) {
	zone := newFakeZone()
	zone.afterAnswer = func() { zone.setSerial(testSerial + 1) }
	z := newTestPlugin(zone)
	got := serve(t, z, query(wwwName, dns.TypeA, emptyOption()))
	wantNoVersion(t, got)
	if len(got.Answer) != 1 {
		t.Fatal("the answer itself must still be served")
	}

	// The next query brackets against the new serial and gets it.
	zone.afterAnswer = nil
	wantVersion(t, serve(t, z, query(wwwName, dns.TypeA, emptyOption())), testSerial+1)
}

// A negative answer carries its own SOA, from the same snapshot as the
// answer: no bracket needed, and a reload right after it does not matter.
func TestNegativeAnswerUsesItsOwnSOA(t *testing.T) {
	zone := newFakeZone()
	zone.afterAnswer = func() { zone.setSerial(testSerial + 1) }
	wantVersion(t, serve(t, newTestPlugin(zone), query("nx.example.com.", dns.TypeA, emptyOption())), testSerial)
}

// The cache stands in for the "before" lookup: the second query costs one SOA
// lookup, not two.
func TestCacheSavesALookup(t *testing.T) {
	zone := newFakeZone()
	z := newTestPlugin(zone)
	r := func() *dns.Msg { return query(wwwName, dns.TypeA, emptyOption()) }
	wantVersion(t, serve(t, z, r()), testSerial)
	if _, soa := zone.counts(); soa != 2 {
		t.Fatalf("first query: %d SOA lookups, want 2 (before and after)", soa)
	}
	wantVersion(t, serve(t, z, r()), testSerial)
	if _, soa := zone.counts(); soa != 3 {
		t.Fatalf("second query: %d SOA lookups in all, want 3", soa)
	}
	// Past maxEntryAge the cache is not used.
	z.now = func() time.Time { return testEpoch.Add(maxEntryAge + time.Second) }
	wantVersion(t, serve(t, z, r()), testSerial)
	if _, soa := zone.counts(); soa != 5 {
		t.Fatalf("after expiry: %d SOA lookups in all, want 5", soa)
	}
}

// A rollback: the cache keeps the higher serial until it goes stale, and the
// option is withheld meanwhile rather than bracketed against a value the
// zone left.
func TestRollback(t *testing.T) {
	zone := newFakeZone()
	z := newTestPlugin(zone)
	r := func() *dns.Msg { return query(wwwName, dns.TypeA, emptyOption()) }
	wantVersion(t, serve(t, z, r()), testSerial)
	zone.setSerial(testSerial - 10)
	wantNoVersion(t, serve(t, z, r()))
	z.now = func() time.Time { return testEpoch.Add(maxEntryAge + time.Second) }
	wantVersion(t, serve(t, z, r()), testSerial-10)
}

// The SOA lookup must come back authoritative with an SOA at the apex.
func TestLookupFailure(t *testing.T) {
	zone := newFakeZone()
	zone.noSOA = true
	wantNoVersion(t, serve(t, newTestPlugin(zone), query(wwwName, dns.TypeA, emptyOption())))
}

// A stray ZONEVERSION from another plugin is replaced, never duplicated
// (§3.2: at most one per TYPE and LABELCOUNT), and removed when withheld.
func TestStrayOptionReplaced(t *testing.T) {
	zone := newFakeZone()
	zone.echo = true
	wantVersion(t, serve(t, newTestPlugin(zone), query(wwwName, dns.TypeA, emptyOption())), testSerial)
	wantNoVersion(t, serve(t, newTestPlugin(zone), query(fwdName, dns.TypeA, emptyOption())))
}

// SizeAndDo reuses the request's OPT in the response; attaching the version
// must not write it into the request.
func TestRequestNotModified(t *testing.T) {
	zone := newFakeZone()
	r := query(wwwName, dns.TypeA, emptyOption())
	got := serve(t, newTestPlugin(zone), r)
	wantVersion(t, got, testSerial)
	if ro := r.IsEdns0(); ro != nil && len(ro.Option) > 1 {
		t.Fatalf("request OPT now has %d options", len(ro.Option))
	}
	for _, o := range r.IsEdns0().Option {
		if _, ok := o.(*dns.EDNS0_ZONEVERSION); ok {
			t.Fatal("the response's option was written into the request")
		}
	}
}

// LABELCOUNT is the deepest configured zone's, and never more than QNAME's.
func TestLongestZoneWins(t *testing.T) {
	zone := newFakeZone()
	z := newZoneVersion([]string{"com.", testApex})
	z.Next = zone
	z.now = func() time.Time { return testEpoch }
	wantVersion(t, serve(t, z, query(wwwName, dns.TypeA, emptyOption())), testSerial)
}

// Zone transfers and non-QUERY opcodes pass through untouched.
func TestPassThrough(t *testing.T) {
	zone := newFakeZone()
	z := newTestPlugin(zone)
	axfr := query(testApex, dns.TypeAXFR, emptyOption())
	wantNoVersion(t, serve(t, z, axfr))
	notify := query(testApex, dns.TypeSOA, emptyOption())
	notify.Opcode = dns.OpcodeNotify
	wantNoVersion(t, serve(t, z, notify))
}

// Writes through Write([]byte) are kept in order and versioned like any other.
func TestRawWrite(t *testing.T) {
	zone := newFakeZone()
	z := newTestPlugin(&rawWriter{zone})
	wantVersion(t, serve(t, z, query(wwwName, dns.TypeA, emptyOption())), testSerial)

	cw := &captureWriter{}
	if _, err := cw.Write([]byte{1, 2, 3}); err == nil {
		t.Fatal("garbage bytes captured")
	}
}

// RawWriter answers through Write([]byte).
type rawWriter struct{ next *fakeZone }

func (*rawWriter) Name() string { return "raw" }

func (h *rawWriter) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	rec := &recorder{}
	rcode, err := h.next.ServeDNS(ctx, rec, r)
	if err != nil || len(rec.msgs) != 1 {
		return rcode, err
	}
	b, err := rec.msgs[0].Pack()
	if err != nil {
		return dns.RcodeServerFailure, fmt.Errorf("raw: %w", err)
	}
	if _, err := w.Write(b); err != nil {
		return dns.RcodeServerFailure, fmt.Errorf("raw: %w", err)
	}
	return rcode, nil
}

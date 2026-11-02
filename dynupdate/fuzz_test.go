package dynupdate

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

const wwwName = "www.example.org."

// parseSeedZone parses seedZone once; fuzz iterations deep-copy the result so
// each one starts from an identical, unshared zone.
func parseSeedZone(tb testing.TB) []dns.RR {
	tb.Helper()
	rrs := make([]dns.RR, 0, 16)
	zp := dns.NewZoneParser(strings.NewReader(seedZone), testZone, "seed")
	for r, ok := zp.Next(); ok; r, ok = zp.Next() {
		rrs = append(rrs, r)
	}
	if err := zp.Err(); err != nil {
		tb.Fatalf("parse seed zone: %v", err)
	}
	return rrs
}

// freshPlugin builds a new DynUpdate over a private copy of the seed zone, so
// no state leaks from one fuzz iteration to the next.
func freshPlugin(tb testing.TB, seed []dns.RR, mutable map[uint16]bool) *DynUpdate {
	tb.Helper()
	rrs := make([]dns.RR, len(seed))
	for i, r := range seed {
		rrs[i] = dns.Copy(r)
	}
	d := &DynUpdate{Zone: testZone, rrs: rrs, mutable: mutable}
	if err := d.swap(rrs); err != nil {
		tb.Fatalf("swap: %v", err)
	}
	return d
}

func snapshot(rrs []dns.RR) []string {
	out := make([]string, len(rrs))
	for i, r := range rrs {
		out[i] = r.String()
	}
	return out
}

// FuzzServeUpdate feeds arbitrary wire-format messages to the UPDATE path
// (RFC 2136) of a fresh plugin per input. The message is whatever a peer can
// put on the wire; only messages miekg/dns can unpack reach the plugin.
//
// Invariants, whatever the input:
//   - no panic, and exactly one response is written;
//   - any rcode other than NOERROR leaves the zone untouched (RFC 2136
//     §3.4.2.1, atomicity);
//   - an update the tsig layer did not verify never changes the zone;
//   - the zone stays well-formed: every record in zone, one apex SOA, an
//     apex NS, no CNAME beside other data, no duplicate record, and an SOA
//     serial that never moves backwards;
//   - the served view agrees with the record slice on the apex SOA serial;
//   - under a type allowlist, a successful update touches only allowed types.
//
//nolint:gocognit // A fuzz target is a flat list of invariants; splitting it only hides them.
func FuzzServeUpdate(f *testing.F) {
	seed := parseSeedZone(f)
	addSeeds(f)

	f.Fuzz(func(t *testing.T, wire []byte, tsigOK, restrict bool) {
		msg := new(dns.Msg)
		if err := msg.Unpack(wire); err != nil {
			return
		}
		// Route into the UPDATE machinery; the opcode check itself is a
		// one-line dispatch and not worth the mutator's time to hit.
		msg.Opcode = dns.OpcodeUpdate

		var mutable map[uint16]bool
		if restrict {
			mutable = map[uint16]bool{dns.TypeTXT: true}
		}
		d := freshPlugin(t, seed, mutable)
		before := snapshot(d.rrs)
		beforeSOA := *soaOf(d.rrs)

		w := &testWriter{tsigOK: tsigOK}
		if _, err := d.ServeDNS(context.Background(), w, msg); err != nil {
			t.Fatalf("ServeDNS: %v", err)
		}
		if w.msg == nil {
			t.Fatal("no response written")
		}
		rcode := w.msg.Rcode
		after := snapshot(d.rrs)

		if rcode != dns.RcodeSuccess && !slices.Equal(before, after) {
			t.Fatalf("rcode %s but the zone changed:\nbefore %v\nafter  %v", dns.RcodeToString[rcode], before, after)
		}
		if !tsigOK && rcode == dns.RcodeSuccess {
			t.Fatal("unverified UPDATE answered NOERROR")
		}
		if !tsigOK && !slices.Equal(before, after) {
			t.Fatal("unverified UPDATE changed the zone")
		}

		checkZoneInvariants(t, d)

		soa := soaOf(d.rrs)
		if soa.Serial != beforeSOA.Serial && !serialGreater(soa.Serial, beforeSOA.Serial) {
			t.Fatalf("SOA serial went backwards: %d -> %d", beforeSOA.Serial, soa.Serial)
		}
		checkViewSerial(t, d, soa.Serial)

		if restrict && rcode == dns.RcodeSuccess {
			// Everything other than the SOA (whose serial is bumped
			// automatically) must differ only in allowed types.
			if diff := nonTXTChanges(before, d.rrs); len(diff) > 0 {
				t.Fatalf("allowlist {TXT} but a non-TXT record changed: %v", diff)
			}
		}
	})
}

// nonTXTChanges returns the records of a type other than TXT or SOA that appear in
// exactly one of before and now (rendered with TTL).
func nonTXTChanges(before []string, now []dns.RR) []string {
	have := map[string]int{}
	for _, s := range before {
		have[s]++
	}
	var diff []string
	for _, r := range now {
		if t := r.Header().Rrtype; t == dns.TypeTXT || t == dns.TypeSOA {
			continue
		}
		s := r.String()
		if have[s] == 0 {
			diff = append(diff, "added "+s)
			continue
		}
		have[s]--
	}
	for _, s := range before {
		if strings.Contains(s, "\tSOA\t") || strings.Contains(s, "\tTXT\t") {
			continue
		}
		if have[s] > 0 {
			diff = append(diff, "removed "+s)
			have[s]--
		}
	}
	return diff
}

//nolint:gocognit // A fuzz target is a flat list of invariants; splitting it only hides them.
func checkZoneInvariants(t *testing.T, d *DynUpdate) {
	t.Helper()
	var soas, apexNS int
	seen := map[string]bool{}
	types := map[string]map[uint16]bool{}
	for _, r := range d.rrs {
		h := r.Header()
		if !d.inZone(h.Name) {
			t.Fatalf("record outside the zone: %s", r)
		}
		name := strings.ToLower(dns.CanonicalName(h.Name))
		if h.Rrtype == dns.TypeSOA {
			soas++
			if name != d.Zone {
				t.Fatalf("SOA not at the apex: %s", r)
			}
		}
		if h.Rrtype == dns.TypeNS && name == d.Zone {
			apexNS++
		}
		k := name + "|" + rdataKey(r)
		if seen[k] {
			t.Fatalf("duplicate record: %s", r)
		}
		seen[k] = true
		if types[name] == nil {
			types[name] = map[uint16]bool{}
		}
		types[name][h.Rrtype] = true
	}
	if soas != 1 {
		t.Fatalf("%d SOA records, want exactly 1", soas)
	}
	if apexNS == 0 {
		t.Fatal("apex NS RRset is gone")
	}
	for name, ts := range types {
		if ts[dns.TypeCNAME] && len(ts) > 1 {
			t.Fatalf("CNAME coexists with other data at %s: %v", name, ts)
		}
	}
}

// checkViewSerial asserts the served zone and the source-of-truth slice agree.
func checkViewSerial(t *testing.T, d *DynUpdate, want uint32) {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(testZone, dns.TypeSOA)
	w := &testWriter{}
	if _, err := d.ServeDNS(context.Background(), w, m); err != nil {
		t.Fatalf("ServeDNS(SOA query): %v", err)
	}
	if w.msg == nil || len(w.msg.Answer) != 1 {
		t.Fatalf("SOA query answered %v", w.msg)
	}
	got, ok := w.msg.Answer[0].(*dns.SOA)
	if !ok || got.Serial != want {
		t.Fatalf("served SOA %v, record slice serial %d", w.msg.Answer[0], want)
	}
}

// addSeeds registers well-formed UPDATE messages covering add, delete (all
// three forms), SOA replacement, CNAME conflicts and every prerequisite form,
// signed and unsigned, with and without a type allowlist.
func addSeeds(f *testing.F) {
	f.Helper()
	pack := func(m *dns.Msg) []byte {
		b, err := m.Pack()
		if err != nil {
			f.Fatalf("pack seed: %v", err)
		}
		return b
	}
	mk := func(s string) dns.RR {
		r, err := dns.NewRR(s)
		if err != nil {
			f.Fatalf("NewRR(%q): %v", s, err)
		}
		return r
	}
	withClass := func(r dns.RR, class uint16) dns.RR {
		r.Header().Class = class
		return r
	}

	// Add TXT, add + delete, delete-RRset, delete-all-at-name, SOA bump,
	// CNAME conflicts, prerequisites of every form.
	f.Add(pack(newUpdate(nil, []dns.RR{mk(`_acme-challenge.example.org. 60 IN TXT "tok"`)})), true, false)
	f.Add(pack(newUpdate(nil, []dns.RR{mk(`_acme-challenge.example.org. 60 IN TXT "tok"`)})), false, false)
	f.Add(pack(newUpdate(nil, []dns.RR{mk(`_acme-challenge.example.org. 60 IN TXT "tok"`)})), true, true)
	f.Add(pack(newUpdate(nil, []dns.RR{withClass(mk(`www.example.org. 0 IN A 192.0.2.10`), dns.ClassNONE)})), true, false)
	f.Add(pack(newUpdate(nil, []dns.RR{withClass(mk(`www.example.org. 0 IN A 192.0.2.10`), dns.ClassANY)})), true, false)
	f.Add(pack(newUpdate(nil, []dns.RR{&dns.ANY{Hdr: dns.RR_Header{Name: wwwName, Rrtype: dns.TypeANY, Class: dns.ClassANY}}})), true, false)
	f.Add(pack(newUpdate(nil, []dns.RR{mk(`example.org. 300 IN SOA ns.example.org. admin.example.org. 101 3600 900 86400 300`)})), true, false)
	f.Add(pack(newUpdate(nil, []dns.RR{mk(`www.example.org. 300 IN CNAME ns.example.org.`)})), true, false)
	f.Add(pack(newUpdate(nil, []dns.RR{mk(`alias.example.org. 300 IN A 192.0.2.7`)})), true, false)
	f.Add(pack(newUpdate(nil, []dns.RR{mk(`alias.example.org. 300 IN CNAME ns2.example.org.`)})), true, false)
	f.Add(pack(newUpdate(
		[]dns.RR{
			&dns.ANY{Hdr: dns.RR_Header{Name: wwwName, Rrtype: dns.TypeA, Class: dns.ClassANY}},
			&dns.ANY{Hdr: dns.RR_Header{Name: "nope.example.org.", Rrtype: dns.TypeANY, Class: dns.ClassNONE}},
			mk(`ns.example.org. 0 IN A 192.0.2.1`),
		},
		[]dns.RR{mk(`new.example.org. 60 IN A 192.0.2.50`)})), true, false)
	f.Add(pack(newUpdate(nil, []dns.RR{mk(`other.example.com. 60 IN A 192.0.2.50`)})), true, false)
	f.Add([]byte{}, true, false)
}

package dynupdate

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/miekg/dns"
)

const seedZone = `$ORIGIN example.org.
$TTL 300
@   SOA ns.example.org. admin.example.org. 100 3600 900 86400 300
@   NS  ns.example.org.
@   NS  ns2.example.org.
ns  A   192.0.2.1
ns2 A   192.0.2.2
www A   192.0.2.10
alias CNAME www.example.org.
`

// testWriter records the response and reports a TSIG status the test chooses.
// The real chain has the tsig plugin in front doing verification; this stands
// in for it so the update path can be exercised without key management.
type testWriter struct {
	dns.ResponseWriter
	msg    *dns.Msg
	tsigOK bool
}

func (w *testWriter) WriteMsg(m *dns.Msg) error { w.msg = m; return nil }
func (w *testWriter) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("192.0.2.99"), Port: 5353}
}

func (w *testWriter) TsigStatus() error {
	if w.tsigOK {
		return nil
	}
	return dns.ErrSig
}

func newTestPlugin(t *testing.T, mutable map[uint16]bool) *DynUpdate {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, "db.example.org")
	if err := os.WriteFile(path, []byte(seedZone), 0o600); err != nil {
		t.Fatal(err)
	}

	rrs, err := readZone(path, "example.org.")
	if err != nil {
		t.Fatalf("readZone: %v", err)
	}

	d := &DynUpdate{Zone: "example.org.", rrs: rrs, mutable: mutable}
	if err := d.swap(rrs); err != nil {
		t.Fatalf("swap: %v", err)
	}
	return d
}

// newUpdate builds a signed UPDATE. The TSIG RR only has to be present — the
// plugin asks the writer whether verification succeeded, it does not verify.
func newUpdate(prereqs, updates []dns.RR) *dns.Msg {
	m := new(dns.Msg)
	m.SetUpdate("example.org.")
	m.Answer = prereqs
	m.Ns = updates
	m.SetTsig("key.example.org.", dns.HmacSHA256, 300, 0)
	return m
}

// send runs one UPDATE and returns the rcode the plugin replied with. Records
// are re-packed and re-parsed first: Header().Rdlength is set by the wire
// decoder, and several RFC 2136 rules turn on it, so tests that hand the
// plugin hand-built structs would exercise a message no client can send.
func send(t *testing.T, d *DynUpdate, m *dns.Msg) int {
	t.Helper()

	wire, err := m.Pack()
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	got := new(dns.Msg)
	if err := got.Unpack(wire); err != nil {
		t.Fatalf("unpack: %v", err)
	}

	w := &testWriter{tsigOK: true}
	if _, err := d.ServeDNS(context.Background(), w, got); err != nil {
		t.Fatalf("ServeDNS: %v", err)
	}
	if w.msg == nil {
		t.Fatal("no response written")
	}
	if w.msg.Opcode != dns.OpcodeUpdate {
		t.Errorf("response opcode = %s, want UPDATE", dns.OpcodeToString[w.msg.Opcode])
	}
	return w.msg.Rcode
}

func rr(t *testing.T, s string) dns.RR {
	t.Helper()
	r, err := dns.NewRR(s)
	if err != nil {
		t.Fatalf("NewRR(%q): %v", s, err)
	}
	return r
}

// query runs a normal lookup through the plugin, which is how a test checks
// that an update is actually visible to resolvers rather than merely present
// in the record slice.
func query(t *testing.T, d *DynUpdate, name string, qtype uint16) *dns.Msg {
	t.Helper()

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	w := &testWriter{}
	if _, err := d.ServeDNS(context.Background(), w, m); err != nil {
		t.Fatalf("ServeDNS(query): %v", err)
	}
	if w.msg == nil {
		t.Fatal("no response written for query")
	}
	return w.msg
}

func serialOf(t *testing.T, d *DynUpdate) uint32 {
	t.Helper()
	soa := soaOf(d.rrs)
	if soa == nil {
		t.Fatal("zone lost its SOA")
	}
	return soa.Serial
}

func TestUnsignedUpdateIsRefused(t *testing.T) {
	d := newTestPlugin(t, nil)

	m := new(dns.Msg)
	m.SetUpdate("example.org.")
	m.Ns = []dns.RR{rr(t, "new.example.org. 300 IN A 192.0.2.50")}

	w := &testWriter{tsigOK: true} // writer would verify, but there is no TSIG
	if _, err := d.ServeDNS(context.Background(), w, m); err != nil {
		t.Fatal(err)
	}
	if w.msg.Rcode != dns.RcodeRefused {
		t.Errorf("rcode = %s, want REFUSED", dns.RcodeToString[w.msg.Rcode])
	}
	if d.nameInUse("new.example.org.") {
		t.Error("an unsigned update was applied")
	}
}

func TestFailedTsigIsRefused(t *testing.T) {
	d := newTestPlugin(t, nil)

	m := newUpdate(nil, []dns.RR{rr(t, "new.example.org. 300 IN A 192.0.2.50")})
	wire, _ := m.Pack()
	got := new(dns.Msg)
	if err := got.Unpack(wire); err != nil {
		t.Fatal(err)
	}

	w := &testWriter{tsigOK: false}
	if _, err := d.ServeDNS(context.Background(), w, got); err != nil {
		t.Fatal(err)
	}
	if w.msg.Rcode != dns.RcodeRefused {
		t.Errorf("rcode = %s, want REFUSED", dns.RcodeToString[w.msg.Rcode])
	}
}

func TestWrongZoneIsNotAuth(t *testing.T) {
	d := newTestPlugin(t, nil)

	m := new(dns.Msg)
	m.SetUpdate("elsewhere.test.")
	m.Ns = []dns.RR{rr(t, "x.elsewhere.test. 300 IN A 192.0.2.50")}
	m.SetTsig("key.example.org.", dns.HmacSHA256, 300, 0)

	if got := send(t, d, m); got != dns.RcodeNotAuth {
		t.Errorf("rcode = %s, want NOTAUTH", dns.RcodeToString[got])
	}
}

func TestOutOfZoneUpdateIsNotZone(t *testing.T) {
	d := newTestPlugin(t, nil)

	m := newUpdate(nil, []dns.RR{rr(t, "x.other.test. 300 IN A 192.0.2.50")})
	if got := send(t, d, m); got != dns.RcodeNotZone {
		t.Errorf("rcode = %s, want NOTZONE", dns.RcodeToString[got])
	}
}

func TestAddIsServedAndBumpsSerial(t *testing.T) {
	d := newTestPlugin(t, nil)
	before := serialOf(t, d)

	m := newUpdate(nil, []dns.RR{rr(t, `_acme-challenge.example.org. 60 IN TXT "token-value"`)})
	if got := send(t, d, m); got != dns.RcodeSuccess {
		t.Fatalf("rcode = %s, want NOERROR", dns.RcodeToString[got])
	}

	resp := query(t, d, "_acme-challenge.example.org.", dns.TypeTXT)
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
		t.Fatalf("query after add: rcode=%s answers=%d", dns.RcodeToString[resp.Rcode], len(resp.Answer))
	}
	txt, ok := resp.Answer[0].(*dns.TXT)
	if !ok || txt.Txt[0] != "token-value" {
		t.Errorf("answer = %v, want the added TXT", resp.Answer[0])
	}

	if after := serialOf(t, d); after != before+1 {
		t.Errorf("serial = %d, want %d", after, before+1)
	}
}

// The reason this plugin owns the zone instead of overlaying one: the transfer
// plugin takes the first Transferer that answers and does not merge, so a
// side-table design would leave dynamic records out of AXFR — and a DNS-01
// challenge the secondary never receives is the failure this must not have.
func TestTransferIncludesDynamicRecords(t *testing.T) {
	d := newTestPlugin(t, nil)

	m := newUpdate(nil, []dns.RR{rr(t, `_acme-challenge.example.org. 60 IN TXT "in-the-axfr"`)})
	if got := send(t, d, m); got != dns.RcodeSuccess {
		t.Fatalf("add: %s", dns.RcodeToString[got])
	}

	ch, err := d.Transfer("example.org.", 0)
	if err != nil {
		t.Fatalf("Transfer: %v", err)
	}

	found := false
	for batch := range ch {
		for _, r := range batch {
			if txt, ok := r.(*dns.TXT); ok && txt.Txt[0] == "in-the-axfr" {
				found = true
			}
		}
	}
	if !found {
		t.Error("the dynamically added TXT was not in the AXFR stream")
	}
}

func TestAddingIdenticalRecordIsNoopButSucceeds(t *testing.T) {
	d := newTestPlugin(t, nil)
	before := serialOf(t, d)

	add := func() int {
		return send(t, d, newUpdate(nil, []dns.RR{rr(t, "www.example.org. 300 IN A 192.0.2.10")}))
	}
	if got := add(); got != dns.RcodeSuccess {
		t.Fatalf("rcode = %s", dns.RcodeToString[got])
	}
	if after := serialOf(t, d); after != before {
		t.Errorf("serial moved on a no-op update: %d -> %d", before, after)
	}
}

func TestDeleteRRsetAndSpecificRecord(t *testing.T) {
	d := newTestPlugin(t, nil)

	// Class NONE deletes one specific record: ns2's A, leaving ns's.
	del := rr(t, "ns2.example.org. 0 IN A 192.0.2.2")
	del.Header().Class = dns.ClassNONE
	del.Header().Ttl = 0
	if got := send(t, d, newUpdate(nil, []dns.RR{del})); got != dns.RcodeSuccess {
		t.Fatalf("delete rr: %s", dns.RcodeToString[got])
	}
	if d.rrsetExists("ns2.example.org.", dns.TypeA) {
		t.Error("class NONE did not delete the record")
	}
	if !d.rrsetExists("ns.example.org.", dns.TypeA) {
		t.Error("class NONE deleted more than the named record")
	}

	// Class ANY with a concrete type deletes the whole RRset.
	delset := &dns.ANY{Hdr: dns.RR_Header{
		Name: "www.example.org.", Rrtype: dns.TypeA, Class: dns.ClassANY, Ttl: 0,
	}}
	if got := send(t, d, newUpdate(nil, []dns.RR{delset})); got != dns.RcodeSuccess {
		t.Fatalf("delete rrset: %s", dns.RcodeToString[got])
	}
	if d.rrsetExists("www.example.org.", dns.TypeA) {
		t.Error("class ANY did not delete the RRset")
	}
}

// RFC 2136 §3.4.2.3: these deletions are ignored rather than rejected. A zone
// that lost its SOA or its last NS would stop being a zone, and the plugin
// must not let one update do that.
func TestApexSOAAndLastNSSurviveDeletion(t *testing.T) {
	d := newTestPlugin(t, nil)

	wipe := &dns.ANY{Hdr: dns.RR_Header{
		Name: "example.org.", Rrtype: dns.TypeANY, Class: dns.ClassANY, Ttl: 0,
	}}
	if got := send(t, d, newUpdate(nil, []dns.RR{wipe})); got != dns.RcodeSuccess {
		t.Fatalf("rcode = %s", dns.RcodeToString[got])
	}
	if soaOf(d.rrs) == nil {
		t.Error("delete-all at the apex removed the SOA")
	}
	if countRRset(d.rrs, "example.org.", dns.TypeNS) != 2 {
		t.Error("delete-all at the apex removed the NS set")
	}

	// Deleting NS one at a time must stop at the last one.
	for _, ns := range []string{"ns.example.org.", "ns2.example.org."} {
		del := rr(t, "example.org. 0 IN NS "+ns)
		del.Header().Class = dns.ClassNONE
		del.Header().Ttl = 0
		if got := send(t, d, newUpdate(nil, []dns.RR{del})); got != dns.RcodeSuccess {
			t.Fatalf("delete NS: %s", dns.RcodeToString[got])
		}
	}
	if n := countRRset(d.rrs, "example.org.", dns.TypeNS); n != 1 {
		t.Errorf("apex NS count = %d, want 1 — the last NS must survive", n)
	}
}

func TestPrerequisites(t *testing.T) {
	nameInUse := func(name string, class uint16) dns.RR {
		return &dns.ANY{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeANY, Class: class}}
	}
	rrsetPresence := func(name string, rrtype, class uint16) dns.RR {
		return &dns.ANY{Hdr: dns.RR_Header{Name: name, Rrtype: rrtype, Class: class}}
	}

	cases := []struct {
		name   string
		prereq func(t *testing.T) dns.RR
		want   int
	}{
		{"name in use, and it is", func(*testing.T) dns.RR {
			return nameInUse("www.example.org.", dns.ClassANY)
		}, dns.RcodeSuccess},
		{"name in use, but it is not", func(*testing.T) dns.RR {
			return nameInUse("absent.example.org.", dns.ClassANY)
		}, dns.RcodeNameError},
		{"name not in use, and it is not", func(*testing.T) dns.RR {
			return nameInUse("absent.example.org.", dns.ClassNONE)
		}, dns.RcodeSuccess},
		{"name not in use, but it is", func(*testing.T) dns.RR {
			return nameInUse("www.example.org.", dns.ClassNONE)
		}, dns.RcodeYXDomain},
		{"rrset exists, and it does", func(*testing.T) dns.RR {
			return rrsetPresence("www.example.org.", dns.TypeA, dns.ClassANY)
		}, dns.RcodeSuccess},
		{"rrset exists, but it does not", func(*testing.T) dns.RR {
			return rrsetPresence("www.example.org.", dns.TypeMX, dns.ClassANY)
		}, dns.RcodeNXRrset},
		{"rrset does not exist, and it does not", func(*testing.T) dns.RR {
			return rrsetPresence("www.example.org.", dns.TypeMX, dns.ClassNONE)
		}, dns.RcodeSuccess},
		{"rrset does not exist, but it does", func(*testing.T) dns.RR {
			return rrsetPresence("www.example.org.", dns.TypeA, dns.ClassNONE)
		}, dns.RcodeYXRrset},
		{"value-dependent match", func(t *testing.T) dns.RR {
			r := rr(t, "www.example.org. 0 IN A 192.0.2.10")
			r.Header().Ttl = 0
			return r
		}, dns.RcodeSuccess},
		{"value-dependent mismatch", func(t *testing.T) dns.RR {
			r := rr(t, "www.example.org. 0 IN A 198.51.100.1")
			r.Header().Ttl = 0
			return r
		}, dns.RcodeNXRrset},
		{"prerequisite with a non-zero TTL is a format error", func(t *testing.T) dns.RR {
			return rr(t, "www.example.org. 300 IN A 192.0.2.10")
		}, dns.RcodeFormatError},
		{"prerequisite outside the zone", func(*testing.T) dns.RR {
			return nameInUse("www.other.test.", dns.ClassANY)
		}, dns.RcodeNotZone},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := newTestPlugin(t, nil)
			add := rr(t, "gate.example.org. 300 IN A 192.0.2.77")
			got := send(t, d, newUpdate([]dns.RR{tc.prereq(t)}, []dns.RR{add}))
			if got != tc.want {
				t.Errorf("rcode = %s, want %s", dns.RcodeToString[got], dns.RcodeToString[tc.want])
			}
			// Whatever the verdict, the update must have been applied only on
			// success — a prerequisite that fails must leave nothing behind.
			applied := d.rrsetExists("gate.example.org.", dns.TypeA)
			if applied != (tc.want == dns.RcodeSuccess) {
				t.Errorf("update applied = %v, but rcode was %s",
					applied, dns.RcodeToString[got])
			}
		})
	}
}

// A rejected update must leave the zone byte-for-byte as it was, including
// records earlier in the same message that would individually have been fine.
func TestRejectedUpdateIsAllOrNothing(t *testing.T) {
	d := newTestPlugin(t, nil)
	before := serialOf(t, d)

	good := rr(t, "first.example.org. 300 IN A 192.0.2.60")
	bad := rr(t, "second.other.test. 300 IN A 192.0.2.61") // out of zone

	if got := send(t, d, newUpdate(nil, []dns.RR{good, bad})); got != dns.RcodeNotZone {
		t.Fatalf("rcode = %s, want NOTZONE", dns.RcodeToString[got])
	}
	if d.nameInUse("first.example.org.") {
		t.Error("the valid half of a rejected update was applied")
	}
	if after := serialOf(t, d); after != before {
		t.Errorf("serial moved on a rejected update: %d -> %d", before, after)
	}
}

func TestMutableTypePolicy(t *testing.T) {
	d := newTestPlugin(t, map[uint16]bool{dns.TypeTXT: true})

	txt := rr(t, `_acme-challenge.example.org. 60 IN TXT "allowed"`)
	if got := send(t, d, newUpdate(nil, []dns.RR{txt})); got != dns.RcodeSuccess {
		t.Errorf("TXT rcode = %s, want NOERROR", dns.RcodeToString[got])
	}

	a := rr(t, "www.example.org. 300 IN A 198.51.100.9")
	if got := send(t, d, newUpdate(nil, []dns.RR{a})); got != dns.RcodeRefused {
		t.Errorf("A rcode = %s, want REFUSED", dns.RcodeToString[got])
	}
	// And the refusal must not have partially applied.
	for _, r := range d.rrsetOf("www.example.org.", dns.TypeA) {
		if r.(*dns.A).A.String() == "198.51.100.9" {
			t.Error("a policy-refused record was applied anyway")
		}
	}
}

func TestCNAMEExclusivity(t *testing.T) {
	d := newTestPlugin(t, nil)

	// alias already has a CNAME; adding an A there must be ignored.
	if got := send(t, d, newUpdate(nil, []dns.RR{rr(t, "alias.example.org. 300 IN A 192.0.2.80")})); got != dns.RcodeSuccess {
		t.Fatalf("rcode = %s", dns.RcodeToString[got])
	}
	if d.rrsetExists("alias.example.org.", dns.TypeA) {
		t.Error("an A was added alongside an existing CNAME")
	}

	// www already has an A; adding a CNAME there must be ignored.
	if got := send(t, d, newUpdate(nil, []dns.RR{rr(t, "www.example.org. 300 IN CNAME elsewhere.example.org.")})); got != dns.RcodeSuccess {
		t.Fatalf("rcode = %s", dns.RcodeToString[got])
	}
	if d.rrsetExists("www.example.org.", dns.TypeCNAME) {
		t.Error("a CNAME was added alongside an existing A")
	}
}

func TestSOAAddOnlyMovesForward(t *testing.T) {
	d := newTestPlugin(t, nil)
	before := serialOf(t, d)

	older := rr(t, "example.org. 300 IN SOA ns.example.org. admin.example.org. 50 3600 900 86400 300")
	if got := send(t, d, newUpdate(nil, []dns.RR{older})); got != dns.RcodeSuccess {
		t.Fatalf("rcode = %s", dns.RcodeToString[got])
	}
	if after := serialOf(t, d); after != before {
		t.Errorf("a lower SOA serial was accepted: %d -> %d", before, after)
	}
}

func TestSerialGreaterWrapsPerRFC1982(t *testing.T) {
	cases := []struct {
		a, b uint32
		want bool
	}{
		{2, 1, true},
		{1, 2, false},
		{1, 1, false},
		{0, 4294967295, true},  // wrapped forward
		{4294967295, 0, false}, // the same comparison, the other way
		{1 << 31, 0, false},    // exactly half the space: undefined, so not greater
	}
	for _, tc := range cases {
		if got := serialGreater(tc.a, tc.b); got != tc.want {
			t.Errorf("serialGreater(%d, %d) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestQueriesStillWorkForUntouchedNames(t *testing.T) {
	d := newTestPlugin(t, nil)

	resp := query(t, d, "www.example.org.", dns.TypeA)
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
		t.Fatalf("rcode=%s answers=%d, want one A", dns.RcodeToString[resp.Rcode], len(resp.Answer))
	}

	// And a name that does not exist is still a proper authoritative NXDOMAIN,
	// not a fallthrough or an empty NOERROR.
	resp = query(t, d, "nothing.example.org.", dns.TypeA)
	if resp.Rcode != dns.RcodeNameError {
		t.Errorf("rcode = %s, want NXDOMAIN", dns.RcodeToString[resp.Rcode])
	}
}

package probe

import (
	"context"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"
	"github.com/miekg/dns"
)

// TestBuildZoneVersionWireFormat is the assertion that matters most here. RFC
// 9660 §2.2 says SOA-SERIAL is a 4-octet unsigned integer in NETWORK BYTE ORDER.
// Version is a Go string of opaque octets, so formatting the serial as decimal
// text would look plausible in a debugger and be wrong on the wire — a bug no
// type checker catches.
func TestBuildZoneVersionWireFormat(t *testing.T) {
	const serial = 0x01020304

	zv := buildZoneVersion("check.example.com.", serial)
	if zv == nil {
		t.Fatal("buildZoneVersion returned nil for a real zone")
	}

	if zv.Type != zoneVersionTypeSOASerial {
		t.Errorf("Type = %d, want %d (SOA-SERIAL)", zv.Type, zoneVersionTypeSOASerial)
	}
	// check.example.com. is three labels; the count identifies which zone the
	// version refers to when the queried name sits below a delegation.
	if zv.LabelCount != 3 {
		t.Errorf("LabelCount = %d, want 3", zv.LabelCount)
	}
	if len(zv.Version) != 4 {
		t.Fatalf("Version is %d octets, want exactly 4", len(zv.Version))
	}
	if got := binary.BigEndian.Uint32([]byte(zv.Version)); got != serial {
		t.Errorf("Version decodes to %#x, want %#x", got, serial)
	}
	// Explicitly not decimal text: "16909060" would be 8 octets.
	if zv.Version == "16909060" {
		t.Error("Version was written as decimal text instead of 4 network-order octets")
	}
}

// TestBuildZoneVersionLabelCounts pins the count across zone depths, since it is
// derived from the zone rather than taken from the query and a client must be
// able to rely on it.
func TestBuildZoneVersionLabelCounts(t *testing.T) {
	for _, tc := range []struct {
		zone string
		want uint8
	}{
		{"example.com.", 2},
		{"check.example.com.", 3},
		{"a.b.check.example.com.", 5},
		// Unqualified input must be treated the same as qualified.
		{"check.example.com", 3},
	} {
		zv := buildZoneVersion(tc.zone, 1)
		if zv == nil {
			t.Errorf("%s: nil", tc.zone)
			continue
		}
		if zv.LabelCount != tc.want {
			t.Errorf("%s: LabelCount = %d, want %d", tc.zone, zv.LabelCount, tc.want)
		}
	}
}

// TestBuildZoneVersionRefusesRoot — RFC 9660's single-octet label count cannot
// describe the root zone meaningfully, and this plugin is never authoritative for
// it. Returning nil keeps "cannot answer" from being emitted as an answer of
// zero, which a client would have to believe.
func TestBuildZoneVersionRefusesRoot(t *testing.T) {
	for _, zone := range []string{"", "."} {
		if zv := buildZoneVersion(zone, 1); zv != nil {
			t.Errorf("buildZoneVersion(%q) = %+v, want nil", zone, zv)
		}
	}
}

// TestRequestsZoneVersion checks the detection side.
func TestRequestsZoneVersion(t *testing.T) {
	if requestsZoneVersion(ednsQuery(nil)) {
		t.Error("no OPT record read as a ZONEVERSION request")
	}
	if requestsZoneVersion(ednsQuery(newOpt())) {
		t.Error("OPT with no options read as a ZONEVERSION request")
	}

	// RFC 9660 §3.1: the querier sends the option EMPTY.
	o := newOpt()
	o.Option = append(o.Option, &dns.EDNS0_ZONEVERSION{})
	if !requestsZoneVersion(ednsQuery(o)) {
		t.Error("empty ZONEVERSION option not detected")
	}

	// A populated option from a client is a protocol misunderstanding, but it is
	// still a request. What must not happen is echoing their payload, which is
	// covered by TestZoneVersionResponseIgnoresClientPayload below.
	o2 := newOpt()
	o2.Option = append(o2.Option, &dns.EDNS0_ZONEVERSION{LabelCount: 9, Type: 0, Version: "junk"})
	if !requestsZoneVersion(ednsQuery(o2)) {
		t.Error("populated ZONEVERSION option not detected as a request")
	}
}

// TestParseZoneVersionSerialRejectsNonsense — a misparsed serial is worse than an
// absent one, because it looks authoritative.
func TestParseZoneVersionSerialRejectsNonsense(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   *dns.EDNS0_ZONEVERSION
	}{
		{"nil", nil},
		{"unknown version type", &dns.EDNS0_ZONEVERSION{Type: 1, Version: "\x00\x00\x00\x01"}},
		{"short payload", &dns.EDNS0_ZONEVERSION{Type: 0, Version: "\x00\x01"}},
		{"long payload", &dns.EDNS0_ZONEVERSION{Type: 0, Version: "\x00\x00\x00\x00\x01"}},
		{"empty payload", &dns.EDNS0_ZONEVERSION{Type: 0, Version: ""}},
	} {
		if _, ok := parseZoneVersionSerial(tc.in); ok {
			t.Errorf("%s: parsed as valid", tc.name)
		}
	}

	good := buildZoneVersion("check.example.com.", 4242)
	got, ok := parseZoneVersionSerial(good)
	if !ok {
		t.Fatal("round trip of our own option failed to parse")
	}
	if got != 4242 {
		t.Errorf("serial = %d, want 4242", got)
	}
}

// TestZoneVersionRoundTripsOnTheWire packs the option through a real message, so
// the implementation is checked against the wire encoding rather than against
// the struct we built.
func TestZoneVersionRoundTripsOnTheWire(t *testing.T) {
	m := new(dns.Msg)
	m.SetQuestion("deadbeef.check.example.com.", dns.TypeTXT)
	opt := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
	opt.SetUDPSize(1232)
	opt.Option = append(opt.Option, buildZoneVersion("check.example.com.", 0xDEADBEEF))
	m.Extra = append(m.Extra, opt)

	wire, err := m.Pack()
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	var got dns.Msg
	if err := got.Unpack(wire); err != nil {
		t.Fatalf("Unpack: %v", err)
	}

	o := got.IsEdns0()
	if o == nil {
		t.Fatal("no OPT survived the round trip")
	}
	for _, e := range o.Option {
		zv, ok := e.(*dns.EDNS0_ZONEVERSION)
		if !ok {
			continue
		}
		serial, ok := parseZoneVersionSerial(zv)
		if !ok {
			t.Fatalf("option did not parse after round trip: %+v", zv)
		}
		if serial != 0xDEADBEEF {
			t.Errorf("serial = %#x, want %#x", serial, 0xDEADBEEF)
		}
		if zv.LabelCount != 3 {
			t.Errorf("LabelCount = %d after round trip, want 3", zv.LabelCount)
		}
		return
	}
	t.Error("ZONEVERSION option not present after round trip")
}

// serveWithOptions drives one request through ServeDNS carrying the given EDNS
// options, and returns the response's OPT record.
func serveWithOptions(t *testing.T, p *Probe, qname string, opts ...dns.EDNS0) *dns.OPT {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(qname, dns.TypeTXT)
	m.SetEdns0(1232, false)
	if o := m.IsEdns0(); o != nil {
		o.Option = append(o.Option, opts...)
	}
	rec := dnstest.NewRecorder(&test.ResponseWriter{})
	if _, err := p.ServeDNS(context.Background(), rec, m); err != nil {
		t.Fatalf("ServeDNS: %v", err)
	}
	if rec.Msg == nil {
		t.Fatal("ServeDNS wrote no message")
	}
	return rec.Msg.IsEdns0()
}

func responseZoneVersion(o *dns.OPT) *dns.EDNS0_ZONEVERSION {
	if o == nil {
		return nil
	}
	for _, e := range o.Option {
		if zv, ok := e.(*dns.EDNS0_ZONEVERSION); ok {
			return zv
		}
	}
	return nil
}

// TestZoneVersionOnlyWhenAsked — RFC 9660 §3.2 has the server include the option
// only in response to a request for it. Sending it unsolicited would add bytes to
// every answer from a zone whose whole point includes measuring response size.
func TestZoneVersionOnlyWhenAsked(t *testing.T) {
	p := newTestProbe(t, false)
	const qname = "deadbeef." + erTestZone

	if zv := responseZoneVersion(serveWithOptions(t, p, qname)); zv != nil {
		t.Errorf("ZONEVERSION sent unsolicited: %+v", zv)
	}

	zv := responseZoneVersion(serveWithOptions(t, p, qname, &dns.EDNS0_ZONEVERSION{}))
	if zv == nil {
		t.Fatal("ZONEVERSION not returned when requested")
	}
	if serial, ok := parseZoneVersionSerial(zv); !ok {
		t.Errorf("returned option does not parse: %+v", zv)
	} else if serial != p.soa().Serial {
		t.Errorf("serial = %d, want %d (the zone's SOA serial)", serial, p.soa().Serial)
	}
}

// TestZoneVersionResponseIgnoresClientPayload is the one with a security flavour.
// A client can send a populated ZONEVERSION option; the response must be built
// from OUR zone, never echoed back from theirs. Echoing would let a querier
// choose what we appear to assert about our own zone version, which any
// downstream diagnosis would then believe.
func TestZoneVersionResponseIgnoresClientPayload(t *testing.T) {
	p := newTestProbe(t, false)

	hostile := &dns.EDNS0_ZONEVERSION{
		LabelCount: 99,
		Type:       0,
		Version:    "\xff\xff\xff\xff",
	}
	zv := responseZoneVersion(serveWithOptions(t, p, "deadbeef."+erTestZone, hostile))
	if zv == nil {
		t.Fatal("no ZONEVERSION in response")
	}

	if zv.LabelCount == 99 {
		t.Error("LabelCount echoed from the client's option")
	}
	if zv.LabelCount != uint8(dns.CountLabel(dns.CanonicalName(p.Zone))) {
		t.Errorf("LabelCount = %d, want %d (derived from the zone)",
			zv.LabelCount, dns.CountLabel(dns.CanonicalName(p.Zone)))
	}
	serial, ok := parseZoneVersionSerial(zv)
	if !ok {
		t.Fatalf("response option does not parse: %+v", zv)
	}
	if serial == 0xFFFFFFFF {
		t.Error("serial echoed from the client's option")
	}
	if serial != p.soa().Serial {
		t.Errorf("serial = %d, want %d", serial, p.soa().Serial)
	}
}

// TestObserveRecordsZoneVersionAsked wires the detection into the observation and
// the in-band readout, so a `dig` user sees it too.
func TestObserveRecordsZoneVersionAsked(t *testing.T) {
	if obs := observeWith(t, ednsQuery(newOpt())); obs.ZoneVersionAsked {
		t.Error("ZoneVersionAsked = true without the option")
	}

	o := newOpt()
	o.Option = append(o.Option, &dns.EDNS0_ZONEVERSION{})
	obs := observeWith(t, ednsQuery(o))
	if !obs.ZoneVersionAsked {
		t.Fatal("ZoneVersionAsked = false with an empty ZONEVERSION option")
	}
	if s := obs.Summary(); !strings.Contains(s, "zoneversion=1") {
		t.Errorf("Summary lacks zoneversion=1: %s", s)
	}
	if s := observeWith(t, ednsQuery(newOpt())).Summary(); !strings.Contains(s, "zoneversion=0") {
		t.Errorf("Summary lacks zoneversion=0: %s", s)
	}
}

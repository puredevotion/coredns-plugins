package zoneversion

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// ConformantQuery is the wire form of an RFC 9660 §3.1 query: an OPT RR
// carrying OPTION-CODE 19 with OPTION-LENGTH 0. Built from EDNS0_LOCAL,
// which packs its Data verbatim, so the bytes do not depend on the
// miekg/dns fork under test.
func conformantQuery(t *testing.T) []byte {
	t.Helper()
	wire, err := query(wwwName, dns.TypeA, localEmptyOption()).Pack()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasSuffix(wire, []byte{0, 19, 0, 0}) {
		t.Fatalf("query does not end in an empty option 19: % x", wire)
	}
	return wire
}

// The former blocker, now fixed and pinned. Upstream miekg/dns v1.1.73
// refuses to unpack a zero-length ZONEVERSION option (ErrBuf below two
// octets), so CoreDNS answered every conformant query FORMERR before any
// plugin ran. This module's go.mod replaces it with
// github.com/puredevotion/dns, which unpacks the empty option as
// EDNS0_ZONEVERSION{Empty: true} and packs that back to zero octets. If this test fails, the replace has been lost: see
// docs/zoneversion-plugin.md, "The miekg/dns fork".
func TestMiekgUnpacksEmptyOption(t *testing.T) {
	wire := conformantQuery(t)
	m := new(dns.Msg)
	if err := m.Unpack(wire); err != nil {
		t.Fatalf("miekg/dns refuses the empty ZONEVERSION option (%v): is the puredevotion/dns replace in go.mod?", err)
	}
	zv := versionOf(m)
	if len(zv) != 1 || !zv[0].Empty {
		t.Fatalf("unpacked options %+v, want one EDNS0_ZONEVERSION with Empty set", m.IsEdns0().Option)
	}
	if got := classify(m.IsEdns0()); got != askVersion {
		t.Fatalf("classify = %d, want askVersion", got)
	}
	// And the struct form packs to exactly the same octets.
	again, err := query(wwwName, dns.TypeA, emptyOption()).Pack()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(again[2:], wire[2:]) { // Past the random message ID.
		t.Fatalf("EDNS0_ZONEVERSION{Empty: true} packs to % x, want % x", again, wire)
	}
	// One octet is still malformed: the server answers FORMERR itself.
	short := bytes.Clone(wire)
	short[len(short)-1] = 1  // OPTION-LENGTH 1.
	short = append(short, 0) // One octet of OPTION-DATA.
	short[len(short)-6]++    // Low octet of the OPT RR's RDLENGTH, just before the option.
	if err := new(dns.Msg).Unpack(short); err == nil {
		t.Fatal("a one-octet ZONEVERSION option unpacked")
	}
}

// What miekg/dns-based clients send instead: EDNS0_ZONEVERSION{} packs
// LABELCOUNT and TYPE even when empty, so the "query" carries two octets,
// which §3.2.1 makes a FORMERR.
func TestMiekgPacksEmptyStructAsTwoOctets(t *testing.T) {
	wire, err := query(wwwName, dns.TypeA, &dns.EDNS0_ZONEVERSION{Code: dns.EDNS0ZONEVERSION}).Pack()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasSuffix(wire, []byte{0, 19, 0, 2, 0, 0}) {
		t.Fatalf("wire % x", wire)
	}
	m := new(dns.Msg)
	if err := m.Unpack(wire); err != nil {
		t.Fatal(err)
	}
	if got := classify(m.IsEdns0()); got != askMalformed {
		t.Fatalf("classify = %d, want askMalformed", got)
	}
}

// LoopbackServer serves the plugin in front of zone over loopback UDP,
// through a real miekg/dns server, and returns an exchange function.
func loopbackServer(t *testing.T, zone *fakeZone) func([]byte) *dns.Msg {
	t.Helper()
	lc := net.ListenConfig{}
	pc, err := lc.ListenPacket(t.Context(), "udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback UDP: %v", err)
	}
	z := newTestPlugin(zone)
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		if _, serr := z.ServeDNS(t.Context(), w, r); serr != nil {
			t.Errorf("ServeDNS: %v", serr)
		}
	})}
	started := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(started) }
	served := make(chan error, 1)
	go func() { served <- srv.ActivateAndServe() }()
	t.Cleanup(func() {
		if serr := srv.Shutdown(); serr != nil {
			t.Errorf("shutdown: %v", serr)
		}
		if serr := <-served; serr != nil {
			t.Errorf("serve: %v", serr)
		}
	})
	<-started

	d := net.Dialer{}
	conn, err := d.DialContext(t.Context(), "udp", pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if cerr := conn.Close(); cerr != nil {
			t.Errorf("close: %v", cerr)
		}
	})
	return func(wire []byte) *dns.Msg {
		t.Helper()
		if derr := conn.SetDeadline(time.Now().Add(2 * time.Second)); derr != nil {
			t.Fatal(derr)
		}
		if _, werr := conn.Write(wire); werr != nil {
			t.Fatal(werr)
		}
		buf := make([]byte, dns.MaxMsgSize)
		n, rerr := conn.Read(buf)
		if rerr != nil {
			t.Fatal(rerr)
		}
		m := new(dns.Msg)
		if uerr := m.Unpack(buf[:n]); uerr != nil {
			t.Fatal(uerr)
		}
		return m
	}
}

// End to end over loopback UDP: the conformant query gets the serial, the
// two-octet form is FORMERR from the plugin (RFC 9660 §3.2.1) and never
// reaches the zone.
func TestLoopbackServer(t *testing.T) {
	zone := newFakeZone()
	exchange := loopbackServer(t, zone)

	got := exchange(conformantQuery(t))
	if got.Rcode != dns.RcodeSuccess {
		t.Fatalf("conformant query: rcode %s, want NOERROR", dns.RcodeToString[got.Rcode])
	}
	wantVersion(t, got, testSerial)
	before, _ := zone.counts()
	two, err := query(wwwName, dns.TypeA, &dns.EDNS0_ZONEVERSION{}).Pack()
	if err != nil {
		t.Fatal(err)
	}
	if got := exchange(two); got.Rcode != dns.RcodeFormatError || len(versionOf(got)) != 0 {
		t.Fatalf("two-octet query: rcode %s, %d options", dns.RcodeToString[got.Rcode], len(versionOf(got)))
	}
	plain, err := query(wwwName, dns.TypeA).Pack()
	if err != nil {
		t.Fatal(err)
	}
	if got := exchange(plain); got.Rcode != dns.RcodeSuccess || len(versionOf(got)) != 0 {
		t.Fatalf("plain query: rcode %s, %d options", dns.RcodeToString[got.Rcode], len(versionOf(got)))
	}
	if q, _ := zone.counts(); q != before+1 {
		t.Fatalf("zone saw %d queries after the conformant one, want 1 (the plain one; the FORMERR must not reach it)", q-before)
	}
}

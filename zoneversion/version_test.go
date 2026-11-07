package zoneversion

import (
	"bytes"
	"errors"
	"testing"

	"github.com/miekg/dns"
)

// RFC 9660 §5, Figure 2: www.example.com in example.com at serial 2023073001
// is "ZONEVERSION: 02 00 78 95 a4 e9".
func TestRFC9660Example(t *testing.T) {
	v, err := NewVersion(testApex, wwwName, 2023073001)
	if err != nil {
		t.Fatal(err)
	}
	got := v.Encode()
	if want := mustHex(t, "02007895a4e9"); !bytes.Equal(got[:], want) {
		t.Fatalf("Encode = % x, want % x", got, want)
	}
	back, err := Decode(got[:])
	if err != nil || back != v {
		t.Fatalf("Decode = %+v, %v; want %+v", back, err, v)
	}
}

func TestNewVersion(t *testing.T) {
	for _, tc := range []struct {
		err         error
		zone, qname string
		labels      uint8
	}{
		{nil, testApex, wwwName, 2},
		{nil, "example.com", "www.example.com", 2}, // Not fully qualified: qualified.
		{nil, "Example.COM.", "WWW.example.com.", 2},
		{nil, testApex, testApex, 2}, // The apex itself: equal is allowed.
		{nil, "a.b.c.example.com.", "a.b.c.example.com.", 5},
		{errRootZone, ".", wwwName, 0},
		{errNotAncestor, testApex, "www.example.net.", 0},
		{errNotAncestor, wwwName, testApex, 0}, // More labels than QNAME (§2.1).
		{errBadName, "exam..ple.com.", wwwName, 0},
		{errBadName, testApex, "", 0},
	} {
		v, err := NewVersion(tc.zone, tc.qname, 1)
		if !errors.Is(err, tc.err) {
			t.Errorf("NewVersion(%q, %q) error %v, want %v", tc.zone, tc.qname, err, tc.err)
			continue
		}
		if err == nil && v.LabelCount() != tc.labels {
			t.Errorf("NewVersion(%q, %q) labels %d, want %d", tc.zone, tc.qname, v.LabelCount(), tc.labels)
		}
	}
}

func TestDecodeRejects(t *testing.T) {
	for _, tc := range []struct {
		err error
		hex string
	}{
		{errLength, ""},           // The query form is not a response.
		{errLength, "0200"},       // No VERSION.
		{errLength, "02007895a4"}, // Short serial.
		{errLength, "02007895a4e900"},
		{errType, "02017895a4e9"},       // Unassigned TYPE 1.
		{errType, "02f67895a4e9"},       // Private-use TYPE 246.
		{errRootZone, "00007895a4e9"},   // LABELCOUNT 0: root, never emitted.
		{errLabelCount, "80007895a4e9"}, // 128 labels: no name has that many.
	} {
		if _, err := Decode(mustHex(t, tc.hex)); !errors.Is(err, tc.err) {
			t.Errorf("Decode(%s) error %v, want %v", tc.hex, err, tc.err)
		}
	}
}

// The option survives miekg/dns's pack and unpack with OPTION-LENGTH 6 (§4)
// and the same fields.
func TestEDNS0Wire(t *testing.T) {
	v, err := NewVersion(testApex, wwwName, 0xfffffffe)
	if err != nil {
		t.Fatal(err)
	}
	m := new(dns.Msg)
	m.SetQuestion(wwwName, dns.TypeA)
	m.SetEdns0(1232, false)
	o := m.IsEdns0()
	o.Option = append(o.Option, v.EDNS0())
	wire, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	enc := v.Encode()
	// OPTION-CODE 19, OPTION-LENGTH 6, then the data, at the end of the OPT RR.
	want := append([]byte{0, 19, 0, wireLen}, enc[:]...)
	if !bytes.HasSuffix(wire, want) {
		t.Fatalf("wire % x does not end in % x", wire, want)
	}
	back := new(dns.Msg)
	if err := back.Unpack(wire); err != nil {
		t.Fatal(err)
	}
	got := versionOf(back)
	if len(got) != 1 {
		t.Fatalf("%d options after unpack", len(got))
	}
	if dv, err := Decode(optionData(got[0])); err != nil || dv != v {
		t.Fatalf("unpacked %+v (%v), want %+v", dv, err, v)
	}
}

func TestValidateZeroValue(t *testing.T) {
	if (Version{}).Validate() == nil {
		t.Fatal("the zero Version (root zone) validated")
	}
}

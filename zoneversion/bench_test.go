package zoneversion

import (
	"context"
	"testing"

	"github.com/miekg/dns"
)

// The path every query to the zone takes: no ZONEVERSION option.
func BenchmarkServeDNSNoOption(b *testing.B) {
	z := newZoneVersion([]string{testApex})
	z.Next = nopHandler{}
	w := &recorder{}
	r := query(wwwName, dns.TypeA)
	ctx := context.Background()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := z.ServeDNS(ctx, w, r); err != nil {
			b.Fatal(err)
		}
	}
}

// benchVersioned runs qname, asking for the version, with the cache warm.
func benchVersioned(b *testing.B, qname string) {
	b.Helper()
	z := newTestPlugin(newFakeZone())
	ctx := context.Background()
	b.ReportAllocs()
	for b.Loop() {
		w := &recorder{}
		if _, err := z.ServeDNS(ctx, w, query(qname, dns.TypeA, emptyOption())); err != nil {
			b.Fatal(err)
		}
	}
}

// A versioned positive answer: one answer and one SOA lookup through the
// (fake) zone, the cache standing in for the other.
func BenchmarkServeDNSVersioned(b *testing.B) { benchVersioned(b, wwwName) }

// A versioned negative answer: the serial comes from the response.
func BenchmarkServeDNSVersionedNXDOMAIN(b *testing.B) { benchVersioned(b, "nx.example.com.") }

func BenchmarkEncodeDecode(b *testing.B) {
	v, err := NewVersion(testApex, wwwName, testSerial)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		enc := v.Encode()
		if _, err := Decode(enc[:]); err != nil {
			b.Fatal(err)
		}
	}
}

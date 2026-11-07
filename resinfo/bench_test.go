package resinfo

import (
	"context"
	"testing"

	"github.com/coredns/coredns/plugin/test"
	"github.com/miekg/dns"
)

func benchHandler(b *testing.B) *ResInfo {
	b.Helper()
	info, err := New(
		Pair{Key: KeyQNameMin},
		Pair{Key: KeyExtErr, Value: extErrExample, HasValue: true},
		Pair{Key: KeyInfoURL, Value: exampleURL, HasValue: true},
	)
	if err != nil {
		b.Fatal(err)
	}
	h := newResInfo([]string{resolverName, ddrName}, info, 7200)
	h.Next = test.NextHandler(dns.RcodeSuccess, nil)
	return h
}

// BenchmarkServeDNSPassThrough is the cost every other query through the
// server block pays.
func BenchmarkServeDNSPassThrough(b *testing.B) {
	h := benchHandler(b)
	w := &test.ResponseWriter{}
	req := query("www.example.org.", dns.TypeA)
	ctx := context.Background()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := h.ServeDNS(ctx, w, req); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkServeDNSAnswer answers a RESINFO query, 0x20-cased.
func BenchmarkServeDNSAnswer(b *testing.B) {
	h := benchHandler(b)
	w := &test.ResponseWriter{}
	req := query("ReSoLvEr.ExAmPlE.NeT.", dns.TypeRESINFO)
	ctx := context.Background()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := h.ServeDNS(ctx, w, req); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkDecodeWire validates RFC 9606 Figure 1's RDATA.
func BenchmarkDecodeWire(b *testing.B) {
	info, err := New(
		Pair{Key: KeyQNameMin},
		Pair{Key: KeyExtErr, Value: extErrExample, HasValue: true},
		Pair{Key: KeyInfoURL, Value: exampleURL, HasValue: true},
	)
	if err != nil {
		b.Fatal(err)
	}
	wire := info.AppendWire(nil)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := DecodeWire(wire); err != nil {
			b.Fatal(err)
		}
	}
}

package resinfo

import (
	"bytes"
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/coredns/coredns/plugin/test"
	"github.com/miekg/dns"
)

// FuzzDecodeWire: for any RDATA octets, DecodeWire never panics, and whatever
// it accepts is canonical: it re-encodes to the same octets, every string is
// at most 255 octets, and New on the decoded pairs agrees.
func FuzzDecodeWire(f *testing.F) {
	for _, s := range []string{
		"\x0cexterr=15-17\x2ainfourl=https://resolver.example.com/guide\x08qnamemin",
		"\x08qnamemin",
		"\x08qnamemin\x08qnamemin",
		"\x09qnamemin=",
		"\x00",
		"\x05",
		"",
		"\x06temp-x\x05deleg",
	} {
		f.Add([]byte(s))
	}
	for _, s := range stringSeeds(f) {
		f.Add(append([]byte{byte(min(len(s), MaxString))}, s[:min(len(s), MaxString)]...))
	}
	f.Fuzz(func(t *testing.T, rdata []byte) {
		info, err := DecodeWire(rdata)
		if err != nil {
			return
		}
		if got := info.AppendWire(nil); !bytes.Equal(got, rdata) {
			t.Fatalf("DecodeWire(%q) re-encodes to %q", rdata, got)
		}
		if info.WireLen() != len(rdata) || len(rdata) > MaxRDATA {
			t.Fatalf("WireLen %d for %d octets", info.WireLen(), len(rdata))
		}
		again, err := New(info.Pairs()...)
		if err != nil || !slices.Equal(again.Strings(), info.Strings()) {
			t.Fatalf("New disagrees: %v", err)
		}
	})
}

// FuzzPair: a single key[=value] string decodes iff it is the canonical
// rendering of a valid pair, and then splits at the first '=' exactly.
func FuzzPair(f *testing.F) {
	for _, s := range []string{KeyQNameMin, "exterr=15-17", "infourl=https://r.example/", "temp-a=b=c", "=x", "deleg=", "temp-"} {
		f.Add(s)
	}
	for _, s := range stringSeeds(f) {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		info, err := Decode([]string{s})
		if err != nil {
			return
		}
		p := info.Pairs()[0]
		if p.String() != s || strings.Contains(p.Key, "=") || len(s) > MaxString {
			t.Fatalf("Decode(%q) = %+v", s, p)
		}
		if k, v, ok := strings.Cut(s, "="); k != p.Key || v != p.Value || ok != p.HasValue {
			t.Fatalf("%q split as %+v", s, p)
		}
	})
}

// FuzzParseExtErr: an accepted exterr value parses to canonical ranges whose
// rendering is itself canonical and parses back to the same ranges.
func FuzzParseExtErr(f *testing.F) {
	for _, s := range []string{extErrExample, "1,3-4", fullRange, "17,15", "65536", "1-", "00"} {
		f.Add(s)
	}
	for _, s := range stringSeeds(f) {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		rs, err := ParseExtErr(s)
		if err != nil {
			return
		}
		for i, r := range rs {
			if r.Lo > r.Hi || (i > 0 && uint32(rs[i-1].Hi)+1 >= uint32(r.Lo)) {
				t.Fatalf("ParseExtErr(%q) = %v is not canonical", s, rs)
			}
		}
		c := FormatExtErr(rs)
		back, err := ParseExtErr(c)
		if err != nil || !slices.Equal(back, rs) || checkCanonicalExtErr(c) != nil {
			t.Fatalf("FormatExtErr round trip of %q: %q, %v", s, c, err)
		}
	})
}

// FuzzServeDNS: for any message the server could receive, the handler never
// panics; it answers exactly when the question is RESINFO/IN at a configured
// name, and then with one record carrying the configured RDATA.
func FuzzServeDNS(f *testing.F) {
	for _, m := range []*dns.Msg{query(resolverName, dns.TypeRESINFO), query("RESOLVER.arpa.", dns.TypeRESINFO), query(resolverName, dns.TypeA), query("x.example.", dns.TypeRESINFO)} {
		wire, err := m.Pack()
		if err != nil {
			f.Fatal(err)
		}
		f.Add(wire)
	}
	info, err := New(Pair{Key: KeyQNameMin}, Pair{Key: KeyExtErr, Value: extErrExample, HasValue: true})
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, wire []byte) {
		req := new(dns.Msg)
		if req.Unpack(wire) != nil {
			return
		}
		h := newResInfo([]string{resolverName, ddrName}, info, 60)
		h.Next = stubNext()
		w := &recorder{ResponseWriter: &test.ResponseWriter{}}
		code, err := h.ServeDNS(context.Background(), w, req)
		if err != nil {
			t.Fatal(err)
		}
		want := req.Opcode == dns.OpcodeQuery && len(req.Question) == 1 &&
			req.Question[0].Qtype == dns.TypeRESINFO && req.Question[0].Qclass == dns.ClassINET &&
			(equalFoldASCII(req.Question[0].Name, resolverName) || equalFoldASCII(req.Question[0].Name, ddrName))
		if want != (code == dns.RcodeSuccess) {
			t.Fatalf("answered=%v for %v", code == dns.RcodeSuccess, req.Question)
		}
		if !want {
			return
		}
		if !w.msg.Authoritative || len(w.msg.Answer) != 1 {
			t.Fatalf("reply %v", w.msg)
		}
		rr, ok := w.msg.Answer[0].(*dns.RESINFO)
		if !ok || !slices.Equal(rr.Txt, info.Strings()) {
			t.Fatalf("answer %v", w.msg.Answer[0])
		}
	})
}

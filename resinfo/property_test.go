package resinfo

import (
	"bytes"
	"context"
	"math/rand"
	"slices"
	"strings"
	"testing"

	"github.com/coredns/coredns/plugin/test"
	"github.com/miekg/dns"
)

const (
	propIterations = 5000
	propSeed       = 9606
)

func newRand() *rand.Rand {
	return rand.New(rand.NewSource(propSeed)) //nolint:gosec // G404: deterministic test generator, not security.
}

// randKey is mostly a valid key, sometimes not.
func randKey(r *rand.Rand) string {
	valid := []string{KeyQNameMin, KeyExtErr, KeyInfoURL, KeyDeleg, "temp-a", "temp-b", "temp-zz", "temp-0"}
	invalid := []string{"temp-", "Temp-a", "foo", "", "temp-a=b", "temp a"}
	if r.Intn(10) == 0 {
		return invalid[r.Intn(len(invalid))]
	}
	return valid[r.Intn(len(valid))]
}

func randValue(r *rand.Rand, key string) (string, bool) {
	if registered[key] == kindFlag && r.Intn(8) != 0 {
		return "", false
	}
	switch r.Intn(8) {
	case 0:
		return "", false
	case 1:
		return "", true
	}
	switch key {
	case KeyExtErr:
		return FormatExtErr(randRanges(r)), true
	case KeyInfoURL:
		urls := []string{"https://resolver.example.com/guide", "https://r.example/", "http://r.example/", "https://r.example/a?b=c", "https://"}
		return urls[r.Intn(len(urls))], true
	}
	b := make([]byte, r.Intn(260))
	for i := range b {
		b[i] = randByte(r, 0x20, 0x5f)
	}
	if r.Intn(10) == 0 && len(b) > 0 {
		b[r.Intn(len(b))] = randByte(r, 0, 256) // Occasionally not printable.
	}
	return string(b), true
}

// randByte is uniform in [lo, lo+n), n + lo <= 256.
func randByte(r *rand.Rand, lo, n int) byte {
	return byte(lo + r.Intn(n)) //nolint:gosec // G115: callers keep lo+n <= 256.
}

// randCode is uniform in [lo, hi), 0 <= lo < hi <= 1<<16.
func randCode(r *rand.Rand, lo, hi int) uint16 {
	return uint16(lo + r.Intn(hi-lo)) //nolint:gosec // G115: callers keep hi <= 1<<16.
}

func randRanges(r *rand.Rand) []Range {
	rs := make([]Range, 1+r.Intn(6))
	for i := range rs {
		lo := randCode(r, 0, 40)
		if r.Intn(8) == 0 {
			lo = randCode(r, 0, 1<<16)
		}
		rs[i] = Range{Lo: lo, Hi: randCode(r, int(lo), min(int(lo)+4, 1<<16))}
	}
	return CanonicalRanges(rs)
}

func randPairs(r *rand.Rand) []Pair {
	ps := make([]Pair, r.Intn(6))
	for i := range ps {
		k := randKey(r)
		v, has := randValue(r, k)
		ps[i] = Pair{Key: k, Value: v, HasValue: has}
	}
	return ps
}

// New is canonical and Decode is its inverse: for every accepted input the
// strings decode back to the same pairs, every string is at most 255 octets,
// the RDATA fits, miekg/dns packs exactly WireLen octets of RDATA, and a
// shuffled input gives byte-identical output.
func TestProperty_NewDecodeRoundTrip(t *testing.T) {
	r := newRand()
	var accepted int
	for range propIterations {
		ps := randPairs(r)
		info, err := New(ps...)
		if err != nil {
			continue
		}
		accepted++
		txt := info.Strings()
		back, err := Decode(txt)
		if err != nil || !slices.Equal(back.Pairs(), info.Pairs()) {
			t.Fatalf("Decode(%q) = %v, %v; want %v", txt, back.Pairs(), err, info.Pairs())
		}
		for _, s := range txt {
			if len(s) > MaxString {
				t.Fatalf("string of %d octets", len(s))
			}
		}
		shuffled := slices.Clone(ps)
		r.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
		again, err := New(shuffled...)
		if err != nil || !slices.Equal(again.Strings(), txt) {
			t.Fatalf("order changed the RDATA: %q vs %q (%v)", again.Strings(), txt, err)
		}
		checkWire(t, info)
	}
	if accepted < propIterations/10 {
		t.Fatalf("only %d of %d inputs were valid; the generator is too wild", accepted, propIterations)
	}
}

// checkWire: miekg/dns packs the handler's (escaped) strings to exactly
// AppendWire's octets, WireLen of them, and DecodeWire reads them back.
func checkWire(t *testing.T, info Info) {
	t.Helper()
	h := newResInfo([]string{resolverName}, info, 0)
	rr := &dns.RESINFO{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeRESINFO, Class: dns.ClassINET}, Txt: h.txt}
	buf := make([]byte, dns.Len(rr)+1)
	off, err := dns.PackRR(rr, buf, 0, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	const fixedHeader = 1 + 2 + 2 + 4 + 2 // Root name, type, class, TTL, RDLENGTH.
	got, want := buf[fixedHeader:off], info.AppendWire(nil)
	if !bytes.Equal(got, want) || len(want) != info.WireLen() {
		t.Fatalf("miekg/dns packed %q, AppendWire %q, WireLen %d", got, want, info.WireLen())
	}
	back, err := DecodeWire(got)
	if err != nil || !slices.Equal(back.Pairs(), info.Pairs()) {
		t.Fatalf("DecodeWire = %v, %v", back.Pairs(), err)
	}
}

// Decode accepts only canonical input: whatever it accepts, re-encodes to the
// same strings, and New on its pairs agrees.
func TestProperty_DecodeOnlyCanonical(t *testing.T) {
	r := newRand()
	for range propIterations {
		var txt []string
		if info, err := New(randPairs(r)...); err == nil {
			txt = info.Strings()
		}
		txt = mutate(r, txt)
		info, err := Decode(txt)
		if err != nil {
			continue
		}
		if !slices.Equal(info.Strings(), txt) {
			t.Fatalf("Decode(%q) re-encodes to %q", txt, info.Strings())
		}
		viaNew, err := New(info.Pairs()...)
		if err != nil || !slices.Equal(viaNew.Strings(), txt) {
			t.Fatalf("New disagrees with Decode on %q: %v", txt, err)
		}
	}
}

func mutate(r *rand.Rand, txt []string) []string {
	txt = slices.Clone(txt)
	switch r.Intn(5) {
	case 0:
		if len(txt) > 1 {
			i := r.Intn(len(txt) - 1)
			txt[i], txt[i+1] = txt[i+1], txt[i]
		}
	case 1:
		if len(txt) > 0 {
			txt = append(txt, txt[r.Intn(len(txt))])
		}
	case 2:
		if len(txt) > 0 {
			i := r.Intn(len(txt))
			txt[i] = strings.ToUpper(txt[i][:1]) + txt[i][1:]
		}
	case 3:
		txt = append(txt, randKey(r))
	}
	return txt
}

// CanonicalRanges covers exactly the codes its input covers, in the
// canonical shape, and FormatExtErr/ParseExtErr round-trip it.
func TestProperty_ExtErrCanonical(t *testing.T) {
	r := newRand()
	for range propIterations {
		in := make([]Range, r.Intn(8))
		for i := range in {
			lo := randCode(r, 0, 64)
			in[i] = Range{Lo: lo, Hi: randCode(r, int(lo), int(lo)+6)}
		}
		out := CanonicalRanges(in)
		if !canonicalShape(out) {
			t.Fatalf("not canonical: %v", out)
		}
		if coverage(out) != coverage(in) {
			t.Fatalf("CanonicalRanges(%v) = %v covers different codes", in, out)
		}
		if len(out) == 0 {
			continue
		}
		s := FormatExtErr(out)
		back, err := ParseExtErr(s)
		if err != nil || !slices.Equal(back, out) || checkCanonicalExtErr(s) != nil {
			t.Fatalf("ParseExtErr(%q) = %v, %v; want %v", s, back, err, out)
		}
	}
}

// canonicalShape: Lo <= Hi, and a missing code between consecutive ranges.
func canonicalShape(rs []Range) bool {
	for i, x := range rs {
		if x.Lo > x.Hi || (i > 0 && int(rs[i-1].Hi)+1 >= int(x.Lo)) {
			return false
		}
	}
	return true
}

// coverage is the set of codes below 128 that rs covers.
func coverage(rs []Range) [128]bool {
	var set [128]bool
	for _, x := range rs {
		for c := int(x.Lo); c <= int(x.Hi); c++ {
			set[c] = true
		}
	}
	return set
}

// The handler answers exactly the configured set, only for configured names
// (any ASCII case) and only for type 261 class IN, and passes everything else
// on.
func TestProperty_AnswersExactlyConfigured(t *testing.T) {
	r := newRand()
	h := newTestHandler(t, resolverName, ddrName)
	want := rfcExample(t).Strings()
	names := []string{resolverName, ddrName, "x." + resolverName, "example.net.", "resolver.example.org.", "arpa.", "_dns.resolver.arpa."}
	types := []uint16{dns.TypeRESINFO, dns.TypeA, dns.TypeAAAA, dns.TypeTXT, dns.TypeSVCB, dns.TypeANY, dns.TypeHTTPS, 260, 262}
	classes := []uint16{dns.ClassINET, dns.ClassCHAOS, dns.ClassANY}
	for range propIterations {
		name := randCase(r, names[r.Intn(len(names))])
		qt := types[r.Intn(len(types))]
		qc := classes[r.Intn(len(classes))]
		req := query(name, qt)
		req.Question[0].Qclass = qc
		req.RecursionDesired = r.Intn(2) == 0

		w := &recorder{ResponseWriter: &test.ResponseWriter{}}
		code, err := h.ServeDNS(context.Background(), w, req)
		if err != nil {
			t.Fatal(err)
		}
		lower := strings.ToLower(name)
		should := qt == dns.TypeRESINFO && qc == dns.ClassINET && (lower == resolverName || lower == ddrName)
		if !should {
			if code != nextMarker {
				t.Fatalf("%s %d/%d answered", name, qt, qc)
			}
			continue
		}
		if code != dns.RcodeSuccess || !w.msg.Authoritative || len(w.msg.Answer) != 1 {
			t.Fatalf("%s: code %d, reply %v", name, code, w.msg)
		}
		rr, ok := w.msg.Answer[0].(*dns.RESINFO)
		if !ok || rr.Hdr.Name != name || !slices.Equal(rr.Txt, want) {
			t.Fatalf("%s: answer %v", name, w.msg.Answer[0])
		}
	}
}

func randCase(r *rand.Rand, s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'z' && r.Intn(2) == 0 {
			b[i] = c - 'a' + 'A'
		}
	}
	return string(b)
}

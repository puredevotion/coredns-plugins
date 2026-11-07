package resinfo

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/test"
	"github.com/miekg/dns"
)

const (
	resolverName = "resolver.example.net."
	ddrName      = "resolver.arpa."
)

// nextMarker is the rcode the stub next plugin returns, so a test can tell a
// passed-on query from an answered one.
const nextMarker = dns.RcodeNotImplemented

func stubNext() plugin.Handler {
	return plugin.HandlerFunc(func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
		m := new(dns.Msg)
		m.SetRcode(r, nextMarker)
		if err := w.WriteMsg(m); err != nil {
			return dns.RcodeServerFailure, fmt.Errorf("stub next: %w", err)
		}
		return nextMarker, nil
	})
}

func newTestHandler(t *testing.T, names ...string) *ResInfo {
	t.Helper()
	r := newResInfo(names, rfcExample(t), 7200)
	r.Next = stubNext()
	return r
}

func query(name string, qtype uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(name, qtype)
	m.RecursionDesired = false // RFC 9606 §3: the client MUST set RD to 0.
	return m
}

func serve(t *testing.T, r *ResInfo, req *dns.Msg) (int, *dns.Msg) {
	t.Helper()
	w := &test.ResponseWriter{}
	rec := &recorder{ResponseWriter: w}
	code, err := r.ServeDNS(context.Background(), rec, req)
	if err != nil {
		t.Fatalf("ServeDNS: %v", err)
	}
	return code, rec.msg
}

type recorder struct {
	dns.ResponseWriter
	msg *dns.Msg
}

func (r *recorder) WriteMsg(m *dns.Msg) error { r.msg = m; return nil }

func TestAnswersConfiguredName(t *testing.T) {
	r := newTestHandler(t, resolverName, ddrName)
	for _, name := range []string{resolverName, "ReSoLvEr.ExAmPlE.NeT.", ddrName, "RESOLVER.ARPA."} {
		code, m := serve(t, r, query(name, dns.TypeRESINFO))
		if code != dns.RcodeSuccess || m == nil || m.Rcode != dns.RcodeSuccess {
			t.Fatalf("%s: code %d, msg %v", name, code, m)
		}
		// RFC 9606 §3: AA set, exactly one record.
		if !m.Authoritative {
			t.Errorf("%s: AA not set", name)
		}
		if len(m.Answer) != 1 || len(m.Ns) != 0 {
			t.Fatalf("%s: answer %v, authority %v", name, m.Answer, m.Ns)
		}
		rr, ok := m.Answer[0].(*dns.RESINFO)
		if !ok {
			t.Fatalf("%s: answer is %T", name, m.Answer[0])
		}
		if rr.Hdr.Name != name || rr.Hdr.Ttl != 7200 || rr.Hdr.Class != dns.ClassINET || rr.Hdr.Rrtype != dns.TypeRESINFO {
			t.Errorf("%s: header %+v", name, rr.Hdr)
		}
		if !slices.Equal(rr.Txt, rfcExample(t).Strings()) {
			t.Errorf("%s: RDATA %q", name, rr.Txt)
		}
		if m.RecursionDesired {
			t.Errorf("%s: RD copied wrongly", name)
		}
	}
}

func TestPassesEverythingElseOn(t *testing.T) {
	r := newTestHandler(t, resolverName)
	chaos := query(resolverName, dns.TypeRESINFO)
	chaos.Question[0].Qclass = dns.ClassCHAOS
	notify := query(resolverName, dns.TypeRESINFO)
	notify.Opcode = dns.OpcodeNotify
	two := query(resolverName, dns.TypeRESINFO)
	two.Question = append(two.Question, two.Question[0])
	none := query(resolverName, dns.TypeRESINFO)
	none.Question = nil
	for name, req := range map[string]*dns.Msg{
		"A at the name":            query(resolverName, dns.TypeA),
		"TXT at the name":          query(resolverName, dns.TypeTXT),
		"ANY at the name":          query(resolverName, dns.TypeANY),
		"SVCB at the name":         query(resolverName, dns.TypeSVCB),
		"RESINFO below the name":   query("x."+resolverName, dns.TypeRESINFO),
		"RESINFO above the name":   query("example.net.", dns.TypeRESINFO),
		"RESINFO elsewhere":        query("example.org.", dns.TypeRESINFO),
		"RESINFO at resolver.arpa": query(ddrName, dns.TypeRESINFO),
		"class CH":                 chaos,
		"NOTIFY":                   notify,
		"two questions":            two,
		"no question":              none,
	} {
		code, m := serve(t, r, req)
		if code != nextMarker || m == nil || m.Rcode != nextMarker {
			t.Errorf("%s: not passed on (code %d)", name, code)
		}
	}
}

func TestEDNSAndRD(t *testing.T) {
	r := newTestHandler(t, resolverName)
	req := query(resolverName, dns.TypeRESINFO)
	req.SetEdns0(1232, true)
	req.RecursionDesired = true // A client that ignores §3 still gets the answer.
	_, m := serve(t, r, req)
	if m.IsEdns0() == nil {
		t.Error("no OPT in the reply to an EDNS query (RFC 6891 §7)")
	}
	if len(m.Answer) != 1 {
		t.Errorf("answer %v", m.Answer)
	}

	// The whole reply survives the wire, and its RDATA decodes canonically.
	wire, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	var back dns.Msg
	if err := back.Unpack(wire); err != nil {
		t.Fatal(err)
	}
	rr, ok := back.Answer[0].(*dns.RESINFO)
	if !ok {
		t.Fatalf("answer is %T", back.Answer[0])
	}
	if _, err := Decode(rr.Txt); err != nil {
		t.Fatalf("published RDATA does not decode: %v", err)
	}
}

// A reply too big for a plain-DNS UDP client is truncated, not dropped.
func TestTruncatesOverUDP(t *testing.T) {
	pairs := make([]Pair, 0, 3)
	for _, k := range []string{"temp-a", "temp-b", "temp-c"} {
		pairs = append(pairs, Pair{Key: k, Value: strings.Repeat("x", 240), HasValue: true})
	}
	info, err := New(pairs...)
	if err != nil {
		t.Fatal(err)
	}
	r := newResInfo([]string{resolverName}, info, 60)
	_, m := serve(t, r, query(resolverName, dns.TypeRESINFO))
	if !m.Truncated {
		t.Fatalf("a %d-octet reply to a 512-octet client is not truncated", m.Len())
	}
}

// miekg/dns reads '\' in a TXT-like field as an escape. A value holding '\'
// or '"' must still reach the wire byte for byte.
func TestBackslashAndQuoteReachTheWire(t *testing.T) {
	info, err := New(Pair{Key: tempX, Value: `a\b"c\065`, HasValue: true})
	if err != nil {
		t.Fatal(err)
	}
	r := newResInfo([]string{resolverName}, info, 60)
	_, m := serve(t, r, query(resolverName, dns.TypeRESINFO))
	wire, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	want := info.AppendWire(nil)
	if !strings.Contains(string(wire), string(want)) {
		t.Fatalf("wire %q does not hold the raw RDATA %q", wire, want)
	}
}

type failWriter struct{ *test.ResponseWriter }

func (failWriter) WriteMsg(*dns.Msg) error { return errors.New("boom") }

func TestWriteError(t *testing.T) {
	r := newTestHandler(t, resolverName)
	code, err := r.ServeDNS(context.Background(), failWriter{&test.ResponseWriter{}}, query(resolverName, dns.TypeRESINFO))
	if err == nil || code != dns.RcodeServerFailure {
		t.Fatalf("code %d err %v", code, err)
	}
}

func TestNoNextIsServfail(t *testing.T) {
	r := newResInfo([]string{resolverName}, rfcExample(t), 60)
	code, err := r.ServeDNS(context.Background(), &test.ResponseWriter{}, query(resolverName, dns.TypeA))
	if err == nil || code != dns.RcodeServerFailure {
		t.Fatalf("code %d err %v", code, err)
	}
	if r.Name() != pluginName {
		t.Fatal(r.Name())
	}
}

func TestEqualFoldASCII(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"a.", "a.", true},
		{"A.", "a.", true},
		{"a.", "b.", false},
		{"a.", "ab.", false},
		{"K.", "k.", false}, // KELVIN SIGN: Unicode folds it onto k, RFC 4343 does not.
		{"[.", "{.", false}, // 0x5B and 0x7B differ by 0x20 but are not letters.
		{"@.", "`.", false},
	} {
		if got := equalFoldASCII(c.a, c.b); got != c.want {
			t.Errorf("equalFoldASCII(%q, %q) = %v", c.a, c.b, got)
		}
	}
}

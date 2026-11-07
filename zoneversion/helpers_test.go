package zoneversion

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
)

const (
	testApex     = "example.com."
	testSerial   = 2023073001
	wwwName      = "www.example.com."
	cnameName    = "cname.example.com."
	fwdName      = "fwd.example.com."
	strayVersion = "abcd"
)

var testEpoch = time.Unix(1_700_000_000, 0)

// FakeZone is an authoritative backend for example.com with a serial the
// test can move. It answers through request.SizeAndDo, which (like file)
// reuses the request's OPT RR in the response: the aliasing replaceOPT
// guards against.
type fakeZone struct {
	// AfterAnswer, if set, runs after a non-SOA answer is built and before
	// it is written: the place a concurrent zone reload lands between the
	// answer and the plugin's second SOA lookup.
	afterAnswer func()
	soaQueries  int
	queries     int
	mu          sync.Mutex
	serial      uint32
	// Echo, if set, puts a stray ZONEVERSION option on the response, as
	// another plugin (or CoreDNS, had a plugin registered option 19 with
	// edns.SetSupportedOption) might.
	echo  bool
	noSOA bool // The SOA query is answered without an SOA.
	// SOANotAA answers the SOA query without the AA bit, as a forwarder or
	// a cache would.
	soaNotAA bool
	// FailSOA is how many SOA queries still to answer SERVFAIL (no write).
	failSOA int
}

func newFakeZone() *fakeZone { return &fakeZone{serial: testSerial} }

func (*fakeZone) Name() string { return "fakezone" }

func (f *fakeZone) setSerial(s uint32) {
	f.mu.Lock()
	f.serial = s
	f.mu.Unlock()
}

// Counts returns how many queries the zone saw, and how many of them were
// the plugin's own SOA lookups.
func (f *fakeZone) counts() (queries, soa int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.queries, f.soaQueries
}

func soaRR(owner string, serial uint32) *dns.SOA {
	return &dns.SOA{
		Hdr:     dns.RR_Header{Name: owner, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
		Ns:      "ns." + owner,
		Mbox:    "hostmaster." + owner,
		Serial:  serial,
		Refresh: 7200, Retry: 3600, Expire: 1209600, Minttl: 300,
	}
}

func aRR(owner, ip string) *dns.A {
	return &dns.A{
		Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.ParseIP(ip),
	}
}

func nsRR(owner, target string) *dns.NS {
	return &dns.NS{Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300}, Ns: target}
}

func cnameRR(owner, target string) *dns.CNAME {
	return &dns.CNAME{Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300}, Target: target}
}

// ServeDNS answers from a fixed little zone. The serial is read once, so each
// response is one snapshot, as file's is.
func (f *fakeZone) ServeDNS(_ context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	f.mu.Lock()
	serial := f.serial
	f.queries++
	q := r.Question[0]
	failSOA := false
	if q.Qtype == dns.TypeSOA && r.IsEdns0() == nil {
		f.soaQueries++ // The plugin's own lookups are the only SOA queries without EDNS.
		if f.failSOA > 0 {
			f.failSOA--
			failSOA = true
		}
	}
	f.mu.Unlock()
	if failSOA {
		return dns.RcodeServerFailure, nil
	}

	name := strings.ToLower(q.Name)
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	if !f.answer(m, name, q.Qtype, serial) {
		return dns.RcodeServerFailure, nil
	}
	state := request.Request{W: w, Req: r}
	state.SizeAndDo(m)
	if mo := m.IsEdns0(); f.echo && mo != nil {
		// Some other plugin's stray ZONEVERSION option, wrong in every field.
		mo.Option = append(mo.Option, &dns.EDNS0_ZONEVERSION{LabelCount: 9, Type: 0, Version: strayVersion})
	}
	if q.Qtype != dns.TypeSOA && f.afterAnswer != nil {
		f.afterAnswer()
	}
	if err := w.WriteMsg(m); err != nil {
		return dns.RcodeServerFailure, fmt.Errorf("fakezone: %w", err)
	}
	if name == "twice.example.com." {
		if err := w.WriteMsg(m.Copy()); err != nil {
			return dns.RcodeServerFailure, fmt.Errorf("fakezone: %w", err)
		}
	}
	return dns.RcodeSuccess, nil
}

// Answer fills m for name/qtype in the zone at serial; false means SERVFAIL
// without writing.
func (f *fakeZone) answer(m *dns.Msg, name string, qtype uint16, serial uint32) bool {
	if answerOther(m, name) {
		return true
	}
	soa := soaRR(testApex, serial)
	switch {
	case name == testApex && qtype == dns.TypeSOA:
		if f.noSOA {
			m.Ns = []dns.RR{soaRR("other.test.", serial)}
			return true
		}
		m.Answer = []dns.RR{soa}
		m.Authoritative = !f.soaNotAA
	case name == wwwName && qtype == dns.TypeA:
		m.Answer = []dns.RR{aRR(name, "192.0.2.1")}
		m.Ns = []dns.RR{nsRR(testApex, "ns.example.com.")}
	case name == wwwName:
		m.Ns = []dns.RR{soa} // NODATA.
	case strings.HasSuffix(name, ".wild.example.com."):
		m.Answer = []dns.RR{aRR(name, "192.0.2.2")} // Synthesised from a wildcard.
	case name == cnameName:
		m.Answer = []dns.RR{cnameRR(name, "nx.other.test.")}
		m.Rcode = dns.RcodeNameError
		m.Ns = []dns.RR{soaRR("other.test.", 7)} // The target zone's SOA.
	case name == "child.example.com." || strings.HasSuffix(name, ".child.example.com."):
		m.Authoritative = false // Downward referral.
		m.Ns = []dns.RR{nsRR("child.example.com.", "ns.child.example.com.")}
	case name == fwdName:
		m.Authoritative = false // What a forwarder would answer.
		m.Answer = []dns.RR{aRR(name, "192.0.2.3")}
	case name == "fail.example.com.":
		return false
	case name == "refused.example.com.":
		m.Rcode = dns.RcodeRefused
	default:
		m.Rcode = dns.RcodeNameError
		m.Ns = []dns.RR{soa}
	}
	return true
}

// Recorder keeps what the plugin wrote.
type recorder struct {
	dns.ResponseWriter
	msgs []*dns.Msg
}

func (r *recorder) WriteMsg(m *dns.Msg) error { r.msgs = append(r.msgs, m); return nil }

func (*recorder) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("192.0.2.53"), Port: 4711}
}

func (*recorder) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 53}
}

// Query builds a query for name/qtype with EDNS(0) and the given options.
func query(name string, qtype uint16, opts ...dns.EDNS0) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(name, qtype)
	m.SetEdns0(1232, false)
	o := m.IsEdns0()
	o.Option = append(o.Option, opts...)
	return m
}

// EmptyOption is the conformant query option (RFC 9660 §3.1): code 19,
// length 0, in the form the patched miekg/dns unpacks it to (Empty set).
func emptyOption() dns.EDNS0 { return &dns.EDNS0_ZONEVERSION{Code: dns.EDNS0ZONEVERSION, Empty: true} }

// LocalEmptyOption is the same option built as EDNS0_LOCAL, which packs its
// Data verbatim: the only way to express it with upstream miekg/dns.
func localEmptyOption() dns.EDNS0 { return &dns.EDNS0_LOCAL{Code: dns.EDNS0ZONEVERSION} }

// VersionOf returns the response's ZONEVERSION options.
func versionOf(m *dns.Msg) []*dns.EDNS0_ZONEVERSION {
	var out []*dns.EDNS0_ZONEVERSION
	if o := m.IsEdns0(); o != nil {
		for _, opt := range o.Option {
			if zv, ok := opt.(*dns.EDNS0_ZONEVERSION); ok {
				out = append(out, zv)
			}
		}
	}
	return out
}

// NewTestPlugin is the plugin for example.com in front of zone, on a fixed clock.
func newTestPlugin(zone plugin.Handler) *ZoneVersion {
	z := newZoneVersion([]string{testApex})
	z.Next = zone
	z.now = func() time.Time { return testEpoch }
	return z
}

// NopHandler answers nothing: benchmarks and budgets measure the plugin alone.
type nopHandler struct{}

func (nopHandler) Name() string { return "nop" }

func (nopHandler) ServeDNS(context.Context, dns.ResponseWriter, *dns.Msg) (int, error) {
	return dns.RcodeSuccess, nil
}

// MustHex decodes a hex test vector.
func mustHex(tb testing.TB, s string) []byte {
	tb.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		tb.Fatal(err)
	}
	return b
}

// OptionData is a ZONEVERSION option's OPTION-DATA, rebuilt from miekg's fields.
func optionData(o *dns.EDNS0_ZONEVERSION) []byte {
	return append([]byte{o.LabelCount, o.Type}, o.Version...)
}

// AnswerOther fills m for the names that are not example.com's own content,
// reporting whether name was one of them.
func answerOther(m *dns.Msg, name string) bool {
	switch {
	case name == "deep.example.com." || strings.HasSuffix(name, ".deep.example.com."):
		// A zone below example.com that the chain also serves (say, auto)
		// but the plugin is not configured for.
		if name == "www.deep.example.com." {
			m.Answer = []dns.RR{aRR(name, "192.0.2.4")}
			m.Ns = []dns.RR{nsRR("deep.example.com.", "ns.deep.example.com.")}
			return true
		}
		m.Rcode = dns.RcodeNameError
		m.Ns = []dns.RR{soaRR("deep.example.com.", 99)}
	case name == "lame.example.com.":
		// Not authoritative, no answer, the apex's own NS: not a downward
		// referral (no cut below the apex), whatever produced it.
		m.Authoritative = false
		m.Ns = []dns.RR{nsRR(testApex, "ns.example.com.")}
	case name == "twice.example.com.":
		// ServeDNS writes this one twice.
	default:
		return false
	}
	return true
}

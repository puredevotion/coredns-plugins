package geoscore

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"
	"github.com/miekg/dns"
)

func contextCancelled(tb testing.TB) (context.Context, context.CancelFunc) {
	tb.Helper()
	ctx, cancel := context.WithCancel(tb.Context())
	cancel()
	return ctx, cancel
}

// zoneNext stands in for the authoritative backend after geoscore: it answers
// the zone's SOA and NXDOMAIN for everything else, and counts calls.
type zoneNext struct {
	calls int
	noSOA bool
}

func (z *zoneNext) Name() string { return "zone" }

func (z *zoneNext) ServeDNS(_ context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	z.calls++
	m := new(dns.Msg)
	m.SetReply(r)
	if q := r.Question[0]; q.Qtype == dns.TypeSOA && q.Name == testZone && !z.noSOA {
		m.Answer = []dns.RR{test.SOA("example.com. 3600 IN SOA ns.example.com. host.example.com. 1 7200 900 1209600 60")}
	} else {
		m.Rcode = dns.RcodeNameError
	}
	if err := w.WriteMsg(m); err != nil {
		return dns.RcodeServerFailure, fmt.Errorf("zone: %w", err)
	}
	return m.Rcode, nil
}

func serve(t *testing.T, h *GeoScore, name string, qtype uint16) (int, *dns.Msg) {
	t.Helper()
	req := new(dns.Msg)
	req.SetQuestion(name, qtype)
	rec := dnstest.NewRecorder(&test.ResponseWriter{})
	rc, err := h.ServeDNS(t.Context(), rec, req)
	if err != nil {
		t.Fatalf("ServeDNS(%s %d): %v", name, qtype, err)
	}
	return rc, rec.Msg
}

func handlerFor(f *fixture, next *zoneNext) *GeoScore {
	return &GeoScore{Next: next, instances: []*Instance{f.g}}
}

func TestServeAnswers(t *testing.T) {
	f := newFixture(t, testConfig(t))
	f.put(t, us1, 1, true, 0)
	f.put(t, ap1, 0.5, true, 0)
	h := handlerFor(f, &zoneNext{})

	_, m := serve(t, h, "WwW.Example.COM.", dns.TypeA)
	if !m.Authoritative || len(m.Answer) != 2 {
		t.Fatalf("A answer: %v", m)
	}
	for _, rr := range m.Answer {
		a, ok := rr.(*dns.A)
		if !ok || a.Hdr.Ttl != defaultTTL || a.Hdr.Name != "WwW.Example.COM." || !strings.HasPrefix(a.A.String(), "192.0.2.2") {
			t.Fatalf("A RR %v: want us1's addresses, TTL %d, the query's spelling", rr, defaultTTL)
		}
	}
	_, m = serve(t, h, testName, dns.TypeAAAA)
	if len(m.Answer) != 1 || aaaaString(m.Answer[0]) != "2001:db8::3" {
		t.Fatalf("AAAA answer: %v", m.Answer)
	}
}

func TestServePassesOn(t *testing.T) {
	cfg := testConfig(t)
	cfg.Endpoints = cfg.Endpoints[1:2] // us1: IPv4 only
	f := newFixture(t, cfg)
	next := &zoneNext{}
	h := handlerFor(f, next)
	for _, q := range []struct {
		name  string
		qtype uint16
	}{
		{testName, dns.TypeMX},
		{testName, dns.TypeAAAA}, // No endpoint has IPv6: not ours.
		{"other.example.com.", dns.TypeA},
		{"_geoscore." + testName, dns.TypeTXT}, // The rationale-txt option is off.
		{"wwW.example.com.x.", dns.TypeA},
	} {
		before := next.calls
		serve(t, h, q.name, q.qtype)
		if next.calls != before+1 {
			t.Errorf("%s %d not passed on", q.name, q.qtype)
		}
	}
	req := new(dns.Msg)
	req.SetQuestion(testName, dns.TypeA)
	req.Question[0].Qclass = dns.ClassCHAOS
	if _, err := h.ServeDNS(t.Context(), dnstest.NewRecorder(&test.ResponseWriter{}), req); err != nil || next.calls != 6 {
		t.Errorf("CHAOS class not passed on: %v", err)
	}
}

func TestServeFallbacks(t *testing.T) {
	cfg := testConfig(t)
	cfg.Fallback = FallbackServfail
	f := newFixture(t, cfg)
	if rc, _ := serve(t, handlerFor(f, &zoneNext{}), testName, dns.TypeA); rc != dns.RcodeServerFailure {
		t.Fatalf("servfail fallback: rcode %d", rc)
	}

	f.g.cfg.Fallback = FallbackNodata
	rc, m := serve(t, handlerFor(f, &zoneNext{}), testName, dns.TypeA)
	if rc != dns.RcodeSuccess || len(m.Answer) != 0 || len(m.Ns) != 1 {
		t.Fatalf("nodata fallback: %d %v", rc, m)
	}
	// RFC 2308 §3: the SOA's TTL is min(SOA TTL, MINIMUM).
	if soa, ok := m.Ns[0].(*dns.SOA); !ok || soa.Hdr.Ttl != 60 {
		t.Fatalf("nodata authority: %v", m.Ns)
	}
	if rc, _ := serve(t, handlerFor(f, &zoneNext{noSOA: true}), testName, dns.TypeA); rc != dns.RcodeServerFailure {
		t.Fatalf("nodata without an SOA must SERVFAIL, got %d", rc)
	}
	if rc, _ := serve(t, &GeoScore{instances: []*Instance{f.g}}, testName, dns.TypeA); rc != dns.RcodeServerFailure {
		t.Fatalf("nodata with no next plugin must SERVFAIL, got %d", rc)
	}
}

// R23: the TXT sibling names the endpoint an A query gets, and every string
// fits a <character-string>.
func TestRationaleTXT(t *testing.T) {
	cfg := testConfig(t)
	cfg.RationaleTXT = true
	f := newFixture(t, cfg)
	f.put(t, eu1, 0.85, true, 12)
	f.store.Set(cfg.KeyPrefix+":ap1", []byte("not json"))
	h := handlerFor(f, &zoneNext{})

	_, a := serve(t, h, testName, dns.TypeA)
	_, m := serve(t, h, "_GeoScore."+testName, dns.TypeTXT)
	txt, ok := m.Answer[0].(*dns.TXT)
	if !ok || txt.Hdr.Ttl != defaultTTL {
		t.Fatalf("TXT answer: %v", m.Answer)
	}
	all := strings.Join(txt.Txt, "|")
	for _, want := range []string{
		"geoscore name=www.example.com. mode=best fallback=static max-staleness=300s ttl=30",
		"A outcome=best choice=eu1 eligible=1/3 total-weight=8500",
		"AAAA outcome=best choice=eu1 eligible=1/2",
		"eu1 state=eligible score=0.8500 weight=8500 healthy=true age=12s",
		"us1 state=missing", "ap1 state=invalid",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("rationale lacks %q: %s", want, all)
		}
	}
	if got := aString(a.Answer[0]); got != "192.0.2.1" {
		t.Errorf("A answered %s, rationale says eu1", got)
	}
}

func aString(rr dns.RR) string {
	if a, ok := rr.(*dns.A); ok {
		return a.A.String()
	}
	return ""
}

func aaaaString(rr dns.RR) string {
	if a, ok := rr.(*dns.AAAA); ok {
		return a.AAAA.String()
	}
	return ""
}

func TestRationaleStringBound(t *testing.T) {
	long := strings.Repeat("x", maxIDLen)
	e := slot{found: true, ok: true, entry: Entry{
		Score: 0.123456, Healthy: false, Updated: 1,
		Signal: strings.Repeat("s", maxSignalLen), Note: strings.Repeat("n", maxNoteLen),
	}}
	line := endpointLine(long, &e, maxUpdated, 1)
	if len(line) > maxCharString || clip(line) != line {
		t.Fatalf("endpoint line is %d bytes", len(line))
	}
	if got := clip(strings.Repeat("y", 300)); len(got) != maxCharString {
		t.Fatalf("clip: %d", len(got))
	}
}

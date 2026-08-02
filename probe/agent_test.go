package probe

import (
	"strconv"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

const testAgent = "er.example.com."

// newTestAgentProbe is newTestProbe with RFC 9567 turned on. Kept separate so
// every existing test keeps exercising the reporting-disabled path, which is the
// default and has to stay working.
func newTestAgentProbe(t *testing.T, signed bool) *Probe {
	t.Helper()
	p := newTestProbe(t, signed)
	p.AgentDomain = testAgent
	p.AgentTTL = defaultAgentTTL
	return p
}

// reportName builds the QNAME a reporting resolver would send, per RFC 9567
// §6.1. Written out rather than reusing anything from errorreport.go so the
// tests fail if the parser and the construction drift apart.
func reportName(qtype uint16, reported string, ede uint16) string {
	return "_er." + strconv.Itoa(int(qtype)) + "." + dns.Fqdn(reported) +
		strconv.Itoa(int(ede)) + "._er." + testAgent
}

func reportChannelOf(m *dns.Msg) *dns.EDNS0_REPORTING {
	opt := m.IsEdns0()
	if opt == nil {
		return nil
	}
	for _, o := range opt.Option {
		if rc, ok := o.(*dns.EDNS0_REPORTING); ok {
			return rc
		}
	}
	return nil
}

// TestReportChannelAdvertised is the half of RFC 9567 without which the other
// half never gets exercised: a resolver only knows where to report because we
// told it, unsolicited, in a response it received before anything broke.
func TestReportChannelAdvertised(t *testing.T) {
	p := newTestAgentProbe(t, false)
	m := query(t, p, "a1b2c3d4."+testZone, dns.TypeTXT, true)

	rc := reportChannelOf(m)
	if rc == nil {
		t.Fatal("no Report-Channel option on a probe-zone response")
	}
	if rc.AgentDomain != testAgent {
		t.Errorf("AgentDomain = %q, want %q", rc.AgentDomain, testAgent)
	}
}

// TestReportChannelOnSuccessfulAnswers pins the "unsolicited, on every response"
// behaviour. Advertising only on failures would be the intuitive reading and is
// useless: by the time something fails, the resolver needs to already know where
// to send the report.
func TestReportChannelOnSuccessfulAnswers(t *testing.T) {
	p := newTestAgentProbe(t, true)
	for _, name := range []string{
		"a1b2c3d4." + testZone,           // plain success
		"_badsig.a1b2c3d4." + testZone,   // deliberate failure
		"_servfail.a1b2c3d4." + testZone, // deliberate SERVFAIL
		testZone,                         // apex
	} {
		m := query(t, p, name, dns.TypeTXT, true)
		if reportChannelOf(m) == nil {
			t.Errorf("no Report-Channel option on the response for %s", name)
		}
	}
}

// TestReportChannelAbsentWithoutAgentDomain: the option must not appear at all
// when reporting is unconfigured. Advertising an empty or placeholder agent
// domain is worse than not advertising — RFC 9567 §6.1 forbids it, and it sends
// every reporting resolver into a lookup that cannot succeed.
func TestReportChannelAbsentWithoutAgentDomain(t *testing.T) {
	p := newTestProbe(t, false)
	m := query(t, p, "a1b2c3d4."+testZone, dns.TypeTXT, true)
	if rc := reportChannelOf(m); rc != nil {
		t.Errorf("Report-Channel advertised %q with no agent_domain configured", rc.AgentDomain)
	}
}

// TestReportChannelNeedsEDNS: a querier that sent no OPT gets no OPT back, so
// there is nowhere to put the option and manufacturing one would be a protocol
// violation.
func TestReportChannelNeedsEDNS(t *testing.T) {
	p := newTestAgentProbe(t, false)
	m := query(t, p, "a1b2c3d4."+testZone, dns.TypeTXT, false)
	if m.IsEdns0() != nil {
		t.Fatal("response carries an OPT for a query that sent none")
	}
}

// TestAgentZoneDoesNotAdvertiseItself. The agent domain is served by the same
// plugin instance, so the advertisement has to be suppressed explicitly —
// otherwise the reporting channel invites reports about itself, and a resolver
// failing on the agent domain would report that failure to the agent domain.
func TestAgentZoneDoesNotAdvertiseItself(t *testing.T) {
	p := newTestAgentProbe(t, false)
	m := query(t, p, reportName(dns.TypeA, "a1b2c3d4."+testZone, 7), dns.TypeTXT, true)
	if rc := reportChannelOf(m); rc != nil {
		t.Errorf("agent-zone response advertises a Report-Channel (%q)", rc.AgentDomain)
	}
}

// TestReportCorrelatesToToken is the whole reason this receiver lives inside the
// probe plugin rather than being a standalone agent: the reported name carries
// the token, so a report is attributable to the visitor whose page provoked it.
func TestReportCorrelatesToToken(t *testing.T) {
	p := newTestAgentProbe(t, false)
	qname := reportName(dns.TypeA, "_badsig.a1b2c3d4."+testZone, 6)

	m := query(t, p, qname, dns.TypeTXT, true)
	if m.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s, want NOERROR", dns.RcodeToString[m.Rcode])
	}
	if len(m.Answer) != 1 {
		t.Fatalf("got %d answers, want a TXT: %v", len(m.Answer), m.Answer)
	}
	if _, ok := m.Answer[0].(*dns.TXT); !ok {
		t.Fatalf("answer is %T, want *dns.TXT (RFC 9567 §6.2)", m.Answer[0])
	}

	recs, err := p.Store.LookupReports("a1b2c3d4")
	if err != nil {
		t.Fatalf("LookupReports: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("got %d reports for the token, want 1", len(recs))
	}
	got := recs[0]
	if got.EDE != 6 {
		t.Errorf("EDE = %d, want 6", got.EDE)
	}
	if got.Qtype != dns.TypeA {
		t.Errorf("Qtype = %d, want %d (A)", got.Qtype, dns.TypeA)
	}
	if got.Qname != "_badsig.a1b2c3d4."+testZone {
		t.Errorf("Qname = %q, want the reported name", got.Qname)
	}
	if got.ReporterAddr.String() != testResolverIP {
		t.Errorf("ReporterAddr = %s, want the reporting resolver %s", got.ReporterAddr, testResolverIP)
	}
	if got.At.IsZero() {
		t.Error("At is zero; a report with no arrival time cannot be aged out or ordered")
	}
}

// TestUnattributedReportIsKept. A report about a name that carries no token of
// ours — the zone apex, say — is still a real report from a real resolver.
// Dropping it would lose exactly the reports that arrive about the zone itself.
func TestUnattributedReportIsKept(t *testing.T) {
	p := newTestAgentProbe(t, false)
	query(t, p, reportName(dns.TypeSOA, testZone, 10), dns.TypeTXT, true)

	recs, err := p.Store.LookupReports("")
	if err != nil {
		t.Fatalf("LookupReports: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("got %d unattributed reports, want 1", len(recs))
	}
	if recs[0].Token != "" {
		t.Errorf("Token = %q, want empty", recs[0].Token)
	}
}

// TestAgentNeverReturnsNXDOMAIN is the normative one. RFC 9567 §6.2: the
// monitoring agent MUST NOT respond with NXDOMAIN, because a negative cache
// entry suppresses the reports that follow. Junk under the agent domain is the
// case most likely to reach for NXDOMAIN, so that is what is tested.
func TestAgentNeverReturnsNXDOMAIN(t *testing.T) {
	p := newTestAgentProbe(t, false)
	for _, name := range []string{
		"nonsense." + testAgent,
		"_er.notanumber.name.7._er." + testAgent, // shaped like a report, bad qtype label
		"_er.1.name.999999._er." + testAgent,     // EDE label out of uint16 range
		"_er.1._er." + testAgent,                 // no reported name at all
		"_er.1.name.7." + testAgent,              // missing the trailing _er
		"a.b.c.d.e.f.g.h.i.j.k." + testAgent,     // plain junk
	} {
		m := query(t, p, name, dns.TypeTXT, true)
		if m.Rcode != dns.RcodeSuccess {
			t.Errorf("%s: rcode = %s, want NOERROR (RFC 9567 §6.2 forbids NXDOMAIN here)",
				name, dns.RcodeToString[m.Rcode])
		}
		if len(m.Answer) != 0 {
			t.Errorf("%s: got %d answers, want NODATA", name, len(m.Answer))
		}
		if len(m.Ns) != 1 {
			t.Errorf("%s: got %d authority records, want the SOA", name, len(m.Ns))
			continue
		}
		soa, ok := m.Ns[0].(*dns.SOA)
		if !ok {
			t.Errorf("%s: authority is %T, want *dns.SOA", name, m.Ns[0])
			continue
		}
		if soa.Hdr.Name != testAgent {
			t.Errorf("%s: SOA owner = %q, want the agent domain %q", name, soa.Hdr.Name, testAgent)
		}
	}
}

// TestAgentRejectsNonTXTReportQuery. RFC 9567 §6.1 sends the report as a TXT
// query. Accepting any qtype would let anyone fabricate reports with a stub
// resolver and no TXT support, so the type check is filtering, not pedantry.
func TestAgentRejectsNonTXTReportQuery(t *testing.T) {
	p := newTestAgentProbe(t, false)
	qname := reportName(dns.TypeA, "a1b2c3d4."+testZone, 7)

	m := query(t, p, qname, dns.TypeA, true)
	if m.Rcode != dns.RcodeSuccess {
		t.Errorf("rcode = %s, want NOERROR", dns.RcodeToString[m.Rcode])
	}
	if len(m.Answer) != 0 {
		t.Errorf("got %d answers for a non-TXT report query, want NODATA", len(m.Answer))
	}
	recs, err := p.Store.LookupReports("a1b2c3d4")
	if err != nil {
		t.Fatalf("LookupReports: %v", err)
	}
	if len(recs) != 0 {
		t.Errorf("recorded %d reports from a non-TXT query; the TXT requirement is what makes "+
			"fabricating reports cost something", len(recs))
	}
}

// TestAgentZoneIsNeverSigned. The agent domain exists to receive reports about
// broken signatures. If our signature is what broke, signing this zone with the
// same key means the report cannot be delivered — the failure silences its own
// report. RFC 9567 §7 recommends against signing the agent domain; here it is
// closer to mandatory.
func TestAgentZoneIsNeverSigned(t *testing.T) {
	p := newTestAgentProbe(t, true) // signer present for the probe zone
	if p.Signer == nil {
		t.Fatal("test setup: expected a signer")
	}

	for _, tc := range []struct {
		name  string
		qtype uint16
	}{
		{reportName(dns.TypeA, "a1b2c3d4."+testZone, 7), dns.TypeTXT},
		{testAgent, dns.TypeSOA},
		{"nonsense." + testAgent, dns.TypeTXT},
	} {
		m := query(t, p, tc.name, tc.qtype, true)
		for _, rr := range append(append([]dns.RR{}, m.Answer...), m.Ns...) {
			if _, ok := rr.(*dns.RRSIG); ok {
				t.Errorf("%s: agent-zone response carries an RRSIG", tc.name)
			}
			if _, ok := rr.(*dns.NSEC); ok {
				t.Errorf("%s: agent-zone response carries an NSEC from an unsigned zone", tc.name)
			}
		}
	}
}

// TestAgentApex answers SOA and NS and nothing else — including no TXT, so a
// resolver that truncated a report name down to the apex gets a visible NODATA
// rather than a success that hides the truncation.
func TestAgentApex(t *testing.T) {
	p := newTestAgentProbe(t, false)

	m := query(t, p, testAgent, dns.TypeSOA, true)
	if len(m.Answer) != 1 {
		t.Fatalf("SOA: got %d answers, want 1", len(m.Answer))
	}
	if _, ok := m.Answer[0].(*dns.SOA); !ok {
		t.Fatalf("SOA: answer is %T", m.Answer[0])
	}

	m = query(t, p, testAgent, dns.TypeNS, true)
	if len(m.Answer) != 1 {
		t.Fatalf("NS: got %d answers, want 1", len(m.Answer))
	}

	m = query(t, p, testAgent, dns.TypeTXT, true)
	if len(m.Answer) != 0 {
		t.Errorf("apex TXT: got %d answers, want NODATA", len(m.Answer))
	}
}

// TestAgentDomainDoesNotShadowProbeZone: with both zones on one plugin instance,
// the probe zone must keep answering exactly as before.
func TestAgentDomainDoesNotShadowProbeZone(t *testing.T) {
	p := newTestAgentProbe(t, false)
	m := query(t, p, "a1b2c3d4."+testZone, dns.TypeA, false)
	if len(m.Answer) != 1 {
		t.Fatalf("got %d answers for a plain probe query, want 1", len(m.Answer))
	}
	if _, ok := m.Answer[0].(*dns.A); !ok {
		t.Fatalf("answer is %T, want *dns.A", m.Answer[0])
	}
}

// TestReportMetricsLabelBounds. The EDE code in a report is chosen by whoever
// sent it, so an unregistered value must not mint a new Prometheus series —
// otherwise anyone can grow the metric without bound by walking 0..65535.
func TestReportMetricsLabelBounds(t *testing.T) {
	for _, tc := range []struct {
		code uint16
		want string
	}{
		{0, "0"},
		{6, "6"}, // DNSSEC Bogus
		{7, "7"}, // Signature Expired
		{65535, "other"},
		{4242, "other"},
	} {
		if got := edeLabel(tc.code); got != tc.want {
			t.Errorf("edeLabel(%d) = %q, want %q", tc.code, got, tc.want)
		}
	}
}

// TestReportCounterSeparatesRejects. "A resolver reported a failure" and
// "someone is sending us garbage" are different operational facts; conflating
// them lets noise look like signal on a dashboard.
func TestReportCounterSeparatesRejects(t *testing.T) {
	p := newTestAgentProbe(t, false)

	before := testutil.ToFloat64(probeReportsRejected.WithLabelValues("not-a-report"))
	query(t, p, "nonsense."+testAgent, dns.TypeTXT, true)
	if after := testutil.ToFloat64(probeReportsRejected.WithLabelValues("not-a-report")); after != before+1 {
		t.Errorf("rejected counter = %v, want %v", after, before+1)
	}

	beforeOK := testutil.ToFloat64(probeReports.WithLabelValues("7", "yes"))
	query(t, p, reportName(dns.TypeA, "_expiredsig.a1b2c3d4."+testZone, 7), dns.TypeTXT, true)
	if after := testutil.ToFloat64(probeReports.WithLabelValues("7", "yes")); after != beforeOK+1 {
		t.Errorf("report counter = %v, want %v", after, beforeOK+1)
	}
}

// TestMemStoreReportCaps. The attributed list rides the per-token cap; the
// unattributed one needs its own, larger ceiling because it is a single list
// shared by every reporter on the internet and is exactly what a flood targets.
func TestMemStoreReportCaps(t *testing.T) {
	s := NewMemStore(time.Minute, 100, 2)

	for i := uint16(0); i < 5; i++ {
		err := s.RecordReport(ReportRecord{Token: "a1b2c3d4", EDE: i})
		if i < 2 && err != nil {
			t.Fatalf("RecordReport %d: %v", i, err)
		}
		if i >= 2 && err == nil {
			t.Errorf("RecordReport %d succeeded past the per-token cap", i)
		}
	}
	recs, _ := s.LookupReports("a1b2c3d4")
	if len(recs) != 2 {
		t.Errorf("retained %d reports, want the cap of 2", len(recs))
	}

	for i := 0; i < maxUnattributedReports+5; i++ {
		_ = s.RecordReport(ReportRecord{})
	}
	unattributed, _ := s.LookupReports("")
	if len(unattributed) != maxUnattributedReports {
		t.Errorf("retained %d unattributed reports, want the cap of %d",
			len(unattributed), maxUnattributedReports)
	}
}

// TestMemStoreReportsExpire. Reports are transient diagnostic state about
// someone else's network, same as observations, and must not outlive the TTL.
func TestMemStoreReportsExpire(t *testing.T) {
	s := NewMemStore(10*time.Millisecond, 100, 8)
	if err := s.RecordReport(ReportRecord{Token: "a1b2c3d4", At: time.Now().UTC()}); err != nil {
		t.Fatalf("RecordReport: %v", err)
	}
	time.Sleep(20 * time.Millisecond)
	recs, err := s.LookupReports("a1b2c3d4")
	if err != nil {
		t.Fatalf("LookupReports: %v", err)
	}
	if len(recs) != 0 {
		t.Errorf("got %d reports after the TTL elapsed, want none", len(recs))
	}
}

// TestReportOutlivesObservations is the "arrived late" case, and it is the
// normal one rather than an edge: a resolver reports after it has given up, and
// may hold the report query in cache for a TTL first. A report must not be
// dropped because the visitor's observations are already gone.
func TestReportOutlivesObservations(t *testing.T) {
	s := NewMemStore(time.Minute, 100, 8)
	if err := s.RecordReport(ReportRecord{Token: "deadbeef", EDE: 7}); err != nil {
		t.Fatalf("RecordReport: %v", err)
	}
	// No Record() call for this token at all — the visitor never existed as far
	// as the observation store is concerned.
	obs, err := s.Lookup("deadbeef")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if len(obs) != 0 {
		t.Fatalf("got %d observations, want none", len(obs))
	}
	recs, err := s.LookupReports("deadbeef")
	if err != nil {
		t.Fatalf("LookupReports: %v", err)
	}
	if len(recs) != 1 {
		t.Errorf("got %d reports for a token with no observations, want 1", len(recs))
	}
}

package probe

import (
	"errors"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

const (
	erTestAgent = "a01.agent.example.com."
	erTestZone  = "check.example.com."
)

// TestParseReportRFCExample decodes the exact example from RFC 9567 §6.1. Using
// the spec's own worked example rather than one of our own construction is the
// point: it is the only case where a disagreement is unambiguously our bug.
func TestParseReportRFCExample(t *testing.T) {
	// _er.1.broken.test.7._er.a01.agent-domain.example
	const agent = "a01.agent-domain.example."
	r, err := ParseReport("_er.1.broken.test.7._er.a01.agent-domain.example.", agent, "")
	if err != nil {
		t.Fatalf("ParseReport: %v", err)
	}
	if r.Qtype != dns.TypeA {
		t.Errorf("Qtype = %d, want %d (A)", r.Qtype, dns.TypeA)
	}
	if r.QtypeName != "A" {
		t.Errorf("QtypeName = %q, want A", r.QtypeName)
	}
	if r.Qname != "broken.test." {
		t.Errorf("Qname = %q, want broken.test.", r.Qname)
	}
	if r.EDE != 7 {
		t.Errorf("EDE = %d, want 7", r.EDE)
	}
	if r.EDEText == "" {
		t.Error("EDEText empty for code 7, which is registered (Signature Expired)")
	}
}

// TestParseReportCorrelatesToken is why this receiver lives in the probe plugin
// rather than being generic: the failing name is one of ours, so the report is
// attributable to the visitor session that provoked it.
func TestParseReportCorrelatesToken(t *testing.T) {
	for _, tc := range []struct {
		name, qname, wantToken string
	}{
		{
			name:      "bare token",
			qname:     "_er.16.deadbeef.check.example.com.7._er." + erTestAgent,
			wantToken: "deadbeef",
		},
		{
			// The modifier that provoked the failure is part of the reported
			// name, and the token is still the label nearest the zone.
			name:      "modifier present",
			qname:     "_er.16._badsig.deadbeef.check.example.com.6._er." + erTestAgent,
			wantToken: "deadbeef",
		},
		{
			// A report about a name outside our zone is still a valid report; it
			// just has no token.
			name:      "foreign name",
			qname:     "_er.1.broken.test.7._er." + erTestAgent,
			wantToken: "",
		},
		{
			// Inside the zone but not a valid probe name: no token to recover,
			// and it must not invent one.
			name:      "in zone but ungrammatical",
			qname:     "_er.1.not-a-token.check.example.com.7._er." + erTestAgent,
			wantToken: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := ParseReport(tc.qname, erTestAgent, erTestZone)
			if err != nil {
				t.Fatalf("ParseReport: %v", err)
			}
			if r.Token != tc.wantToken {
				t.Errorf("Token = %q, want %q", r.Token, tc.wantToken)
			}
		})
	}
}

// TestParseReportRejectsHostileInput is the security case. The QNAME is chosen
// by whoever sends it, so every branch here is reachable by an arbitrary
// internet host.
func TestParseReportRejectsHostileInput(t *testing.T) {
	long := strings.Repeat("a.", maxReportLabels+5)

	for _, tc := range []struct {
		name, qname string
		wantErr     error
	}{
		{"not under agent domain", "_er.1.broken.test.7._er.evil.example.", nil},
		{"no _er sentinels", "just.a.name." + erTestAgent, ErrNotReport},
		{"leading sentinel only", "_er.1.broken.test.7." + erTestAgent, ErrNotReport},
		{"trailing sentinel only", "1.broken.test.7._er." + erTestAgent, ErrNotReport},
		{"too few labels", "_er.1.7._er." + erTestAgent, ErrNotReport},
		{"nothing but the agent domain", erTestAgent, ErrNotReport},

		// Bounded before per-label work, so a name built purely to make us walk
		// it is cheap to refuse.
		{"label flood", "_er.1." + long + "7._er." + erTestAgent, ErrBadReport},

		// strconv would accept several of these; a report is not a place to be
		// liberal about input.
		{"qtype not numeric", "_er.A.broken.test.7._er." + erTestAgent, ErrBadReport},
		{"qtype signed", "_er.+1.broken.test.7._er." + erTestAgent, ErrBadReport},
		{"qtype overflows uint16", "_er.65536.broken.test.7._er." + erTestAgent, ErrBadReport},
		{"qtype too many digits", "_er.000001.broken.test.7._er." + erTestAgent, ErrBadReport},
		{"ede not numeric", "_er.1.broken.test.abc._er." + erTestAgent, ErrBadReport},
		{"ede negative", "_er.1.broken.test.-1._er." + erTestAgent, ErrBadReport},
		{"ede overflows uint16", "_er.1.broken.test.70000._er." + erTestAgent, ErrBadReport},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseReport(tc.qname, erTestAgent, erTestZone)
			if err == nil {
				t.Fatal("ParseReport accepted hostile input")
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Errorf("err = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

// TestParseReportEmptyAgentMatchesNothing guards a misconfiguration from
// becoming a namespace grab. An empty agent domain trimmed as a suffix would
// match every name in existence, so the handler would claim traffic it has no
// business answering — and RFC 9567 §6.1 forbids advertising an empty agent
// domain in the first place.
func TestParseReportEmptyAgentMatchesNothing(t *testing.T) {
	for _, agent := range []string{"", "."} {
		if _, err := ParseReport("_er.1.broken.test.7._er.anything.example.", agent, ""); !errors.Is(err, ErrNotReport) {
			t.Errorf("agent %q: err = %v, want ErrNotReport", agent, err)
		}
	}
}

// TestParseReportUnknownEDEIsNotAnError — the EDE registry grows. A report
// carrying a code this build cannot name is still a report, and dropping it
// would silently lose exactly the novel failures worth seeing.
func TestParseReportUnknownEDEIsNotAnError(t *testing.T) {
	r, err := ParseReport("_er.1.broken.test.65000._er."+erTestAgent, erTestAgent, "")
	if err != nil {
		t.Fatalf("ParseReport: %v", err)
	}
	if r.EDE != 65000 {
		t.Errorf("EDE = %d, want 65000", r.EDE)
	}
	if r.EDEText != "" {
		t.Errorf("EDEText = %q, want empty for an unregistered code", r.EDEText)
	}
}

// TestParseReportCaseInsensitive — DNS names are case-insensitive, and a
// resolver doing 0x20 randomization will send the sentinels in mixed case.
// Rejecting those would drop reports from precisely the most careful resolvers.
func TestParseReportCaseInsensitive(t *testing.T) {
	r, err := ParseReport("_ER.16.DeadBeef.Check.Example.COM.7._Er."+strings.ToUpper(erTestAgent), erTestAgent, erTestZone)
	if err != nil {
		t.Fatalf("ParseReport: %v", err)
	}
	if r.Token != "deadbeef" {
		t.Errorf("Token = %q, want deadbeef", r.Token)
	}
	if r.Qname != "deadbeef.check.example.com." {
		t.Errorf("Qname = %q, want deadbeef.check.example.com.", r.Qname)
	}
}

// TestReportChannelOption checks the advertise side, including the MUST NOT.
func TestReportChannelOption(t *testing.T) {
	if o := ReportChannelOption(erTestAgent); o == nil {
		t.Fatal("ReportChannelOption returned nil for a real agent domain")
	} else if o.AgentDomain != erTestAgent {
		t.Errorf("AgentDomain = %q, want %q", o.AgentDomain, erTestAgent)
	} else if o.Option() != dns.EDNS0REPORTING {
		t.Errorf("Option() = %d, want %d", o.Option(), dns.EDNS0REPORTING)
	}

	// RFC 9567 §6.1: MUST NOT include the option when the agent domain is empty
	// or the null label. Returning nil makes "not configured" and "must not
	// advertise" the same path, so a caller cannot get it wrong.
	for _, empty := range []string{"", "."} {
		if o := ReportChannelOption(empty); o != nil {
			t.Errorf("ReportChannelOption(%q) = %v, want nil", empty, o)
		}
	}
}

// TestReportChannelOptionRoundTrips packs and unpacks the option through a real
// message, so the advertisement is verified against the wire format rather than
// against the struct we happened to build.
func TestReportChannelOptionRoundTrips(t *testing.T) {
	m := new(dns.Msg)
	m.SetQuestion("deadbeef.check.example.com.", dns.TypeTXT)
	opt := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
	opt.SetUDPSize(1232)
	opt.Option = append(opt.Option, ReportChannelOption(erTestAgent))
	m.Extra = append(m.Extra, opt)

	wire, err := m.Pack()
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	var got dns.Msg
	if err := got.Unpack(wire); err != nil {
		t.Fatalf("Unpack: %v", err)
	}

	o := got.IsEdns0()
	if o == nil {
		t.Fatal("no OPT record survived the round trip")
	}
	for _, e := range o.Option {
		if rc, ok := e.(*dns.EDNS0_REPORTING); ok {
			if rc.AgentDomain != erTestAgent {
				t.Errorf("AgentDomain = %q, want %q", rc.AgentDomain, erTestAgent)
			}
			return
		}
	}
	t.Error("Report-Channel option not present after round trip")
}

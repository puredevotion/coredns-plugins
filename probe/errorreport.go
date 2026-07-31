package probe

import (
	"errors"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

// RFC 9567 DNS Error Reporting — the receiving side.
//
// Why this belongs in THIS plugin rather than a generic one: RFC 9567 lets a
// resolver tell an authoritative operator "I could not resolve your name, and
// here is the extended error code that stopped me". Reports are only generated
// when something actually fails — and this zone manufactures failures on
// purpose (`_badsig`, `_expiredsig`, `_futuresig`, `_unsigned`, `_nxdomain`).
// So the deliberately-broken variants become a report generator, and the reports
// are attributable to the token that provoked them, which is the one thing a
// public agent domain normally cannot do.
//
// Direction of data matters here. Everything else in this plugin observes a
// query we were asked. This parses a name an arbitrary internet host chose,
// which is a different trust posture — see ParseReport's bounds.

// Report is one decoded RFC 9567 error report.
type Report struct {
	// Qtype is the type of the query that failed, as the reporting resolver
	// stated it.
	Qtype uint16
	// QtypeName is Qtype rendered for display, e.g. "A"; "TYPE1234" for types
	// with no mnemonic.
	QtypeName string
	// Qname is the name the resolver could not resolve, fully qualified.
	Qname string
	// EDE is the RFC 8914 extended error code the resolver reported.
	EDE uint16
	// EDEText is the registered description for EDE, empty for codes this build
	// does not know. Unknown is not an error: the registry grows, and a report
	// carrying a code we cannot name is still a report.
	EDEText string
	// Token is the probe token extracted from Qname when the failing name was
	// one of ours, empty otherwise. This is what correlates a report back to a
	// visitor's session.
	Token string
}

var (
	// ErrNotReport means the name is not shaped like a report at all — no _er
	// sentinels in the right places. Distinguished from ErrBadReport so a
	// handler can answer REFUSED for "not for me" and still record that a
	// malformed report arrived.
	ErrNotReport = errors.New("probe: not an error report name")
	// ErrBadReport means the name had the report shape but its contents did not
	// parse.
	ErrBadReport = errors.New("probe: malformed error report")
)

// Bounds on what will be parsed. These exist because the input is chosen by
// whoever sends it, not by us.
//
// maxReportLabels is generous relative to any real report (a reported name is
// normally a handful of labels) but far below the 127-label DNS ceiling, so a
// name crafted purely to make us do work is rejected on sight rather than
// walked. maxDecimalLabel bounds the numeric labels: a uint16 is at most five
// digits, so anything longer is malformed by construction and there is no
// reason to hand it to strconv.
const (
	maxReportLabels = 24
	maxDecimalLabel = 5
)

// ParseReport decodes an RFC 9567 report QNAME addressed to agentDomain.
//
// The construction, per RFC 9567 §6.1, is:
//
//	_er.<QTYPE>.<reported name labels>.<EDE code>._er.<agent domain>
//
// e.g. for A/broken.test failing with EDE 7 (Signature Expired) at agent domain
// a01.agent-domain.example:
//
//	_er.1.broken.test.7._er.a01.agent-domain.example
//
// probeZone, when non-empty, is the probe zone whose tokens should be recovered
// from the reported name; pass "" to skip correlation.
func ParseReport(qname, agentDomain, probeZone string) (Report, error) {
	name := dns.CanonicalName(qname)
	agent := dns.CanonicalName(agentDomain)

	// An empty agent domain must never match anything. RFC 9567 §6.1 forbids
	// advertising an empty or null agent domain at all, and treating "" as a
	// suffix that matches every name would turn a misconfiguration into a
	// handler that claims the whole namespace.
	if agent == "" || agent == "." {
		return Report{}, ErrNotReport
	}
	if !dns.IsSubDomain(agent, name) {
		return Report{}, ErrNotReport
	}

	rest := strings.TrimSuffix(name, agent)
	rest = strings.TrimSuffix(rest, ".")
	if rest == "" {
		return Report{}, ErrNotReport
	}

	labels := dns.SplitDomainName(rest)
	// _er + qtype + >=1 reported label + ede + _er
	if len(labels) < 5 {
		return Report{}, ErrNotReport
	}
	if len(labels) > maxReportLabels {
		// Refused before any per-label work, deliberately.
		return Report{}, ErrBadReport
	}
	if labels[0] != "_er" || labels[len(labels)-1] != "_er" {
		return Report{}, ErrNotReport
	}

	qtype, err := parseDecimalLabel(labels[1])
	if err != nil {
		return Report{}, err
	}
	ede, err := parseDecimalLabel(labels[len(labels)-2])
	if err != nil {
		return Report{}, err
	}

	reported := labels[2 : len(labels)-2]
	if len(reported) == 0 {
		return Report{}, ErrBadReport
	}
	qn := dns.Fqdn(strings.Join(reported, "."))

	r := Report{
		Qtype:     qtype,
		QtypeName: qtypeName(qtype),
		Qname:     qn,
		EDE:       ede,
		EDEText:   dns.ExtendedErrorCodeToString[ede],
	}

	// Correlate to a visitor when the failing name was one of ours. The token is
	// the label closest to the zone, matching ParseQuery's grammar, so a report
	// about `_badsig.deadbeef.check.example.com` recovers `deadbeef`.
	if probeZone != "" {
		zone := dns.CanonicalName(probeZone)
		if zone != "." && dns.IsSubDomain(zone, qn) {
			sub := strings.TrimSuffix(qn, zone)
			sub = strings.TrimSuffix(sub, ".")
			if q, ok := ParseQuery(sub); ok {
				r.Token = q.Token
			}
		}
	}
	return r, nil
}

// parseDecimalLabel parses one of the two numeric labels. Rejects anything that
// is not plain digits within uint16 range: strconv would accept "+1" and "-0",
// and a report is not a place to be liberal.
func parseDecimalLabel(s string) (uint16, error) {
	if s == "" || len(s) > maxDecimalLabel {
		return 0, ErrBadReport
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, ErrBadReport
		}
	}
	n, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0, ErrBadReport
	}
	return uint16(n), nil
}

func qtypeName(t uint16) string {
	if s, ok := dns.TypeToString[t]; ok {
		return s
	}
	return "TYPE" + strconv.Itoa(int(t))
}

// ReportChannelOption builds the unsolicited EDNS0 Report-Channel option
// advertising agentDomain.
//
// Returns nil when agentDomain is empty or the null label, because RFC 9567 §6.1
// says the option MUST NOT be included in that case — so "not configured" and
// "advertise nothing" are the same code path rather than something a caller has
// to remember to check.
func ReportChannelOption(agentDomain string) *dns.EDNS0_REPORTING {
	d := dns.CanonicalName(agentDomain)
	if d == "" || d == "." {
		return nil
	}
	return &dns.EDNS0_REPORTING{AgentDomain: d}
}

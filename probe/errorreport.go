package probe

import (
	"errors"
	"net/netip"
	"strconv"
	"strings"
	"time"

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

// ReportRecord is a Report as stored: the decoded report plus who sent it and
// when. Separate from Report because Report is a pure function of one name,
// while this carries connection facts that only the handler has.
//
// The JSON tags are a contract with the web tier, which decodes these out of
// Valkey with no shared code. Renaming one silently empties a field on a page
// rather than failing anywhere.
type ReportRecord struct {
	// At is when the report reached us, NOT when the failure happened. A
	// resolver reports after it gives up, and may cache the report query for a
	// TTL before repeating it, so this can lag the failure by minutes.
	At time.Time `json:"at"`
	// Token correlates the report to a visitor, empty when the reported name was
	// not one of ours. Empty is common and expected: a resolver can report about
	// any name in the zone, including the apex.
	Token string `json:"token,omitempty"`

	Qtype     uint16 `json:"qtype"`
	QtypeName string `json:"qtype_name"`
	Qname     string `json:"qname"`
	EDE       uint16 `json:"ede"`
	EDEText   string `json:"ede_text,omitempty"`

	// ReporterAddr is the egress address of the RESOLVER that sent the report.
	// It need not equal the address that made the failing query — a resolver
	// pool can report from a different member than the one that failed, and that
	// mismatch is itself worth being able to see.
	ReporterAddr netip.Addr `json:"reporter_addr"`
	// ReporterPrefix groups a resolver pool's addresses, same widths as
	// Observation.ResolverPrefix and for the same reason.
	ReporterPrefix netip.Prefix `json:"reporter_prefix"`
	// Transport is how the report query itself arrived.
	Transport Transport `json:"transport"`
}

// NewReportRecord stamps a parsed report with its arrival facts.
func NewReportRecord(r Report, addr netip.Addr, transport Transport) ReportRecord {
	addr = addr.Unmap()
	bits := v4PrefixBits
	if addr.Is6() {
		bits = v6PrefixBits
	}
	prefix, err := addr.Prefix(bits)
	if err != nil {
		// Only reachable if bits exceeds the address width, which the branch
		// above prevents. A host route beats dropping the record.
		prefix = netip.PrefixFrom(addr, addr.BitLen())
	}
	return ReportRecord{
		At:             time.Now().UTC(),
		Token:          r.Token,
		Qtype:          r.Qtype,
		QtypeName:      r.QtypeName,
		Qname:          r.Qname,
		EDE:            r.EDE,
		EDEText:        r.EDEText,
		ReporterAddr:   addr,
		ReporterPrefix: prefix,
		Transport:      transport,
	}
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

// attachReportChannel adds the Report-Channel option to a response's OPT record.
//
// Mirrors attachEDE, including the requirement that an OPT already be present: a
// querier that sent no EDNS gets no OPT in its response, and manufacturing one
// to advertise a feature it cannot parse is how middleboxes learn to drop our
// answers.
//
// The duplicate guard is not defensive clutter — RFC 9567 §6.1 says the server
// MUST NOT include more than one Report-Channel option in a response, and this
// response's OPT is the CLIENT's OPT reused in place by SizeAndDo. CoreDNS's
// supportedOptions filter happens to strip an unknown option code 18 on the way
// past today, so a client cannot currently smuggle one in; that filter's
// contents are not this plugin's to depend on.
func attachReportChannel(m *dns.Msg, agentDomain string) {
	o := ReportChannelOption(agentDomain)
	if o == nil {
		return
	}
	opt := m.IsEdns0()
	if opt == nil {
		return
	}
	for _, existing := range opt.Option {
		if _, ok := existing.(*dns.EDNS0_REPORTING); ok {
			return
		}
	}
	opt.Option = append(opt.Option, o)
}

// edeLabel renders an extended error code for use as a Prometheus label.
//
// Unregistered codes collapse to "other" rather than minting a series per value.
// The sender of a report picks this number, so without the collapse anyone could
// grow probeReports without bound by walking 0..65535 — the same cardinality
// argument metrics.go makes about addresses and tokens, except here the input is
// chosen by a stranger rather than merely varied.
func edeLabel(code uint16) string {
	if _, known := dns.ExtendedErrorCodeToString[code]; !known {
		return "other"
	}
	return strconv.Itoa(int(code))
}

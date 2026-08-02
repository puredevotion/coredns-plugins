package probe

import (
	"errors"

	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
)

// The RFC 9567 monitoring agent — the zone that RECEIVES error reports.
//
// This is the other half of errorreport.go. The probe zone advertises an agent
// domain in every response (the Report-Channel option, code 18); a validating
// resolver that then fails to resolve one of our names encodes the failure into
// a QNAME under that agent domain and queries it. Serving that zone is how the
// failure comes back to us.
//
// Why it is served by this plugin rather than a generic one: correlation. A
// public agent domain normally receives anonymous reports about names it knows
// nothing about. Here the reported name usually contains a probe token, so a
// report can be attributed to the visitor whose page provoked it — which turns
// "some resolver somewhere failed" into "your resolver reported EDE 7 for the
// expired-signature variant you just requested".
//
// # Trust posture
//
// Everything else in this plugin parses names we handed out. This parses names
// an arbitrary internet host composed, for a zone whose whole job is to be
// queried by strangers. ParseReport bounds the label count and the numeric
// labels before doing any work; this file adds the rest:
//
//   - The agent zone is NEVER signed, even when the probe zone has a signer.
//     RFC 9567 §7 recommends against signing the agent domain, and there is a
//     sharper reason here: this zone exists to receive reports about broken
//     signatures. Signing it with the probe zone's key would mean a resolver
//     that cannot validate our signatures also cannot deliver the report saying
//     so — the failure would silence its own report.
//   - NXDOMAIN is never returned. RFC 9567 §6.2 forbids it for monitored
//     domains because a negative cache entry suppresses subsequent reports.
//     Every name under the agent domain therefore answers NOERROR: a TXT for a
//     well-formed report, NODATA for anything else.
//   - The reported name is stored, never re-queried, never used to build a
//     name we look up. A report naming `evil.example` is a string in a JSON
//     blob, not a resolution.

// agentTXT is the positive response body. RFC 9567 §6.2 recommends the agent
// answer with a TXT record; the content is unspecified.
//
// Kept to two words deliberately. This is bytes on the wire for every report,
// and a report query is by construction already a long name — the response is
// the one part of the exchange we control the size of.
const agentTXT = "report received"

// serveReport answers a query under the agent domain.
func (p *Probe) serveReport(state request.Request, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	qname := state.Name()

	if qname == p.AgentDomain {
		return p.serveAgentApex(state, w, r)
	}

	rep, err := ParseReport(qname, p.AgentDomain, p.Zone)
	if err != nil {
		// NODATA, not REFUSED and certainly not NXDOMAIN. The probe zone REFUSES
		// names its grammar rejects, and that is right there — a malformed probe
		// name is a client error worth surfacing. Here the opposite holds: a
		// resolver that gets an error back for a report may retry it, or cache
		// the failure and stop reporting. Absorbing junk quietly is the correct
		// behaviour for a mailbox.
		reason := "not-a-report"
		if errors.Is(err, ErrBadReport) {
			reason = "malformed"
		}
		probeReportsRejected.WithLabelValues(reason).Inc()
		return p.respondAgent(state, w, r, nil)
	}

	// RFC 9567 §6.1: "The resulting report query is sent as a standard DNS query
	// for a TXT DNS resource record type." A well-formed report name asked with
	// another type is not a report — it is somebody reading the zone, or a
	// scanner. Counted, answered NODATA, and deliberately NOT recorded: a report
	// store that accepts any qtype can be filled with fabricated reports by
	// anyone who can compose a name, and the TXT requirement is free filtering.
	if state.QType() != dns.TypeTXT {
		probeReportsRejected.WithLabelValues("wrong-qtype").Inc()
		return p.respondAgent(state, w, r, nil)
	}

	correlated := "no"
	if rep.Token != "" {
		correlated = "yes"
	}
	probeReports.WithLabelValues(edeLabel(rep.EDE), correlated).Inc()

	transport, _ := transportFrom(w, state.Proto())
	rec := NewReportRecord(rep, addrOf(state), transport)
	if err := p.Store.RecordReport(rec); err != nil {
		// Answered anyway, for the same reason the observation path does: a full
		// or unreachable store must degrade the measurement rather than make the
		// reporting channel itself look broken to the resolver using it.
		log.Warningf("recording error report for %s: %v", rep.Qname, err)
	}

	log.Infof("RFC 9567 report: qname=%s qtype=%s ede=%d (%s) token=%q reporter=%s proto=%s",
		rep.Qname, rep.QtypeName, rep.EDE, rep.EDEText, rep.Token, rec.ReporterPrefix, transport)

	answer := []dns.RR{&dns.TXT{
		Hdr: dns.RR_Header{
			Name: qname, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: p.AgentTTL,
		},
		Txt: []string{agentTXT},
	}}
	return p.respondAgent(state, w, r, answer)
}

// serveAgentApex answers the agent domain's own records.
//
// Only SOA and NS exist. A TXT at the apex would be tempting as a "this is an
// RFC 9567 agent" marker, but the apex is also what a resolver hits when it
// truncates a report name it could not fit, and answering positively there would
// make that failure invisible.
func (p *Probe) serveAgentApex(state request.Request, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	var answer []dns.RR
	switch state.QType() {
	case dns.TypeSOA:
		answer = []dns.RR{p.agentSOA()}
	case dns.TypeNS:
		answer = []dns.RR{&dns.NS{
			Hdr: dns.RR_Header{
				Name: p.AgentDomain, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: p.AgentTTL,
			},
			Ns: p.NSName,
		}}
	}
	return p.respondAgent(state, w, r, answer)
}

// respondAgent writes an agent-zone reply.
//
// Separate from respond() rather than a flag on it, because three of respond()'s
// behaviours are wrong here and every one of them is wrong silently:
//
//   - no signing (see the file comment),
//   - no Report-Channel option, which would invite reports about the reporting
//     channel and, since the agent domain is its own agent, loop,
//   - no NSEC in the authority section, since an unsigned zone proving denial
//     with a bare NSEC would be noise a validator has to discard anyway.
func (p *Probe) respondAgent(state request.Request, w dns.ResponseWriter, r *dns.Msg, answer []dns.RR) (int, error) {
	m := new(dns.Msg)
	m.SetRcode(r, dns.RcodeSuccess)
	m.Authoritative = true
	m.Answer = answer
	if len(answer) == 0 {
		// NODATA: the name "exists" (every name under this domain does, by
		// construction) and carries no record of the requested type.
		m.Ns = []dns.RR{p.agentSOA()}
	}

	state.SizeAndDo(m)
	m = state.Scrub(m)

	if err := w.WriteMsg(m); err != nil {
		return dns.RcodeServerFailure, err
	}
	return dns.RcodeSuccess, nil
}

// agentSOA is the agent zone's SOA.
//
// MINIMUM is AgentTTL, which is what governs negative caching of the NODATA
// answers above. RFC 9567 §6.2 calls that caching essential — it is what limits
// a reporting resolver to one report query per TTL for the same problem — so
// this value is a rate limit on our own inbound reports, not a detail.
func (p *Probe) agentSOA() *dns.SOA {
	return &dns.SOA{
		Hdr: dns.RR_Header{
			Name: p.AgentDomain, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: p.AgentTTL,
		},
		Ns:      p.NSName,
		Mbox:    p.Mbox,
		Serial:  1, // Synthesized per query; nothing transfers this zone.
		Refresh: 3600,
		Retry:   900,
		Expire:  604800,
		Minttl:  p.AgentTTL,
	}
}

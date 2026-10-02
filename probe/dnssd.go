package probe

import (
	"strings"

	"github.com/miekg/dns"
)

// RFC 6763 — DNS-Based Service Discovery, served PER VISITOR.
//
// # The design decision that makes this measurable at all
//
// DNS-SD normally lives at fixed names: `_services._dns-sd._udp.<zone>`. That is
// exactly wrong for this lab — a fixed name is cacheable, so the first visitor's
// query populates every cache between here and the internet and no later visitor is
// ever observed. It would look implemented and measure nothing.
//
// So the browse tree is placed UNDER the token instead:
//
//	_services._dns-sd._udp.<token>.<zone>   browse: which service types exist
//	_probe._tcp.<token>.<zone>              enumerate instances of that type
//	probe._probe._tcp.<token>.<zone>        the instance: SRV + TXT
//
// Every name is unique per visitor, so the whole three-step walk is attributable to
// one session and defeats caching the same way the rest of the zone does.
//
// # What it measures
//
// Whether a resolver or client actually follows a DNS-SD chain, and how. The steps
// arrive as separate queries for distinguishable names, so the observation sequence
// shows which of the three levels were reached and whether the client used the
// additional-section records or re-queried for them (RFC 6763 §12 says a server
// SHOULD include SRV/TXT/address records in additional; plenty of clients ignore
// them and ask again, which is the finding).
//
// Underscore-prefixed service labels are also RFC 8552 attrleaf names, so this
// doubles as a check that a resolver transports them intact — the same class of
// mangling the ECH canary looks for, one layer up.

const (
	// DnssdBrowseLabels is RFC 6763 §9's meta-query prefix, split for matching.
	dnssdMetaService = "_services"
	dnssdMetaDNSSD   = "_dns-sd"
	dnssdMetaUDP     = "_udp"

	// DnssdServiceType and dnssdProto are the single service type advertised.
	// One type, deliberately: this exists to observe a walk, not to model a real
	// service catalogue, and every extra type is another name to keep consistent
	// across three levels for no additional measurement.
	dnssdServiceType = "_probe"
	dnssdProto       = "_tcp"

	// DnssdInstance is the instance name. RFC 6763 §4.1.1 allows arbitrary UTF-8
	// here; a plain ASCII label is used because an escaped or spaced instance name
	// would test the client's name parser rather than its DNS-SD walk, which is a
	// different experiment and would muddy this one.
	dnssdInstance = "probe"

	// DnssdPort is advertised in the SRV record. Nothing listens: this zone serves
	// DNS, not the advertised service. Stated here because an SRV record is a
	// promise a naive client will try to keep.
	dnssdPort = 443
)

// dnssdKind is which level of the browse tree a name refers to.
type dnssdKind int

const (
	dnssdNone dnssdKind = iota
	// DnssdBrowse is `_services._dns-sd._udp.<token>` — "what types are here?".
	dnssdBrowse
	// DnssdEnumerate is `_probe._tcp.<token>` — "what instances of this type?".
	dnssdEnumerate
	// DnssdInstanceName is `probe._probe._tcp.<token>` — the instance itself.
	dnssdInstanceName
)

// parseDNSSD classifies a name below the zone, with the zone already stripped, and
// returns the token it belongs to.
//
// Matching is right-to-left because the token is the rightmost label, the same
// convention ParseQuery uses. Case-insensitive: DNS-SD labels are DNS labels, and a
// resolver doing 0x20 randomization will send them mixed-case — rejecting those
// would drop precisely the most careful clients.
func parseDNSSD(sub string) (kind dnssdKind, token string) {
	sub = strings.TrimSuffix(sub, ".")
	i := strings.LastIndexByte(sub, '.')
	if i < 0 {
		return dnssdNone, "" // One label is the token alone, not a browse name.
	}
	token, ok := parseToken(sub[i+1:])
	if !ok {
		return dnssdNone, ""
	}

	// The prefix is matched label by label against the three fixed shapes
	// rather than split and lowercased into a slice, which allocated on every
	// probe query — this runs ahead of ParseQuery for all of them.
	prefix := sub[:i]
	switch {
	case labelsEqualFold(prefix, dnssdMetaService, dnssdMetaDNSSD, dnssdMetaUDP):
		return dnssdBrowse, token
	case labelsEqualFold(prefix, dnssdInstance, dnssdServiceType, dnssdProto):
		return dnssdInstanceName, token
	case labelsEqualFold(prefix, dnssdServiceType, dnssdProto):
		return dnssdEnumerate, token
	}
	return dnssdNone, ""
}

// labelsEqualFold reports whether name is exactly the given labels, compared
// ASCII case-insensitively (RFC 4343) and without allocating.
func labelsEqualFold(name string, labels ...string) bool {
	for i, want := range labels {
		var l string
		if j := strings.IndexByte(name, '.'); j >= 0 {
			l, name = name[:j], name[j+1:]
		} else if i == len(labels)-1 {
			l, name = name, ""
		} else {
			return false // Fewer labels than wanted.
		}
		if !equalFoldASCII(l, want) {
			return false
		}
	}
	return name == ""
}

// equalFoldASCII compares two strings byte for byte, folding A-Z onto a-z and
// nothing else. The standard library's EqualFold also folds Unicode (a LATIN
// SMALL LETTER LONG S would match "s"), which DNS case-insensitivity does not.
func equalFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

// dnssdNames builds the fully-qualified names for one token's browse tree.
func (p *Probe) dnssdNames(token string) (browse, enumerate, instance string) {
	base := token + "." + p.Zone
	browse = dnssdMetaService + "." + dnssdMetaDNSSD + "." + dnssdMetaUDP + "." + base
	enumerate = dnssdServiceType + "." + dnssdProto + "." + base
	instance = dnssdInstance + "." + enumerate
	return browse, enumerate, instance
}

// synthesizeDNSSD answers one level of the browse tree.
//
// Returns the answer and the additional section separately. RFC 6763 §12 says a
// server SHOULD include the records a client will need next — so a conforming
// client completes a browse in fewer round trips, and one that ignores additional
// re-queries. Both behaviours are then visible in the observation sequence, which
// is the point of including them rather than a nicety.
func (p *Probe) synthesizeDNSSD(kind dnssdKind, token string, qtype uint16) (answer, extra []dns.RR) {
	browse, enumerate, instance := p.dnssdNames(token)
	hdr := func(name string, rrtype uint16) dns.RR_Header {
		return dns.RR_Header{Name: name, Rrtype: rrtype, Class: dns.ClassINET, Ttl: p.TTL}
	}

	srv := &dns.SRV{
		Hdr: hdr(instance, dns.TypeSRV), Priority: 0, Weight: 0,
		Port: dnssdPort, Target: p.NSName,
	}
	// RFC 6763 §6.1: a TXT record with no key/value pairs is a single zero-length
	// string, NOT an empty record set — an absent TXT means "no such service",
	// which is a different answer.
	txt := &dns.TXT{Hdr: hdr(instance, dns.TypeTXT), Txt: []string{"txtvers=1", "token=" + token}}

	switch kind {
	case dnssdNone:
		// Not reachable: callers only invoke this after parseDNSSD has already
		// ruled out dnssdNone. Listed explicitly so the switch stays exhaustive.
		return nil, nil
	case dnssdBrowse:
		// §9: the meta-query is answered with PTRs naming each service type.
		if qtype != dns.TypePTR && qtype != dns.TypeANY {
			return nil, nil
		}
		return []dns.RR{&dns.PTR{Hdr: hdr(browse, dns.TypePTR), Ptr: enumerate}}, nil

	case dnssdEnumerate:
		// §4.1: PTR to each instance, with that instance's SRV and TXT in
		// additional so a conforming client needs no second round trip.
		if qtype != dns.TypePTR && qtype != dns.TypeANY {
			return nil, nil
		}
		return []dns.RR{&dns.PTR{Hdr: hdr(enumerate, dns.TypePTR), Ptr: instance}},
			[]dns.RR{srv, txt}

	case dnssdInstanceName:
		switch qtype {
		case dns.TypeSRV:
			// The SRV target's address belongs in additional for the same reason.
			return []dns.RR{srv}, nil
		case dns.TypeTXT:
			return []dns.RR{txt}, nil
		case dns.TypeANY:
			return []dns.RR{srv, txt}, nil
		}
		return nil, nil
	}
	return nil, nil
}

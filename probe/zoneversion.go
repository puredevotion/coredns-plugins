package probe

import (
	"encoding/binary"
	"math"

	"github.com/miekg/dns"
)

// RFC 9660 — the DNS Zone Version (ZONEVERSION) option.
//
// A client puts an EMPTY ZONEVERSION option in its query to signal "tell me
// which version of the zone answered this"; the authoritative server answers
// with the zone's version alongside the data. The point, per RFC 9660 §1, is
// that the version and the answer arrive atomically, so a diagnosis cannot be
// confused by the zone changing between the answer and a follow-up SOA query.
//
// Two reasons this belongs in a measurement zone specifically:
//
//  1. It is a diagnostics protocol, which is what this zone is for. Answering it
//     costs one option on the response.
//  2. Almost nothing REQUESTS it. Recording who does is itself a measurement of
//     resolver sophistication, and one nobody is publishing — the same argument
//     as the DELEG DE bit, and available at the same price.
//
// Only SOA-SERIAL (version type 0) is implemented, which is the only type RFC
// 9660 §2.2 defines.

// zoneVersionTypeSOASerial is RFC 9660's version TYPE 0. Types 1-245 are
// unassigned and 246-255 are reserved for private use; nothing here mints one,
// because a private type would be meaningless to any resolver that asked.
const zoneVersionTypeSOASerial = 0

// requestsZoneVersion reports whether the query carried a ZONEVERSION option.
//
// RFC 9660 §3.1 says the querier sends the option EMPTY. A query arriving with a
// populated one is a client that has misunderstood the protocol (or is probing
// us), and is deliberately still counted as a request: the measurement being
// made is "did you ask", and answering it costs nothing either way. What we must
// not do is echo their data back, which buildZoneVersion prevents by
// constructing the response from the zone rather than from the query.
func requestsZoneVersion(msg *dns.Msg) bool {
	opt := msg.IsEdns0()
	if opt == nil {
		return false
	}
	for _, o := range opt.Option {
		if _, ok := o.(*dns.EDNS0_ZONEVERSION); ok {
			return true
		}
	}
	return false
}

// buildZoneVersion returns the ZONEVERSION option to attach to a response for
// zone, carrying serial as an SOA-SERIAL version.
//
// LabelCount is the number of labels in the zone name, which is how a client
// works out WHICH zone the version refers to when the queried name sits below a
// delegation. Counted from the zone rather than taken from the query, so a
// client cannot influence it.
//
// Returns nil for the root zone: RFC 9660 §3.2's label count cannot express it
// meaningfully, and this plugin is never authoritative for root anyway. Returning
// nil rather than a zero-count option keeps "cannot answer" from looking like an
// answer of zero.
func buildZoneVersion(zone string, serial uint32) *dns.EDNS0_ZONEVERSION {
	z := dns.CanonicalName(zone)
	if z == "" || z == "." {
		return nil
	}
	labels := dns.CountLabel(z)
	if labels <= 0 || labels > math.MaxUint8 {
		// CountLabel cannot exceed DNS's 127-label limit in practice; the bound
		// is here because LabelCount is a single octet and a silent truncation
		// would produce a wrong answer rather than no answer.
		return nil
	}

	// Bounded immediately above against math.MaxUint8, which is the field's own
	// width — so this conversion cannot truncate. Expressed as the guard rather
	// than as a cast annotation, because a silently truncated label count would
	// point a client at the wrong zone.
	labelCount := uint8(labels)

	// SOA-SERIAL is a 4-octet unsigned integer in network byte order (RFC 9660
	// §2.2). Version is a Go string of opaque octets, not text — do NOT format
	// the serial as decimal here, which would look right in a debugger and be
	// wrong on the wire.
	var v [4]byte
	binary.BigEndian.PutUint32(v[:], serial)

	return &dns.EDNS0_ZONEVERSION{
		LabelCount: labelCount,
		Type:       zoneVersionTypeSOASerial,
		Version:    string(v[:]),
	}
}

// parseZoneVersionSerial reads an SOA-SERIAL ZONEVERSION option back out. Used
// by tests and by anything verifying what we emitted; also the function to reach
// for if this plugin ever needs to read another server's version.
//
// Reports ok=false for a version type it does not understand or a payload of the
// wrong length, rather than guessing — a misparsed serial is worse than an absent
// one, because it looks authoritative.
func parseZoneVersionSerial(o *dns.EDNS0_ZONEVERSION) (uint32, bool) {
	if o == nil || o.Type != zoneVersionTypeSOASerial || len(o.Version) != 4 {
		return 0, false
	}
	return binary.BigEndian.Uint32([]byte(o.Version)), true
}

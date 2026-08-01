package dynupdate

import (
	"strings"

	"github.com/miekg/dns"
)

type rrsetKey struct {
	name   string
	rrtype uint16
}

func keyOf(name string, rrtype uint16) rrsetKey {
	return rrsetKey{name: strings.ToLower(dns.CanonicalName(name)), rrtype: rrtype}
}

func sameName(rr dns.RR, canonical string) bool {
	return strings.ToLower(dns.CanonicalName(rr.Header().Name)) == canonical
}

// inZone reports whether name is at or below the served origin. RFC 2136 calls
// anything else NOTZONE, which is a distinct answer from NXDOMAIN: the name may
// well exist, just not here.
func (d *DynUpdate) inZone(name string) bool {
	n := strings.ToLower(dns.CanonicalName(name))
	return n == d.Zone || dns.IsSubDomain(d.Zone, n)
}

func (d *DynUpdate) nameInUse(name string) bool {
	c := strings.ToLower(dns.CanonicalName(name))
	for _, rr := range d.rrs {
		if sameName(rr, c) {
			return true
		}
	}
	return false
}

func (d *DynUpdate) rrsetExists(name string, rrtype uint16) bool {
	return len(d.rrsetOf(name, rrtype)) > 0
}

func (d *DynUpdate) rrsetOf(name string, rrtype uint16) []dns.RR {
	c := strings.ToLower(dns.CanonicalName(name))
	var out []dns.RR
	for _, rr := range d.rrs {
		if sameName(rr, c) && rr.Header().Rrtype == rrtype {
			out = append(out, rr)
		}
	}
	return out
}

// rdataKey identifies a record by everything except its TTL. Comparison goes
// through the presentation form because it is the only representation
// miekg/dns offers for every type without a per-type switch; the TTL is zeroed
// on a copy first, since RFC 2136 compares RRs by name, type, class and RDATA
// and explicitly not by TTL.
func rdataKey(rr dns.RR) string {
	c := dns.Copy(rr)
	h := c.Header()
	h.Name = strings.ToLower(dns.CanonicalName(h.Name))
	h.Ttl = 0
	// An update record arrives in class NONE or ANY to signal intent; the
	// stored record is always in the zone's class. Normalise so a delete can
	// match what an add stored.
	h.Class = dns.ClassINET
	return c.String()
}

func indexOfRR(rrs []dns.RR, want dns.RR) int {
	k := rdataKey(want)
	for i, rr := range rrs {
		if rdataKey(rr) == k {
			return i
		}
	}
	return -1
}

// sameRRset reports set equality, ignoring order and TTL — the comparison
// RFC 2136 §3.2.3 specifies for a value-dependent prerequisite.
func sameRRset(have, want []dns.RR) bool {
	if len(have) != len(want) {
		return false
	}
	counts := map[string]int{}
	for _, rr := range have {
		counts[rdataKey(rr)]++
	}
	for _, rr := range want {
		k := rdataKey(rr)
		if counts[k] == 0 {
			return false
		}
		counts[k]--
	}
	return true
}

func deleteWhere(rrs []dns.RR, changed bool, match func(dns.RR) bool) ([]dns.RR, bool) {
	out := rrs[:0:0]
	for _, rr := range rrs {
		if match(rr) {
			changed = true
			continue
		}
		out = append(out, rr)
	}
	return out, changed
}

func countRRset(rrs []dns.RR, canonical string, rrtype uint16) int {
	n := 0
	for _, rr := range rrs {
		if sameName(rr, canonical) && rr.Header().Rrtype == rrtype {
			n++
		}
	}
	return n
}

func hasCNAME(rrs []dns.RR, canonical string) bool {
	for _, rr := range rrs {
		if sameName(rr, canonical) && rr.Header().Rrtype == dns.TypeCNAME {
			return true
		}
	}
	return false
}

func hasNonCNAME(rrs []dns.RR, canonical string) bool {
	for _, rr := range rrs {
		if !sameName(rr, canonical) {
			continue
		}
		switch rr.Header().Rrtype {
		case dns.TypeCNAME, dns.TypeRRSIG, dns.TypeNSEC:
			// RRSIG and NSEC legitimately sit alongside a CNAME.
		default:
			return true
		}
	}
	return false
}

func soaOf(rrs []dns.RR) *dns.SOA {
	for _, rr := range rrs {
		if soa, ok := rr.(*dns.SOA); ok {
			return soa
		}
	}
	return nil
}

// serialGreater implements RFC 1982 serial number arithmetic. A plain `>`
// would make the zone unupdatable for ~68 years after the serial wraps.
func serialGreater(a, b uint32) bool {
	return a != b && ((a < b && b-a > 1<<31) || (a > b && a-b < 1<<31))
}

// bumpSerial advances the SOA after a successful change. RFC 2136 §3.6 leaves
// this to the server; not doing it means a secondary compares serials, sees no
// difference, and never transfers the change it was just NOTIFYed about.
func bumpSerial(rrs []dns.RR) {
	if soa := soaOf(rrs); soa != nil {
		soa.Serial++
	}
}

func isMetaType(t uint16) bool {
	switch t {
	case dns.TypeANY, dns.TypeAXFR, dns.TypeIXFR, dns.TypeMAILA, dns.TypeMAILB, dns.TypeOPT:
		return true
	}
	return false
}

// reply sends the response to an UPDATE. RFC 2136 §3.8 wants the request's
// sections echoed; miekg's SetReply copies the Zone section, which is what a
// client matches the response against.
func (d *DynUpdate) reply(w dns.ResponseWriter, r *dns.Msg, rcode int) (int, error) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.SetRcode(r, rcode)
	// SetReply resets the opcode to QUERY.
	m.Opcode = dns.OpcodeUpdate
	m.Authoritative = true

	if err := w.WriteMsg(m); err != nil {
		return dns.RcodeServerFailure, err
	}
	// The message is already written, so the chain must not write another.
	return dns.RcodeSuccess, nil
}

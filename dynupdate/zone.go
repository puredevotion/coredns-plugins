package dynupdate

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/miekg/dns"
)

type rrsetKey struct {
	name   string
	rrtype uint16
}

func keyOf(name string, rrtype uint16) rrsetKey {
	return rrsetKey{name: strings.ToLower(dns.CanonicalName(name)), rrtype: rrtype}
}

// sameName reports whether rr's owner name, canonicalised, is canonical.
//
// Compared in place rather than by canonicalising the record's name first:
// that built two strings per record, and every §3.2 prerequisite and every
// §3.4 update runs this over the whole zone. The canonical form is the fully
// qualified name folded to lower case, so the comparison is a case-folded
// equality that tolerates a missing trailing dot. Only a name made of
// non-ASCII bytes, which strings.ToLower folds differently from an ASCII
// fold, goes through the original construction.
func sameName(rr dns.RR, canonical string) bool {
	name := rr.Header().Name
	if !isASCII(name) {
		return strings.ToLower(dns.CanonicalName(name)) == canonical
	}
	if name == "" || name[len(name)-1] != '.' {
		// Fqdn appends the dot, except to a bare "." which is already one.
		return len(canonical) == len(name)+1 && canonical[len(name)] == '.' && equalFoldASCII(name, canonical[:len(name)])
	}
	return equalFoldASCII(name, canonical)
}

// isASCII reports whether s has no byte with the high bit set.
func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// equalFoldASCII compares a and b byte for byte, folding A-Z onto a-z. The
// same fold strings.ToLower applies to ASCII input, without the copy.
func equalFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
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

// indexOfRR finds want in rrs by RFC 2136's record identity: name, type and
// RDATA, not TTL or class.
//
// Type and owner are compared first and the RDATA rendering is reached only
// for records that share both. The rendering (rdataKey) copies the record
// and formats it as text, so doing that for every record in the zone made
// one add against a 10 000-record zone cost 300 000 allocations; almost all
// of them differed in type or name and never needed rendering.
func indexOfRR(rrs []dns.RR, want dns.RR) int {
	wh := want.Header()
	canonical := strings.ToLower(dns.CanonicalName(wh.Name))
	k := ""
	for i, rr := range rrs {
		if rr.Header().Rrtype != wh.Rrtype || !sameName(rr, canonical) {
			continue
		}
		if k == "" {
			k = rdataKey(want)
		}
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
	out := make([]dns.RR, 0, len(rrs))
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

// bumpSerial advances the SOA after a successful change that did not set the
// serial itself. RFC 2136 §3.6: the server "shall increment it
// automatically"; not doing it means a secondary compares serials, sees no
// difference, and never transfers the change it was just NOTIFYed about.
//
// The SOA is replaced by an incremented copy rather than incremented in
// place: rrs is a fresh slice, but its records are still d.rrs's, and an
// in-place ++ would survive a failed rebuild.
func bumpSerial(rrs []dns.RR) {
	for i, rr := range rrs {
		soa, ok := rr.(*dns.SOA)
		if !ok {
			continue
		}
		next := *soa
		next.Serial++
		if next.Serial == 0 {
			// RFC 2136 §7.11: "if the result of the increment is zero (0)
			// (as will be true when wrapping around 2**32), it is
			// necessary to increment it again or set it to one (1)".
			next.Serial = 1
		}
		rrs[i] = &next
		return
	}
}

// isUpdatableType reports whether an update record may carry type t, which
// RFC 2136 §3.4.1.2 limits to recognised data types. Zero is reserved (RFC
// 6895 §3.1), OPT is a pseudo-RR that belongs in a message's additional
// data section (RFC 6891 §6.1.1), and 128-255 are "Q and Meta-TYPEs" (RFC 6895
// §3.1): ANY, AXFR, IXFR, MAILA, MAILB, TSIG and TKEY among them.
// "Recognised" means miekg/dns knows the type; an unknown one is RFC 3597
// opaque data this plugin cannot validate.
func isUpdatableType(t uint16) bool {
	if t == 0 || t == dns.TypeOPT || (t >= 128 && t <= 255) {
		return false
	}
	_, known := dns.TypeToString[t]
	return known
}

// reply sends the response to an UPDATE. RFC 2136 §3.8 allows either
// "copying the ZOCOUNT, PRCOUNT, UPCOUNT, and ADCOUNT fields and associated
// sections, or placing zeros (0) in the these "count" fields" (sic); miekg's
// SetReply copies the Zone section only, as BIND does, which is what a client
// matches the response against.
func (d *DynUpdate) reply(w dns.ResponseWriter, r *dns.Msg, rcode int) (int, error) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.SetRcode(r, rcode)
	// SetReply resets the opcode to QUERY.
	m.Opcode = dns.OpcodeUpdate
	m.Authoritative = true

	if err := w.WriteMsg(m); err != nil {
		return dns.RcodeServerFailure, fmt.Errorf("write dns response: %w", err)
	}
	// The message is already written, so the chain must not write another.
	return dns.RcodeSuccess, nil
}

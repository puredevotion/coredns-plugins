package dynupdate

import (
	"strings"

	"github.com/miekg/dns"
)

// serveUpdate implements RFC 2136 §3. The section names below are the RFC's,
// and the order is load-bearing: every prerequisite is checked before any
// change is prescanned, and the whole update section is prescanned before any
// of it is applied. An update that fails halfway is the one outcome RFC 2136
// §3.4.2.1 forbids.
func (d *DynUpdate) serveUpdate(w dns.ResponseWriter, r *dns.Msg) (int, error) {
	// §3.1.1 — the Zone section is exactly one record, of type SOA, in the
	// zone's own class.
	if len(r.Question) != 1 || r.Question[0].Qtype != dns.TypeSOA || r.Question[0].Qclass != dns.ClassINET {
		return d.reply(w, r, dns.RcodeFormatError)
	}

	zone := strings.ToLower(dns.CanonicalName(r.Question[0].Name))
	if zone != d.Zone {
		// NOTAUTH, not REFUSED: the distinction tells an updater "you have the
		// wrong server" rather than "you have the wrong credentials", and
		// those lead to very different debugging.
		return d.reply(w, r, dns.RcodeNotAuth)
	}

	// Authentication is the tsig plugin's job — it owns the keys and the
	// verification. This checks only that it happened, because a dynamic-update
	// endpoint that answers an unsigned request is an open zone-mutation API,
	// and "the operator surely configured tsig in front" is not an access
	// control. There is deliberately no insecure mode.
	if !tsigVerified(w, r) {
		log.Warningf("refusing unsigned or unverified UPDATE for %s from %s", zone, w.RemoteAddr())
		return d.reply(w, r, dns.RcodeRefused)
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	if rcode := d.checkPrereqs(r.Answer); rcode != dns.RcodeSuccess {
		return d.reply(w, r, rcode)
	}
	if rcode := d.prescan(r.Ns); rcode != dns.RcodeSuccess {
		return d.reply(w, r, rcode)
	}

	updated, changed := d.apply(r.Ns)
	if !changed {
		// RFC 2136 §2.5.1: "Any duplicate RRs will be silently ignored",
		// and §3.4.2.5: "Signal NOERROR". An update that changes nothing is
		// still a success. Silently doing nothing and reporting NOERROR is correct,
		// and is why an ACME client re-adding an identical TXT does not fail.
		return d.reply(w, r, dns.RcodeSuccess)
	}

	// RFC 2136 §3.6: "If the zone's SOA's SERIAL is not changed as a result
	// of an update operation, then the server shall increment it
	// automatically". An UPDATE that replaced the SOA has already moved it
	// forward, by exactly as much as the client asked.
	if cur, next := soaOf(d.rrs), soaOf(updated); cur != nil && next != nil && next.Serial == cur.Serial {
		bumpSerial(updated)
	}
	if err := d.swap(updated); err != nil {
		log.Errorf("rebuilding %s after UPDATE: %v", zone, err)
		return d.reply(w, r, dns.RcodeServerFailure)
	}

	if d.Xfer != nil {
		// Without this a secondary only sees the change at its next refresh,
		// which for an ACME challenge with a 60s validation window is
		// indistinguishable from the update never having happened.
		if err := d.Xfer.Notify(zone); err != nil {
			log.Warningf("NOTIFY for %s after UPDATE: %v", zone, err)
		}
	}

	return d.reply(w, r, dns.RcodeSuccess)
}

// tsigVerified reports whether the request carried a TSIG that the server
// validated. The writer w is wrapped by CoreDNS (ScrubWriter, and the tsig
// plugin's own writer), so the status is reached through an interface
// assertion rather than off the concrete type.
func tsigVerified(w dns.ResponseWriter, r *dns.Msg) bool {
	if r.IsTsig() == nil {
		return false
	}
	s, ok := w.(interface{ TsigStatus() error })
	return ok && s.TsigStatus() == nil
}

// checkPrereqs implements §3.2. All five prerequisite forms are supported;
// anything else is a format error rather than a guess.
func (d *DynUpdate) checkPrereqs(prereqs []dns.RR) int {
	// Value-dependent prerequisites (§3.2.3) are collected and compared as
	// whole RRsets at the end, because "this RRset equals exactly these
	// records" cannot be decided one record at a time.
	valueDependent := map[rrsetKey][]dns.RR{}

	for _, rr := range prereqs {
		h := rr.Header()
		if h.Ttl != 0 {
			return dns.RcodeFormatError
		}
		if !d.inZone(h.Name) {
			return dns.RcodeNotZone
		}

		switch h.Class {
		case dns.ClassANY:
			if rcode := d.checkPrereqExists(h); rcode != rcodeNoVerdict {
				return rcode
			}

		case dns.ClassNONE:
			if rcode := d.checkPrereqAbsent(h); rcode != rcodeNoVerdict {
				return rcode
			}

		case dns.ClassINET:
			k := keyOf(h.Name, h.Rrtype)
			valueDependent[k] = append(valueDependent[k], rr)

		default:
			return dns.RcodeFormatError
		}
	}

	for k, want := range valueDependent {
		if !sameRRset(d.rrsetOf(k.name, k.rrtype), want) {
			return dns.RcodeNXRrset
		}
	}

	return dns.RcodeSuccess
}

// rcodeNoVerdict marks a prerequisite check as passed with nothing more to
// say about that record — as opposed to dns.RcodeSuccess, which is 0 and
// therefore cannot double as a sentinel.
const rcodeNoVerdict = -1

// checkPrereqExists implements §3.2.1, the ClassANY forms: "name is in use"
// (§2.4.4, TypeANY) or "RRset exists (value independent)" (§2.4.1, any other
// type).
func (d *DynUpdate) checkPrereqExists(h *dns.RR_Header) int {
	if h.Rdlength != 0 {
		return dns.RcodeFormatError
	}
	if h.Rrtype == dns.TypeANY {
		if !d.nameInUse(h.Name) {
			return dns.RcodeNameError // NXDOMAIN.
		}
		return rcodeNoVerdict
	}
	if !d.rrsetExists(h.Name, h.Rrtype) {
		return dns.RcodeNXRrset
	}
	return rcodeNoVerdict
}

// checkPrereqAbsent implements §3.2.2, the ClassNONE forms: "name is not in
// use" (§2.4.5, TypeANY) or "RRset does not exist" (§2.4.3, any other type).
func (d *DynUpdate) checkPrereqAbsent(h *dns.RR_Header) int {
	if h.Rdlength != 0 {
		return dns.RcodeFormatError
	}
	if h.Rrtype == dns.TypeANY {
		if d.nameInUse(h.Name) {
			return dns.RcodeYXDomain
		}
		return rcodeNoVerdict
	}
	if d.rrsetExists(h.Name, h.Rrtype) {
		return dns.RcodeYXRrset
	}
	return rcodeNoVerdict
}

// prescan implements §3.4.1: reject the entire update if any single record in
// it is malformed, out of zone, or against policy. Nothing has been applied at
// this point, which is the whole reason the RFC separates the two passes.
func (d *DynUpdate) prescan(updates []dns.RR) int {
	for _, rr := range updates {
		if rcode := d.prescanRecord(rr.Header()); rcode != dns.RcodeSuccess {
			return rcode
		}
	}
	return dns.RcodeSuccess
}

// prescanRecord applies §3.4.1 to a single update record.
//
//nolint:misspell // RFC 2136 §3.4.1.2 is quoted verbatim, in its US spelling.
func (d *DynUpdate) prescanRecord(h *dns.RR_Header) int {
	if !d.inZone(h.Name) {
		return dns.RcodeNotZone
	}
	// RFC 2136 §3.4.1.2: "For RRs whose CLASS is not ANY, check the TYPE
	// and if it is ANY, AXFR, MAILA, MAILB, or any other QUERY metatype, or
	// any unrecognized type, then signal FORMERR", and for CLASS ANY the
	// TYPE must not be "any other QUERY metatype besides ANY, or any
	// unrecognized type". TSIG and TKEY are meta-types too (RFC 6895 §3.1:
	// 128-255 are "Q and Meta-TYPEs"), so a TSIG record in the update
	// section is rejected here rather than added to the zone.
	deleteEverythingAtName := h.Class == dns.ClassANY && h.Rrtype == dns.TypeANY
	if !deleteEverythingAtName && !isUpdatableType(h.Rrtype) {
		return dns.RcodeFormatError
	}

	switch h.Class {
	case dns.ClassINET:
	case dns.ClassANY:
		if h.Ttl != 0 || h.Rdlength != 0 {
			return dns.RcodeFormatError
		}
	case dns.ClassNONE:
		if h.Ttl != 0 {
			return dns.RcodeFormatError
		}
	default:
		return dns.RcodeFormatError
	}

	// Type policy is checked here, in the prescan, so a disallowed type
	// rejects the whole update rather than letting part of it land. An
	// UPDATE key that only needs to publish ACME challenges should not be
	// able to repoint an A record, and TSIG cannot express that.
	//
	// "Delete all RRsets from a name" (§2.5.3) names no type, so under a
	// type allowlist it is refused outright: it would otherwise delete the
	// A, AAAA and MX records a TXT-only key must not touch. RFC 3007 §3
	// leaves this to policy, which "dictates the authorized actions that an
	// authenticated principal can take".
	if d.mutable != nil && (deleteEverythingAtName || !d.mutable[h.Rrtype]) {
		log.Warningf("UPDATE for %s rejected: type %s is not in the mutable set",
			h.Name, dns.TypeToString[h.Rrtype])
		return dns.RcodeRefused
	}

	return dns.RcodeSuccess
}

// apply implements §3.4.2 against a copy, returning the new record set and
// whether anything actually changed.
func (d *DynUpdate) apply(updates []dns.RR) ([]dns.RR, bool) {
	out := make([]dns.RR, 0, len(d.rrs))
	out = append(out, d.rrs...)
	changed := false

	for _, rr := range updates {
		if out == nil {
			// DeleteWhere never actually returns nil, but out is indexed
			// below and nilaway cannot see that across the reassignment.
			out = []dns.RR{}
		}

		h := rr.Header()
		name := strings.ToLower(dns.CanonicalName(h.Name))
		apex := name == d.Zone

		switch h.Class {
		case dns.ClassINET:
			out, changed = applyAdd(out, changed, rr, h, name, apex)
		case dns.ClassANY:
			out, changed = applyDeleteRRset(out, changed, h, name, apex)
		case dns.ClassNONE:
			out, changed = applyDeleteRecord(out, changed, rr, h, name, apex)
		}
	}

	return out, changed
}

// applyAdd implements the ClassINET (add) form of §3.4.2.2: SOA serial
// gating, CNAME exclusivity in both directions, and TTL-only update of an
// already-present record.
//
// SOA and CNAME are singletons, and §3.4.2.2 says so: an accepted SOA or
// CNAME update REPLACES the zone's, it does not join it. Appending instead
// left two SOAs (the view serves the last one inserted while bumpSerial
// advances the first, so the served serial froze and secondaries stopped
// transferring) or two CNAMEs at one name. See
// verification/lean/CorednsPlugins/DynUpdate.lean.
func applyAdd(out []dns.RR, changed bool, rr dns.RR, h *dns.RR_Header, name string, apex bool) ([]dns.RR, bool) {
	// SOA is special: an added SOA only takes effect if its serial is
	// greater than the current one, so a stale updater cannot wind the
	// zone backwards. A zone has one SOA, at its apex; one sent for any
	// other name has nothing to replace.
	if h.Rrtype == dns.TypeSOA {
		cur := soaOf(out)
		newSOA, ok := rr.(*dns.SOA)
		if !ok || !apex || cur == nil || !serialGreater(newSOA.Serial, cur.Serial) {
			return out, changed
		}
		out, _ = deleteWhere(out, changed, func(x dns.RR) bool { return x.Header().Rrtype == dns.TypeSOA })
		return append(out, dns.Copy(rr)), true
	}
	// CNAME exclusivity, both directions. Silently ignored rather than
	// rejected, per §3.4.2.2.
	if h.Rrtype == dns.TypeCNAME && hasNonCNAME(out, name) {
		return out, changed
	}
	if h.Rrtype != dns.TypeCNAME && hasCNAME(out, name) {
		return out, changed
	}

	if i := indexOfRR(out, rr); i >= 0 {
		// Identical record already present: only the TTL is updated. On a
		// copy: out shares its records with d.rrs, and a write through
		// out[i] would land in the live zone even if the rebuild below
		// then fails and the client is told SERVFAIL.
		if out[i].Header().Ttl != h.Ttl {
			out[i] = dns.Copy(out[i])
			out[i].Header().Ttl = h.Ttl
			changed = true
		}
		return out, changed
	}

	if h.Rrtype == dns.TypeCNAME {
		// "otherwise replace the CNAME Zone RR with the CNAME Update RR".
		out, _ = deleteWhere(out, changed, func(x dns.RR) bool {
			return sameName(x, name) && x.Header().Rrtype == dns.TypeCNAME
		})
	}
	return append(out, dns.Copy(rr)), true
}

// applyDeleteRRset implements the ClassANY (delete RRset, or every RRset at
// the name) form of §3.4.2.3. At the apex, SOA and NS survive a
// delete-everything: a zone without them is not a zone.
func applyDeleteRRset(out []dns.RR, changed bool, h *dns.RR_Header, name string, apex bool) ([]dns.RR, bool) {
	if h.Rrtype == dns.TypeANY {
		return deleteWhere(out, changed, func(x dns.RR) bool {
			if !sameName(x, name) {
				return false
			}
			if apex && (x.Header().Rrtype == dns.TypeSOA || x.Header().Rrtype == dns.TypeNS) {
				return false
			}
			return true
		})
	}
	if apex && (h.Rrtype == dns.TypeSOA || h.Rrtype == dns.TypeNS) {
		return out, changed
	}
	return deleteWhere(out, changed, func(x dns.RR) bool {
		return sameName(x, name) && x.Header().Rrtype == h.Rrtype
	})
}

// applyDeleteRecord implements the ClassNONE (delete one specific record)
// form of §3.4.2.4. The apex SOA is never deletable, and the last apex NS is
// kept for the same reason applyDeleteRRset keeps it.
func applyDeleteRecord(out []dns.RR, changed bool, rr dns.RR, h *dns.RR_Header, name string, apex bool) ([]dns.RR, bool) {
	if apex && h.Rrtype == dns.TypeSOA {
		return out, changed
	}
	if apex && h.Rrtype == dns.TypeNS && countRRset(out, name, dns.TypeNS) <= 1 {
		return out, changed
	}
	if i := indexOfRR(out, rr); i >= 0 {
		out = append(out[:i], out[i+1:]...)
		changed = true
	}
	return out, changed
}

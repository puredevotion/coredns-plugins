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
		// RFC 2136 §3.4.2.7: an update that changes nothing is still a
		// success. Silently doing nothing and reporting NOERROR is correct,
		// and is why an ACME client re-adding an identical TXT does not fail.
		return d.reply(w, r, dns.RcodeSuccess)
	}

	bumpSerial(updated)
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
// validated. w is wrapped by CoreDNS (ScrubWriter, and the tsig plugin's own
// writer), so the status is reached through an interface assertion rather than
// off the concrete type.
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
			if h.Rdlength != 0 {
				return dns.RcodeFormatError
			}
			if h.Rrtype == dns.TypeANY {
				if !d.nameInUse(h.Name) {
					return dns.RcodeNameError // NXDOMAIN
				}
			} else if !d.rrsetExists(h.Name, h.Rrtype) {
				return dns.RcodeNXRrset
			}

		case dns.ClassNONE:
			if h.Rdlength != 0 {
				return dns.RcodeFormatError
			}
			if h.Rrtype == dns.TypeANY {
				if d.nameInUse(h.Name) {
					return dns.RcodeYXDomain
				}
			} else if d.rrsetExists(h.Name, h.Rrtype) {
				return dns.RcodeYXRrset
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

// prescan implements §3.4.1: reject the entire update if any single record in
// it is malformed, out of zone, or against policy. Nothing has been applied at
// this point, which is the whole reason the RFC separates the two passes.
func (d *DynUpdate) prescan(updates []dns.RR) int {
	for _, rr := range updates {
		h := rr.Header()
		if !d.inZone(h.Name) {
			return dns.RcodeNotZone
		}
		// Meta-types are queries, not records; none of them can appear in an
		// update section in any class.
		if isMetaType(h.Rrtype) && !(h.Class == dns.ClassANY && h.Rrtype == dns.TypeANY) {
			return dns.RcodeFormatError
		}

		switch h.Class {
		case dns.ClassINET:
			if h.Rrtype == dns.TypeANY {
				return dns.RcodeFormatError
			}
		case dns.ClassANY:
			if h.Ttl != 0 || h.Rdlength != 0 {
				return dns.RcodeFormatError
			}
		case dns.ClassNONE:
			if h.Ttl != 0 || h.Rrtype == dns.TypeANY {
				return dns.RcodeFormatError
			}
		default:
			return dns.RcodeFormatError
		}

		// Type policy is checked here, in the prescan, so a disallowed type
		// rejects the whole update rather than letting part of it land. An
		// UPDATE key that only needs to publish ACME challenges should not be
		// able to repoint an A record, and TSIG cannot express that.
		if d.mutable != nil && h.Rrtype != dns.TypeANY && !d.mutable[h.Rrtype] {
			log.Warningf("UPDATE for %s rejected: type %s is not in the mutable set",
				h.Name, dns.TypeToString[h.Rrtype])
			return dns.RcodeRefused
		}
	}
	return dns.RcodeSuccess
}

// apply implements §3.4.2 against a copy, returning the new record set and
// whether anything actually changed.
func (d *DynUpdate) apply(updates []dns.RR) ([]dns.RR, bool) {
	out := make([]dns.RR, len(d.rrs))
	copy(out, d.rrs)
	changed := false

	for _, rr := range updates {
		h := rr.Header()
		name := strings.ToLower(dns.CanonicalName(h.Name))
		apex := name == d.Zone

		switch h.Class {
		case dns.ClassINET:
			// §3.4.2.3. SOA is special: an added SOA only takes effect if its
			// serial is greater than the current one, so a stale updater
			// cannot wind the zone backwards.
			if h.Rrtype == dns.TypeSOA {
				cur := soaOf(out)
				new, ok := rr.(*dns.SOA)
				if !ok || cur == nil || !serialGreater(new.Serial, cur.Serial) {
					continue
				}
			}
			// CNAME exclusivity, both directions. Silently ignored rather than
			// rejected, per §3.4.2.3.
			if h.Rrtype == dns.TypeCNAME && hasNonCNAME(out, name) {
				continue
			}
			if h.Rrtype != dns.TypeCNAME && h.Rrtype != dns.TypeSOA && hasCNAME(out, name) {
				continue
			}

			if i := indexOfRR(out, rr); i >= 0 {
				// Identical record already present: only the TTL is updated.
				if out[i].Header().Ttl != h.Ttl {
					out[i].Header().Ttl = h.Ttl
					changed = true
				}
				continue
			}
			out = append(out, dns.Copy(rr))
			changed = true

		case dns.ClassANY:
			if h.Rrtype == dns.TypeANY {
				// Delete every RRset at the name. At the apex, SOA and NS
				// survive: a zone without them is not a zone, and §3.4.2.3
				// says to leave them rather than to fail.
				out, changed = deleteWhere(out, changed, func(x dns.RR) bool {
					if !sameName(x, name) {
						return false
					}
					if apex && (x.Header().Rrtype == dns.TypeSOA || x.Header().Rrtype == dns.TypeNS) {
						return false
					}
					return true
				})
				continue
			}
			if apex && (h.Rrtype == dns.TypeSOA || h.Rrtype == dns.TypeNS) {
				continue
			}
			out, changed = deleteWhere(out, changed, func(x dns.RR) bool {
				return sameName(x, name) && x.Header().Rrtype == h.Rrtype
			})

		case dns.ClassNONE:
			// §3.4.2.4 — delete one specific record. The apex SOA is never
			// deletable, and the last apex NS is kept for the same reason as
			// above.
			if apex && h.Rrtype == dns.TypeSOA {
				continue
			}
			if apex && h.Rrtype == dns.TypeNS && countRRset(out, name, dns.TypeNS) <= 1 {
				continue
			}
			if i := indexOfRR(out, rr); i >= 0 {
				out = append(out[:i], out[i+1:]...)
				changed = true
			}
		}
	}

	return out, changed
}

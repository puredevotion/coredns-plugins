// Package zoneversion is a CoreDNS plugin implementing the responder side of
// RFC 9660, the DNS Zone Version (ZONEVERSION) EDNS(0) option, with the
// SOA-SERIAL version type. See docs/zoneversion-plugin.md.
package zoneversion

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/miekg/dns"
)

const pluginName = "zoneversion"

// ZoneVersion answers RFC 9660 ZONEVERSION requests for the zones it is
// configured with, on responses produced by the plugins after it.
type ZoneVersion struct {
	Next  plugin.Handler
	now   func() time.Time
	cache *serialCache
	zones []string // Canonical (lower case, fully qualified), never ".".
}

func newZoneVersion(zones []string) *ZoneVersion {
	return &ZoneVersion{zones: zones, cache: newSerialCache(), now: time.Now}
}

// Name implements plugin.Handler.
func (*ZoneVersion) Name() string { return pluginName }

// ServeDNS implements plugin.Handler.
//
// A query without a ZONEVERSION option goes straight to the next plugin,
// untouched and without allocating: the plugin never adds the option to a
// response nobody asked it for (RFC 9660 §3.2.2).
func (z *ZoneVersion) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	a := classify(r.IsEdns0())
	if a == askNone || r.Opcode != dns.OpcodeQuery || len(r.Question) != 1 {
		return plugin.NextOrFailure(pluginName, z.Next, ctx, w, r) //nolint:wrapcheck // chain errors pass through
	}
	qname := r.Question[0].Name
	apex := z.match(qname)
	if apex == "" {
		// Not one of our zones: not ours to answer for, either way.
		return plugin.NextOrFailure(pluginName, z.Next, ctx, w, r) //nolint:wrapcheck // chain errors pass through
	}
	if a == askMalformed {
		count(resultFormErr)
		return dns.RcodeSuccess, w.WriteMsg(formErr(r)) //nolint:wrapcheck // response already written; the error is the writer's
	}
	switch r.Question[0].Qtype {
	case dns.TypeAXFR, dns.TypeIXFR:
		// A transfer is a stream of messages, not one response; RFC 9660
		// says nothing about it and transfer sits before this plugin anyway.
		return plugin.NextOrFailure(pluginName, z.Next, ctx, w, r) //nolint:wrapcheck // chain errors pass through
	}
	return z.serveVersioned(ctx, w, r, apex)
}

// serveVersioned runs the rest of the chain into a capture, decides whether
// and which version to attach, then writes the response.
//
// The serial: a negative answer (NXDOMAIN, NODATA) carries the zone's SOA, so
// the serial is read from the response itself, from the same snapshot as the
// answer. A positive answer or a referral carries no SOA, so the serial is
// looked up again after the answer and bracketed: the option is attached
// only if a serial observed BEFORE the answer (from the cache, else a lookup)
// equals the one observed AFTER it. See docs/zoneversion-plugin.md, "What the
// plugin guarantees", and verification/tla/ZoneVersionSerial.tla.
func (z *ZoneVersion) serveVersioned(ctx context.Context, w dns.ResponseWriter, r *dns.Msg, apex string) (int, error) {
	before, haveBefore := z.cache.get(apex, z.now())
	if !haveBefore {
		before, haveBefore = z.lookup(ctx, w, apex)
	}

	cw := &captureWriter{ResponseWriter: w}
	rcode, err := plugin.NextOrFailure(pluginName, z.Next, ctx, cw, r)
	if len(cw.msgs) == 0 {
		// Nothing written: the server writes the error response for rcode,
		// which carries no ZONEVERSION.
		return rcode, err //nolint:wrapcheck // chain errors pass through
	}
	if len(cw.msgs) == 1 {
		res := cw.msgs[0]
		stripOption(res)
		if v, res2 := z.decide(ctx, w, r, res, apex, before, haveBefore); res2 == resultAdded {
			attach(res, r, v)
			count(resultAdded)
		} else {
			count(res2)
		}
	}
	for _, m := range cw.msgs {
		if werr := w.WriteMsg(m); werr != nil {
			return rcode, werr //nolint:wrapcheck // the underlying writer's error
		}
	}
	return rcode, err //nolint:wrapcheck // chain errors pass through
}

// decide returns the version to attach and resultAdded, or why not.
func (z *ZoneVersion) decide(ctx context.Context, w dns.ResponseWriter, r, res *dns.Msg, apex string, before uint32, haveBefore bool) (Version, result) {
	qname := r.Question[0].Name
	if !eligible(res, qname, apex) {
		return Version{}, resultIneligible
	}
	serial, ok := soaSerial(res, apex)
	if ok {
		z.observe(apex, serial)
	} else {
		var after uint32
		after, ok = z.lookup(ctx, w, apex)
		switch {
		case !ok:
			return Version{}, resultLookupFailed
		case !haveBefore || before != after:
			return Version{}, resultSerialChanged
		}
		serial = after
	}
	v, err := NewVersion(apex, qname, serial)
	if err != nil {
		return Version{}, resultIneligible
	}
	return v, resultAdded
}

// lookup asks the rest of the chain for apex's SOA, as a fresh query with no
// EDNS options (RFC 9660 §3.2.2: the option is not copied onward), and
// returns its serial if the answer is authoritative and is exactly one SOA
// owned by apex. Every successful lookup is also an observation for the
// cache.
func (z *ZoneVersion) lookup(ctx context.Context, w dns.ResponseWriter, apex string) (uint32, bool) {
	q := new(dns.Msg)
	q.SetQuestion(apex, dns.TypeSOA)
	cw := &captureWriter{ResponseWriter: w}
	if _, err := plugin.NextOrFailure(pluginName, z.Next, ctx, cw, q); err != nil || len(cw.msgs) != 1 {
		return 0, false
	}
	res := cw.msgs[0]
	if res.Rcode != dns.RcodeSuccess || !res.Authoritative {
		return 0, false
	}
	serial, ok := soaIn(res.Answer, apex)
	if !ok {
		return 0, false
	}
	z.observe(apex, serial)
	return serial, true
}

func (z *ZoneVersion) observe(apex string, serial uint32) {
	if z.cache.observe(apex, serial, z.now()) == outcomeRegressed {
		regressions.Inc()
	}
}

// match returns the longest configured zone enclosing qname, the same choice
// file, auto and secondary make (plugin.Zones.Matches), or "".
func (z *ZoneVersion) match(qname string) string {
	best := ""
	for _, zone := range z.zones {
		if len(zone) > len(best) && dns.IsSubDomain(zone, qname) {
			best = zone
		}
	}
	return best
}

// eligible reports whether res is a response RFC 9660 §3.2 lets this server
// version for apex: it is authoritative for apex (the operator asserts that
// by listing the zone) and the response is one it produced as such.
//
//   - AA set and NOERROR (an answer or NODATA), NXDOMAIN, or YXDOMAIN (a
//     DNAME substitution that overflowed, RFC 6672 §2.2): yes.
//   - AA clear: only a downward referral out of apex, "even though the
//     response's Authoritative Answer bit is not set" (§3.2); the version is
//     then the referring zone's, which apex is.
//   - Anything else, notably SERVFAIL and REFUSED, and every response from a
//     plugin that is not authoritative (forward, a recursive answer): no.
func eligible(res *dns.Msg, qname, apex string) bool {
	if res.Opcode != dns.OpcodeQuery {
		return false
	}
	if res.Authoritative {
		switch res.Rcode {
		case dns.RcodeSuccess, dns.RcodeNameError, dns.RcodeYXDomain:
			return true
		}
		return false
	}
	return isReferral(res, qname, apex)
}

// isReferral is RFC 9499's downward referral, out of apex: NOERROR, no
// answer, no SOA, and an NS RRset in the authority section owned by a name
// strictly below apex that encloses qname.
func isReferral(res *dns.Msg, qname, apex string) bool {
	if res.Rcode != dns.RcodeSuccess || len(res.Answer) != 0 {
		return false
	}
	cut := false
	for _, rr := range res.Ns {
		h := rr.Header()
		switch h.Rrtype {
		case dns.TypeSOA:
			return false
		case dns.TypeNS:
			if !strings.EqualFold(h.Name, apex) && dns.IsSubDomain(apex, h.Name) && dns.IsSubDomain(h.Name, qname) {
				cut = true
			}
		}
	}
	return cut
}

// soaSerial returns the serial of apex's SOA if the response itself carries
// it: in the answer (an SOA query at the apex) or the authority section (a
// negative answer from apex). An SOA owned by any other name, e.g. the target
// zone at the end of a CNAME chain, says nothing about apex.
func soaSerial(res *dns.Msg, apex string) (uint32, bool) {
	if !res.Authoritative {
		return 0, false
	}
	if s, ok := soaIn(res.Answer, apex); ok {
		return s, true
	}
	return soaIn(res.Ns, apex)
}

// soaIn returns the serial of the SOA owned by apex in rrs, if there is
// exactly one serial for it. Two SOAs for apex with different serials is a
// response nobody can attribute to one version.
func soaIn(rrs []dns.RR, apex string) (uint32, bool) {
	var serial uint32
	found := false
	for _, rr := range rrs {
		soa, ok := rr.(*dns.SOA)
		if !ok || !strings.EqualFold(soa.Hdr.Name, apex) {
			continue
		}
		if found && soa.Serial != serial {
			return 0, false
		}
		serial, found = soa.Serial, true
	}
	return serial, found
}

// stripOption removes every ZONEVERSION option from res, so that the one
// attach adds is the only one (RFC 9660 §3.2: "MUST NOT include more than one
// ZONEVERSION option for a given TYPE and LABELCOUNT"), and so that nothing
// another plugin echoed survives when this plugin withholds the option.
func stripOption(res *dns.Msg) {
	opt := res.IsEdns0()
	if opt == nil {
		return
	}
	if slices.ContainsFunc(opt.Option, isZoneVersion) {
		replaceOPT(res, opt, nil)
	}
}

// attach puts v on res as its single ZONEVERSION option.
func attach(res, req *dns.Msg, v Version) {
	opt := res.IsEdns0()
	if opt == nil {
		ro := req.IsEdns0() // Non-nil: classify found the option in it.
		size, do := uint16(dns.MinMsgSize), false
		if ro != nil {
			size, do = ro.UDPSize(), ro.Do()
		}
		res.SetEdns0(size, do)
		opt = res.IsEdns0()
	}
	replaceOPT(res, opt, v.EDNS0())
}

// replaceOPT swaps res's OPT for a copy without ZONEVERSION options, plus
// extra if non-nil. A copy, because CoreDNS's request.SizeAndDo reuses the
// request's own OPT RR in the response: editing it in place would edit the
// request.
func replaceOPT(res *dns.Msg, opt *dns.OPT, extra dns.EDNS0) {
	n := &dns.OPT{Hdr: opt.Hdr, Option: make([]dns.EDNS0, 0, len(opt.Option)+1)}
	for _, o := range opt.Option {
		if !isZoneVersion(o) {
			n.Option = append(n.Option, o)
		}
	}
	if extra != nil {
		n.Option = append(n.Option, extra)
	}
	for i, rr := range res.Extra {
		if rr == dns.RR(opt) {
			res.Extra[i] = n
		}
	}
}

// formErr is the RFC 9660 §3.2.1 response. It keeps an OPT RR, without
// options, since the query had one (RFC 6891 §7).
func formErr(r *dns.Msg) *dns.Msg {
	m := new(dns.Msg)
	m.SetRcode(r, dns.RcodeFormatError)
	if ro := r.IsEdns0(); ro != nil {
		m.SetEdns0(ro.UDPSize(), ro.Do())
	}
	return m
}

// captureWriter keeps what the rest of the chain writes instead of sending
// it, so the response can be versioned (or not) before it leaves, and so the
// internal SOA lookup never reaches the client.
type captureWriter struct {
	dns.ResponseWriter
	msgs []*dns.Msg
}

// WriteMsg implements dns.ResponseWriter.
func (c *captureWriter) WriteMsg(m *dns.Msg) error {
	c.msgs = append(c.msgs, m)
	return nil
}

// Write implements dns.ResponseWriter. A plugin that writes raw bytes is
// unpacked into a message so it stays in order with the others; bytes that
// do not unpack are refused rather than sent unversioned out of order.
func (c *captureWriter) Write(b []byte) (int, error) {
	m := new(dns.Msg)
	if err := m.Unpack(b); err != nil {
		return 0, err //nolint:wrapcheck // the caller's own bytes
	}
	c.msgs = append(c.msgs, m)
	return len(b), nil
}

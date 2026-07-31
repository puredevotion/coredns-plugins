// Package probe serves a synthetic, per-visitor DNS measurement zone.
//
// Every name in the zone is generated on demand from a random token supplied by
// the querier, which is what makes the measurement possible: a unique name
// defeats every cache between a visitor and this server, so the visitor's
// resolver is forced to query us directly and we get to observe it. What we can
// see — egress address, transport, DNSSEC posture, EDNS buffer, cookie and ECS
// support, 0x20 case randomization — is recorded against the token so a web
// tier can report "your resolver did X".
//
// The zone can also be asked to answer WRONG in specific, named ways
// (unsigned, bad signature, expired signature, truncated, NXDOMAIN, SERVFAIL,
// oversized), which is how a page can establish whether a resolver genuinely
// validates DNSSEC rather than merely claiming to.
//
// Deliberately independent of any existing implementation of this idea: the
// label grammar here (underscore-prefixed modifier labels, RFC 8552 style) was
// designed for this plugin rather than adapted from another codebase, so this
// package carries no licence obligations beyond the repository's own MIT.
//
// Safety: this zone answers the public internet, synthesizes signed responses,
// and has a modifier whose whole purpose is to emit a large answer. It must sit
// behind response rate limiting (see docs/rrl-plugin.md) and must never share a
// server block with a forwarder or a cache.
package probe

import (
	"context"
	"net"
	"net/netip"
	"strings"

	"github.com/coredns/coredns/plugin"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
)

var log = clog.NewWithPlugin("probe")

// Probe is the plugin handler.
type Probe struct {
	// Zone is the origin this plugin is authoritative for, normalised and
	// fully qualified.
	Zone string
	// TTL applies to every synthesized record. Small by default: these answers
	// describe one moment for one visitor and must not linger in caches, or a
	// second visit reports the first visit's findings.
	TTL uint32
	// NSName is the nameserver name published at the apex.
	NSName string
	// Mbox is the SOA responsible-person mailbox.
	Mbox string
	// Signer is optional. Without it the zone is unsigned and the
	// signature-related modifiers become no-ops, which is worth saying out
	// loud because it silently guts most of the point of the zone.
	Signer *Signer
	// Store records observations. Never nil after setup.
	Store Store
	// BigSize is the payload size the `_big` modifier aims for, in bytes.
	BigSize int

	Next plugin.Handler
}

// Name implements plugin.Handler.
func (p *Probe) Name() string { return "probe" }

// ServeDNS implements plugin.Handler.
func (p *Probe) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}

	qname := state.Name() // normalised, lowercase
	if !plugin.Name(p.Zone).Matches(qname) {
		return plugin.NextOrFailure(p.Name(), p.Next, ctx, w, r)
	}

	// The raw question name, before CoreDNS normalises case, is itself a
	// measurement — a resolver doing 0x20 randomization is only visible here.
	raw := qname
	if len(r.Question) > 0 {
		raw = r.Question[0].Name
	}

	// RFC 9824 §3.4: NXNAME is a meta-type that exists only inside an NSEC type
	// bitmap. A query asking for it directly is malformed, and the RFC requires
	// FORMERR — not NODATA, which would imply the type is a real thing this zone
	// simply has none of.
	if state.QType() == dns.TypeNXNAME {
		return p.respond(state, w, r, dns.RcodeFormatError, nil, nil, false)
	}

	sub := strings.TrimSuffix(qname, p.Zone)
	sub = strings.TrimSuffix(sub, ".")

	if sub == "" {
		return p.serveApex(state, w, r)
	}

	q, ok := ParseQuery(sub)
	if !ok {
		// REFUSED, not NXDOMAIN: the name is malformed for this zone's grammar
		// rather than absent from it, and a probe zone that quietly
		// reinterprets a malformed request produces measurements nobody can
		// trust.
		return p.respond(state, w, r, dns.RcodeRefused, nil, nil, false)
	}

	obs := Observe(q, raw, addrOf(state), transportOf(state), state.QType(), r)

	// Before Record, and unconditionally: the aggregate must not depend on
	// whether the per-token store accepted the observation. A store at its
	// ceiling is exactly when the population question ("who is hammering us,
	// and with what") matters most, and metrics carry no per-visitor data, so
	// there is no reason for them to share the store's fate.
	recordMetrics(obs)

	stored, err := p.Store.Record(obs)
	if err != nil {
		// Answer anyway. A full or unreachable store degrades the measurement;
		// failing the query instead would turn a memory ceiling into an outage
		// and, worse, make the zone's failure indistinguishable from the
		// deliberate failures it exists to serve.
		log.Warningf("recording observation for token %s: %v", q.Token, err)
	}
	obs = stored

	switch {
	case q.Mods.Has(ModServfail):
		return p.respond(state, w, r, dns.RcodeServerFailure, nil, nil, false)

	case q.Mods.Has(ModNXDOMAIN):
		// The legacy shape: a literal NXDOMAIN with only a signed SOA behind it.
		// Deliberately unprovable (see nodataDenial) — that is the experiment.
		auth := p.nodataDenial(qname, q.Mods, state.Do())
		return p.respond(state, w, r, dns.RcodeNameError, nil, auth, false)

	case q.Mods.Has(ModNXNAME):
		// Compact denial of existence (RFC 9824): NOERROR, empty answer, and an
		// NSEC carrying the NXNAME meta-type. The provable counterpart to
		// ModNXDOMAIN above.
		auth := p.compactDenial(qname, q.Mods, state.Do())
		return p.respond(state, w, r, dns.RcodeSuccess, nil, auth, false)

	case q.Mods.Has(ModTruncate):
		// TC=1 with an empty answer section. A conforming client retries over
		// TCP; this is also precisely the shape rate limiting uses when it
		// "slips" a response, so it doubles as a way to see how clients cope.
		return p.respond(state, w, r, dns.RcodeSuccess, nil, nil, true)
	}

	answer := p.synthesize(qname, state.QType(), obs, q.Mods)
	if len(answer) == 0 {
		// NODATA: the name exists, this type does not.
		auth := p.nodataDenial(qname, q.Mods, state.Do())
		return p.respond(state, w, r, dns.RcodeSuccess, nil, auth, false)
	}

	if state.Do() {
		if sig := p.sign(answer, q.Mods); sig != nil {
			answer = append(answer, sig)
		}
	}
	return p.respond(state, w, r, dns.RcodeSuccess, answer, nil, false)
}

// synthesize builds the answer records for one query.
//
// A and AAAA return the RESOLVER's own address, not the visitor's. That is the
// in-band version of the whole measurement: `dig <token>.<zone> A` tells you
// which address your resolver egresses from, with no web page involved.
func (p *Probe) synthesize(qname string, qtype uint16, obs Observation, mods Modifier) []dns.RR {
	hdr := dns.RR_Header{Name: qname, Class: dns.ClassINET, Ttl: p.TTL}

	switch qtype {
	case dns.TypeA:
		if !obs.ResolverAddr.Is4() {
			return nil // NODATA: resolver reached us over IPv6
		}
		h := hdr
		h.Rrtype = dns.TypeA
		return []dns.RR{&dns.A{Hdr: h, A: net.IP(obs.ResolverAddr.AsSlice())}}

	case dns.TypeAAAA:
		if !obs.ResolverAddr.Is6() {
			return nil // NODATA: resolver reached us over IPv4
		}
		h := hdr
		h.Rrtype = dns.TypeAAAA
		return []dns.RR{&dns.AAAA{Hdr: h, AAAA: net.IP(obs.ResolverAddr.AsSlice())}}

	case dns.TypeTXT:
		h := hdr
		h.Rrtype = dns.TypeTXT
		payload := obs.Summary()
		if mods.Has(ModBig) {
			payload = pad(payload, p.BigSize)
		}
		return []dns.RR{&dns.TXT{Hdr: h, Txt: chunk(payload)}}
	}
	return nil
}

// serveApex answers the zone's own records. Kept separate from the probe path
// because the apex is not a measurement — it is the delegation and trust anchor
// that makes every measurement below it meaningful.
func (p *Probe) serveApex(state request.Request, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	var answer []dns.RR
	switch state.QType() {
	case dns.TypeSOA:
		answer = []dns.RR{p.soa()}
	case dns.TypeNS:
		answer = []dns.RR{&dns.NS{
			Hdr: dns.RR_Header{Name: p.Zone, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: p.TTL},
			Ns:  p.NSName,
		}}
	case dns.TypeDNSKEY:
		if p.Signer == nil {
			break
		}
		answer = []dns.RR{p.Signer.DNSKEY()}
	}

	if len(answer) == 0 {
		return p.respond(state, w, r, dns.RcodeSuccess, nil,
			p.nodataDenial(p.Zone, 0, state.Do()), false)
	}
	if state.Do() {
		// Apex records are never spoiled: a broken DNSKEY or SOA signature
		// would make the whole zone bogus and every per-query variant below it
		// unmeasurable. Modifiers apply to probe names only.
		if sig := p.sign(answer, 0); sig != nil {
			answer = append(answer, sig)
		}
	}
	return p.respond(state, w, r, dns.RcodeSuccess, answer, nil, false)
}

func (p *Probe) soa() *dns.SOA {
	return &dns.SOA{
		Hdr:     dns.RR_Header{Name: p.Zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: p.TTL},
		Ns:      p.NSName,
		Mbox:    p.Mbox,
		Serial:  1, // Nothing transfers this zone; it is synthesized per query.
		Refresh: 3600,
		Retry:   900,
		Expire:  604800,
		Minttl:  p.TTL,
	}
}

// nodataDenial builds the authority section for NODATA: the name exists, the
// queried type does not.
//
// The NSEC asserts the queried name itself with a bitmap of just RRSIG and
// NSEC. Per RFC 9824 the NXNAME bit is specifically NOT set here — that bit
// means "this name does not exist", and setting it for a name that does exist
// would be a lie a resolver could act on.
//
// The next-domain name is the "black lies" trick: one byte greater than this
// name, so the NSEC covers nothing but itself and no real name becomes
// enumerable. For a zone of unbounded synthesized names that is a requirement
// rather than a bonus — the alternative is an enumerable chain that cannot
// exist.
//
// Note what this does NOT do: prove non-existence. A literal NXDOMAIN needs an
// NSEC chain, which this zone cannot have, which is exactly why compactDenial
// below exists and why ModNXDOMAIN is documented as the deliberately
// unprovable variant.
func (p *Probe) nodataDenial(name string, mods Modifier, do bool) []dns.RR {
	return p.denial(name, mods, do, []uint16{dns.TypeRRSIG, dns.TypeNSEC})
}

// compactDenial builds the authority section for compact denial of existence
// (RFC 9824): the name does not exist at all.
//
// Identical in shape to nodataDenial except that the type bitmap also carries
// NXNAME (type 128, a meta-type that never appears as an actual record). That
// single bit is the whole mechanism: a resolver that understands it synthesizes
// NXDOMAIN for its own client, while one that does not sees a perfectly valid
// NODATA. Both outcomes are correct and provable, which is what the legacy
// NXDOMAIN form cannot manage from a synthesized zone.
//
// RFC 9824 §3.1: the bitmap MUST carry only RRSIG, NSEC and NXNAME.
func (p *Probe) compactDenial(name string, mods Modifier, do bool) []dns.RR {
	return p.denial(name, mods, do, []uint16{dns.TypeRRSIG, dns.TypeNSEC, dns.TypeNXNAME})
}

// denial is the shared body of the two above.
func (p *Probe) denial(name string, mods Modifier, do bool, bitmap []uint16) []dns.RR {
	auth := []dns.RR{p.soa()}
	if !do {
		// Without DO there is nothing to prove to anyone, and shipping an NSEC
		// to a client that did not ask for DNSSEC is wasted bytes on a zone
		// where response size is the amplification budget.
		return auth
	}

	nsec := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: name, Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: p.TTL},
		NextDomain: "\\000." + name,
		TypeBitMap: bitmap,
	}
	auth = append(auth, nsec)

	if sig := p.sign([]dns.RR{nsec}, mods); sig != nil {
		auth = append(auth, sig)
	}
	if sig := p.sign([]dns.RR{auth[0]}, mods); sig != nil {
		auth = append(auth, sig)
	}
	return auth
}

// sign is a nil-safe wrapper: an unsigned zone is a valid configuration.
func (p *Probe) sign(rrs []dns.RR, mods Modifier) dns.RR {
	if p.Signer == nil {
		return nil
	}
	sig, err := p.Signer.signRRset(rrs, mods)
	if err != nil {
		// Log rather than fail: an unsigned answer is a worse measurement, but
		// a SERVFAIL here would be indistinguishable from the deliberate
		// SERVFAIL variant.
		log.Errorf("signing failed: %v", err)
		return nil
	}
	if sig == nil {
		return nil
	}
	return sig
}

// respond assembles and writes the reply.
func (p *Probe) respond(state request.Request, w dns.ResponseWriter, r *dns.Msg,
	rcode int, answer, auth []dns.RR, truncate bool,
) (int, error) {
	// Read the ZONEVERSION request BEFORE SizeAndDo, which is not optional
	// ordering: SizeAndDo reuses the REQUEST's OPT record as the response's and
	// runs CoreDNS's supportedOptions filter over it IN PLACE. That filter keeps
	// only NSID/EXPIRE/COOKIE/TCPKEEPALIVE/PADDING plus anything registered via
	// edns.SetSupportedOption, so it deletes the client's ZONEVERSION option
	// from r on the way past. Checking afterwards silently never fires — which
	// is exactly what happened, and only an end-to-end test through ServeDNS
	// caught it.
	//
	// Registering ZONEVERSION as a "supported" option would be the wrong fix: it
	// would make CoreDNS echo the client's own option back, so we would either
	// return their payload as our zone version or emit two ZONEVERSION options.
	wantZoneVersion := requestsZoneVersion(r)

	m := new(dns.Msg)
	m.SetRcode(r, rcode)
	m.Authoritative = true
	m.Answer = answer
	m.Ns = auth
	m.Truncated = truncate

	// Scrub to the client's advertised buffer unless we are deliberately
	// truncating. Without this the `_big` variant would be dropped by the
	// stack rather than delivered and observed.
	state.SizeAndDo(m)

	// RFC 9660: answer ZONEVERSION only when asked. Attached after SizeAndDo,
	// which is what puts an OPT record on the response, and before Scrub, so the
	// option is inside the size the client advertised rather than pushing the
	// message past it.
	if wantZoneVersion {
		if zv := buildZoneVersion(p.Zone, p.soa().Serial); zv != nil {
			if opt := m.IsEdns0(); opt != nil {
				opt.Option = append(opt.Option, zv)
			}
		}
	}

	if !truncate {
		m = state.Scrub(m)
	}

	if err := w.WriteMsg(m); err != nil {
		return dns.RcodeServerFailure, err
	}
	return dns.RcodeSuccess, nil
}

// addrOf extracts the source address as a netip.Addr.
func addrOf(state request.Request) netip.Addr {
	if addr, err := netip.ParseAddr(state.IP()); err == nil {
		return addr.Unmap()
	}
	return netip.Addr{}
}

// transportOf maps the connection to a Transport.
//
// Limitation worth naming: CoreDNS reports the transport as udp or tcp, so DoT
// and DoH — which are TCP underneath — are not distinguished here. Recording
// them separately needs the listener to pass that down, which is a change
// outside this plugin.
func transportOf(state request.Request) Transport {
	switch state.Proto() {
	case "tcp":
		return TransportTCP
	default:
		return TransportUDP
	}
}

// chunk splits a payload into the 255-byte strings a TXT record is made of.
func chunk(s string) []string {
	const max = 255
	if len(s) <= max {
		return []string{s}
	}
	var out []string
	for len(s) > max {
		out = append(out, s[:max])
		s = s[max:]
	}
	if len(s) > 0 {
		out = append(out, s)
	}
	return out
}

// pad grows a payload towards size with filler, so the `_big` modifier produces
// a large answer whose useful prefix is still readable.
func pad(s string, size int) string {
	if size <= len(s) {
		return s
	}
	var b strings.Builder
	b.Grow(size)
	b.WriteString(s)
	b.WriteString(" pad=")
	for b.Len() < size {
		b.WriteByte('x')
	}
	return b.String()
}

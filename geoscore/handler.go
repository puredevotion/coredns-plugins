package geoscore

import (
	"context"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/pkg/nonwriter"
	"github.com/miekg/dns"
)

const pluginName = "geoscore"

// GeoScore is the plugin.Handler: every `geoscore` block of one server block.
type GeoScore struct {
	Next      plugin.Handler
	instances []*Instance
}

// Name implements plugin.Handler.
func (*GeoScore) Name() string { return pluginName }

// ServeDNS implements plugin.Handler. It answers A and AAAA at a configured
// name (for a family some endpoint has), and TXT at its `_geoscore.` sibling
// when rationale-txt is on. Everything else goes to the next plugin.
func (h *GeoScore) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	if r.Opcode != dns.OpcodeQuery || len(r.Question) != 1 || r.Question[0].Qclass != dns.ClassINET {
		return plugin.NextOrFailure(pluginName, h.Next, ctx, w, r) //nolint:wrapcheck // the next plugin's own result
	}
	q := r.Question[0]
	for _, g := range h.instances {
		if equalFoldASCII(q.Name, g.cfg.Name) {
			if fam, ok := familyOf(q.Qtype); ok && len(g.byFam[fam]) > 0 {
				return g.serveAddr(ctx, w, r, fam, h.Next)
			}
			break
		}
		if g.txtName != "" && q.Qtype == dns.TypeTXT && equalFoldASCII(q.Name, g.txtName) {
			return g.serveTXT(ctx, w, r)
		}
	}
	return plugin.NextOrFailure(pluginName, h.Next, ctx, w, r) //nolint:wrapcheck // the next plugin's own result
}

// equalFoldASCII compares DNS names folding ASCII case only (RFC 4343 §3); no
// non-ASCII byte folds onto an ASCII one.
func equalFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range len(a) {
		x, y := a[i], b[i]
		if x >= 'A' && x <= 'Z' {
			x += 'a' - 'A'
		}
		if y >= 'A' && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
}

func (g *Instance) serveAddr(ctx context.Context, w dns.ResponseWriter, r *dns.Msg, fam family, next plugin.Handler) (int, error) {
	now := g.now()
	d := g.decide(fam, g.current(ctx, now), now.Unix())
	answers.WithLabelValues(g.cfg.Name, fam.String(), d.outcome.String()).Inc()

	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	switch d.outcome {
	case outServfail:
		return dns.RcodeServerFailure, nil
	case outNodata:
		soa := soaFromNext(ctx, w, next, g.cfg.Zone)
		if soa == nil {
			// RFC 2308 §3: an authoritative NODATA MUST carry the zone's SOA.
			// Without one, SERVFAIL is the honest answer.
			log.Warningf("%s: fallback nodata, but no SOA for %s from the next plugin; answering SERVFAIL", g.cfg.Name, g.cfg.Zone)
			return dns.RcodeServerFailure, nil
		}
		m.Ns = []dns.RR{soa}
	case outBest, outWeighted, outStatic:
		m.Answer = g.answer(d.endpoint, fam, r.Question[0].Name)
	}
	if err := w.WriteMsg(m); err != nil {
		return dns.RcodeServerFailure, err //nolint:wrapcheck // the writer's own error, as other plugins return it
	}
	return dns.RcodeSuccess, nil
}

// answer is the RRset of the endpoint's addresses in the family: one TTL for
// every RR (RFC 2181 §5.2), the owner name spelled as the query spelled it.
func (g *Instance) answer(ep int, fam family, qname string) []dns.RR {
	if fam == famAAAA {
		t := g.rr6[ep]
		out := make([]dns.RR, len(t))
		for i := range t {
			rr := t[i]
			rr.Hdr.Name = qname
			out[i] = &rr
		}
		return out
	}
	t := g.rr4[ep]
	out := make([]dns.RR, len(t))
	for i := range t {
		rr := t[i]
		rr.Hdr.Name = qname
		out[i] = &rr
	}
	return out
}

// soaFromNext asks the next plugin for the zone's SOA, for the NODATA
// fallback's authority section. Its TTL becomes min(SOA TTL, MINIMUM), the
// negative-caching TTL of RFC 2308 §3 and §5.
func soaFromNext(ctx context.Context, w dns.ResponseWriter, next plugin.Handler, zone string) *dns.SOA {
	if next == nil {
		return nil
	}
	req := new(dns.Msg)
	req.SetQuestion(zone, dns.TypeSOA)
	nw := nonwriter.New(w)
	if _, err := next.ServeDNS(ctx, nw, req); err != nil || nw.Msg == nil {
		return nil
	}
	for _, rr := range nw.Msg.Answer {
		if soa, ok := rr.(*dns.SOA); ok && equalFoldASCII(soa.Hdr.Name, zone) {
			c := *soa
			c.Hdr.Ttl = min(c.Hdr.Ttl, c.Minttl)
			return &c
		}
	}
	return nil
}

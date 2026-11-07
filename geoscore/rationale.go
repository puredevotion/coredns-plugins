package geoscore

import (
	"context"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

// maxCharString is the longest <character-string> a TXT record can carry
// (RFC 1035 §3.3: a length octet then up to 255 octets).
const maxCharString = 255

// serveTXT answers the rationale TXT at _geoscore.NAME (R23): why the
// address answer is what it is right now. One string for the configuration,
// one per family, one per endpoint:
//
//	"geoscore name=www.example.com. mode=best fallback=static max-staleness=300s ttl=30"
//	"A outcome=best choice=eu1 eligible=2/3 total-weight=17000"
//	"eu1 state=eligible score=0.8500 weight=8500 healthy=true age=12s signal=carbon note=212 gCO2/kWh"
//
// It is computed from the same snapshot and clock as an address answer, so
// in best mode `choice` is what an A or AAAA query gets now. In weighted mode
// it is one draw; the weights give the distribution.
func (g *Instance) serveTXT(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	m.Answer = []dns.RR{&dns.TXT{
		Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: g.cfg.TTL},
		Txt: g.rationale(ctx),
	}}
	if err := w.WriteMsg(m); err != nil {
		return dns.RcodeServerFailure, err //nolint:wrapcheck // the writer's own error, as other plugins return it
	}
	return dns.RcodeSuccess, nil
}

// rationale builds the TXT strings. Every string is at most 255 octets of
// printable ASCII by construction (ids, signals and notes are validated), and
// clipping guarantees it regardless. The miekg/dns package escapes '"' and
// '\' itself.
func (g *Instance) rationale(ctx context.Context) []string {
	now := g.now()
	s := g.current(ctx, now)
	unix := now.Unix()

	out := []string{clip("geoscore name=" + g.cfg.Name +
		" mode=" + g.cfg.Mode.String() +
		" fallback=" + g.cfg.Fallback.String() +
		" max-staleness=" + strconv.FormatInt(g.maxStale, 10) + "s" +
		" ttl=" + strconv.FormatUint(uint64(g.cfg.TTL), 10))}

	for fam := range numFamilies {
		if len(g.byFam[fam]) == 0 {
			continue
		}
		var buf [maxEndpoints]cand
		cs := g.candidates(&buf, fam, s, unix)
		n := 0
		for _, c := range cs {
			if c.eligible {
				n++
			}
		}
		d := g.decide(fam, s, unix)
		line := fam.String() + " outcome=" + strings.ReplaceAll(d.outcome.String(), "_", "-")
		if d.endpoint >= 0 {
			line += " choice=" + g.cfg.Endpoints[d.endpoint].ID
		}
		line += " eligible=" + strconv.Itoa(n) + "/" + strconv.Itoa(len(cs)) +
			" total-weight=" + strconv.FormatUint(totalWeight(cs), 10)
		out = append(out, clip(line))
	}

	for i, ep := range g.cfg.Endpoints {
		out = append(out, clip(endpointLine(ep.ID, &s.slots[i], unix, g.maxStale)))
	}
	return out
}

func endpointLine(id string, sl *slot, now, maxStale int64) string {
	st := classify(sl, now, maxStale)
	line := id + " state=" + st.String()
	if st == stateMissing || st == stateInvalid {
		return line
	}
	e := &sl.entry
	line += " score=" + strconv.FormatFloat(e.Score, 'f', 4, 64) +
		" weight=" + strconv.FormatUint(uint64(e.Weight()), 10) +
		" healthy=" + strconv.FormatBool(e.Healthy) +
		" age=" + strconv.FormatInt(now-e.Updated, 10) + "s"
	if e.Signal != "" {
		line += " signal=" + e.Signal
	}
	if e.Note != "" {
		line += " note=" + e.Note
	}
	return line
}

func clip(s string) string {
	if len(s) > maxCharString {
		return s[:maxCharString]
	}
	return s
}

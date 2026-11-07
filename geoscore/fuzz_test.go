package geoscore

import (
	"net/netip"
	"testing"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"
	"github.com/miekg/dns"
)

// FuzzParseEntry: the validator is the only way store bytes become an Entry
// (R14). Whatever it accepts is valid, has a weight in [0, 10000], and
// survives Marshal then ParseEntry unchanged.
func FuzzParseEntry(f *testing.F) {
	for _, s := range []string{
		`{"score":0.83,"healthy":true,"updated":1762500000,"signal":"carbon","note":"212 gCO2/kWh"}`,
		`{"score":0,"healthy":false,"updated":1}`,
		`{"score":1e400,"healthy":true,"updated":1}`,
		`{"score":-0,"healthy":true,"updated":1,"note":"A"}`,
		`{"SCORE":0.5,"Healthy":true,"UPDATED":7}`,
	} {
		f.Add([]byte(s))
	}
	for _, s := range stringSeeds(f) {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		e, err := ParseEntry(b)
		if err != nil {
			return
		}
		if verr := e.Validate(); verr != nil {
			t.Fatalf("accepted an invalid entry %+v: %v", e, verr)
		}
		if w := e.Weight(); w > weightScale {
			t.Fatalf("weight %d", w)
		}
		out, err := e.Marshal()
		if err != nil {
			t.Fatalf("Marshal(%+v): %v", e, err)
		}
		if again, err := ParseEntry(out); err != nil || again != e {
			t.Fatalf("round trip %+v -> %s -> %+v, %v", e, out, again, err)
		}
	})
}

// FuzzDecide: for any snapshot, clock, draw, mode and fallback, the answer is
// an eligible member of the family's candidate set, or exactly the
// documented fallback when none is eligible (Lean decide_mem,
// decide_eligible_or_fallback).
func FuzzDecide(f *testing.F) {
	f.Add([]byte{0xff, 200, 0, 0xff, 100, 1, 0x0f, 0, 2}, int64(0), uint64(0), uint8(0), uint8(0))
	f.Add([]byte{0x07, 255, 9, 0x07, 255, 9, 0x07, 255, 9}, int64(301), uint64(7), uint8(1), uint8(2))
	f.Fuzz(func(t *testing.T, raw []byte, offset int64, draw uint64, mode, fb uint8) {
		cfg := testConfig(t)
		cfg.Mode, cfg.Fallback = Mode(mode%2), Fallback(fb%3)
		fx := newFixture(t, cfg)
		fx.draw = draw
		s := &snapshot{slots: make([]slot, len(cfg.Endpoints))}
		for i := range s.slots {
			var b [3]byte
			copy(b[:], raw[min(len(raw), 3*i):])
			s.slots[i] = slot{
				found: b[0]&1 != 0, ok: b[0]&2 != 0,
				entry: Entry{Healthy: b[0]&4 != 0, Score: float64(b[1]) / 255, Updated: t0.Unix() - int64(b[2])*30},
			}
		}
		now := t0.Unix() + offset%100000
		for fam := range numFamilies {
			checkDecision(t, fx.g, fam, s, now)
		}
	})
}

// FuzzParseCorefile: any block body either fails to parse or validate, or
// yields a Config that New accepts. Never connects anywhere (no build).
func FuzzParseCorefile(f *testing.F) {
	f.Add("endpoint eu1 192.0.2.1\nstore memory\nttl 5\nmax-staleness 5s")
	f.Add("endpoint a 2001:db8::1 192.0.2.1\nmode weighted\nfallback nodata\nrationale-txt")
	f.Add("endpoint eu1 ::ffff:192.0.2.1\nkey x y\nrefresh 0s")
	for _, s := range stringSeeds(f) {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, body string) {
		c := caddy.NewTestController("dns", "geoscore www {\n"+body+"\n}")
		if !c.Next() {
			return
		}
		b := block{cfg: DefaultConfig(testName, testZone)}
		if b.parseBody(c) != nil || b.cfg.Validate() != nil {
			return
		}
		if _, err := New(b.cfg, NewMemStore()); err != nil {
			t.Fatalf("Validate accepted, New refused: %v", err)
		}
	})
}

// FuzzServeDNS: any question either passes to the next plugin or is answered
// with addresses of configured endpoints only.
func FuzzServeDNS(f *testing.F) {
	f.Add(testName, dns.TypeA, uint64(0))
	f.Add("WWW.EXAMPLE.COM.", dns.TypeAAAA, uint64(3))
	f.Add("_geoscore.www.example.com.", dns.TypeTXT, uint64(1))
	for _, s := range stringSeeds(f) {
		f.Add(s, dns.TypeA, uint64(0))
	}
	f.Fuzz(func(t *testing.T, name string, qtype uint16, draw uint64) {
		cfg := testConfig(t)
		cfg.Mode, cfg.RationaleTXT = ModeWeighted, true
		fx := newFixture(t, cfg)
		fx.draw = draw
		fx.put(t, eu1, 0.4, true, 0)
		fx.put(t, ap1, 0.6, true, 0)
		known := map[netip.Addr]bool{}
		for _, ep := range cfg.Endpoints {
			for _, a := range ep.Addrs {
				known[a] = true
			}
		}
		req := new(dns.Msg)
		req.SetQuestion(name, qtype)
		rec := dnstest.NewRecorder(&test.ResponseWriter{})
		h := handlerFor(fx, &zoneNext{})
		if _, err := h.ServeDNS(t.Context(), rec, req); err != nil || rec.Msg == nil {
			return
		}
		for _, rr := range rec.Msg.Answer {
			var ip netip.Addr
			switch v := rr.(type) {
			case *dns.A:
				ip, _ = netip.AddrFromSlice(v.A)
			case *dns.AAAA:
				ip, _ = netip.AddrFromSlice(v.AAAA)
			default:
				continue
			}
			if !known[ip.Unmap()] && !known[ip] {
				t.Fatalf("answered %v, not a configured address", ip)
			}
		}
	})
}

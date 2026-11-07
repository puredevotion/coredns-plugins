package geoscore

import (
	"testing"

	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"
	"github.com/miekg/dns"
)

func BenchmarkDecide(b *testing.B) {
	for _, mode := range []Mode{ModeBest, ModeWeighted} {
		b.Run(mode.String(), func(b *testing.B) {
			cfg := testConfig(b)
			cfg.Endpoints = manyEndpoints(b, maxEndpoints)
			cfg.Mode = mode
			f := newFixture(b, cfg)
			for i, ep := range cfg.Endpoints {
				f.put(b, ep.ID, float64(i%7)/7, i%5 != 0, int64(i))
			}
			now := f.clk.now()
			s := f.g.current(b.Context(), now)
			b.ReportAllocs()
			for i := 0; b.Loop(); i++ {
				f.draw = uint64(i)
				_ = f.g.decide(famA, s, now.Unix())
			}
		})
	}
}

func BenchmarkServeDNS(b *testing.B) {
	for name, qtype := range map[string]uint16{"A": dns.TypeA, "AAAA": dns.TypeAAAA, "pass": dns.TypeMX} {
		b.Run(name, func(b *testing.B) {
			f := newFixture(b, testConfig(b))
			f.put(b, eu1, 0.9, true, 0)
			h := handlerFor(f, &zoneNext{})
			req := new(dns.Msg)
			req.SetQuestion(testName, qtype)
			b.ReportAllocs()
			for b.Loop() {
				if _, err := h.ServeDNS(b.Context(), dnstest.NewRecorder(&test.ResponseWriter{}), req); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkParseEntry(b *testing.B) {
	in := []byte(`{"score":0.83,"healthy":true,"updated":1762500000,"signal":"carbon","note":"212 gCO2/kWh"}`)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := ParseEntry(in); err != nil {
			b.Fatal(err)
		}
	}
}

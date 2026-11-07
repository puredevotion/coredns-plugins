//go:build !race

package geoscore

import (
	"testing"

	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"
	"github.com/miekg/dns"
)

// Allocation budgets for the per-query path. The race detector adds
// allocations, hence the build tag. The decision runs on every A/AAAA query
// at a configured name and allocates nothing; a rise means a value started
// escaping to the heap.
func TestDecideAllocs(t *testing.T) {
	for _, mode := range []Mode{ModeBest, ModeWeighted} {
		cfg := testConfig(t)
		cfg.Mode = mode
		f := newFixture(t, cfg)
		f.put(t, eu1, 0.4, true, 0)
		f.put(t, ap1, 0.6, true, 0)
		now := f.clk.now()
		s := f.g.current(t.Context(), now)
		if got := testing.AllocsPerRun(200, func() { _ = f.g.decide(famA, s, now.Unix()) }); got != 0 {
			t.Errorf("%v: decide = %v allocs, budget 0", mode, got)
		}
		if got := testing.AllocsPerRun(200, func() { _ = f.g.current(t.Context(), now) }); got != 0 {
			t.Errorf("%v: current (no refresh due) = %v allocs, budget 0", mode, got)
		}
	}
}

// The whole ServeDNS for an A answer of two RRs: the reply message, its
// question copy, the answer slice and one RR each, plus the recorder.
func TestServeDNSAllocs(t *testing.T) {
	f := newFixture(t, testConfig(t))
	f.put(t, us1, 1, true, 0) // Two A records.
	h := handlerFor(f, &zoneNext{})
	req := new(dns.Msg)
	req.SetQuestion(testName, dns.TypeA)
	f.g.current(t.Context(), f.clk.now())
	const budget = 7
	got := testing.AllocsPerRun(200, func() {
		rec := dnstest.NewRecorder(&test.ResponseWriter{})
		if _, err := h.ServeDNS(t.Context(), rec, req); err != nil {
			t.Fatal(err)
		}
	})
	if got > budget {
		t.Errorf("ServeDNS = %v allocs, budget %d", got, budget)
	}
}

//go:build !race

package resinfo

import (
	"context"
	"testing"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/test"
	"github.com/miekg/dns"
)

// Allocation budgets for the per-query path. The race detector adds
// allocations, hence the build tag. Every query through this server block
// pays for the pass-through decision, so it must not allocate; answering
// pays for the reply message only.
func TestServeDNSAllocs(t *testing.T) {
	h := newTestHandler(t, resolverName, ddrName)
	h.Next = plugin.HandlerFunc(func(context.Context, dns.ResponseWriter, *dns.Msg) (int, error) {
		return dns.RcodeSuccess, nil
	})
	w := &test.ResponseWriter{}
	ctx := context.Background()

	pass := query("www.example.org.", dns.TypeA)
	if got := testing.AllocsPerRun(200, func() { _ = h.answers(pass) }); got != 0 {
		t.Errorf("answers (pass-through) = %v allocs, budget 0", got)
	}
	// The one allocation is CoreDNS's plugin.NextOrFailure (its tracing
	// hook), not this plugin's: answers above is allocation-free.
	const passBudget = 1
	if got := testing.AllocsPerRun(200, func() { mustServe(t, h, ctx, w, pass) }); got > passBudget {
		t.Errorf("ServeDNS (pass-through) = %v allocs, budget %d", got, passBudget)
	}

	hit := query("ReSoLvEr.ExAmPlE.NeT.", dns.TypeRESINFO)
	if got := testing.AllocsPerRun(200, func() { _ = h.answers(hit) }); got != 0 {
		t.Errorf("answers (hit) = %v allocs, budget 0", got)
	}
	// The reply Msg, the Question copy SetReply makes, the Answer slice and
	// the RESINFO record (4); Scrub's Truncate measuring the reply (2); and
	// the test ResponseWriter's RemoteAddr, which Scrub asks for the
	// transport (2). Measured 8 on go1.27.3, miekg/dns v1.1.73.
	const answerBudget = 8
	if got := testing.AllocsPerRun(200, func() { mustServe(t, h, ctx, w, hit) }); got > answerBudget {
		t.Errorf("ServeDNS (answer) = %v allocs, budget %d", got, answerBudget)
	}
}

func mustServe(t *testing.T, h *ResInfo, ctx context.Context, w dns.ResponseWriter, req *dns.Msg) {
	t.Helper()
	if _, err := h.ServeDNS(ctx, w, req); err != nil {
		t.Fatal(err)
	}
}

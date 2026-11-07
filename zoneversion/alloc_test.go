//go:build !race

package zoneversion

import (
	"context"
	"testing"

	"github.com/miekg/dns"
)

// Allocation budgets. The race detector adds allocations, hence the build
// tag. Every query to the zone goes through the no-option path, so the
// plugin's own share of it must be nothing; a rise here means it started
// taxing queries that never asked for a version. The one allocation the
// ServeDNS budgets allow is CoreDNS's, not ours: v1.15.0's
// plugin.NextOrFailure wraps the writer in a pluginWriter for every plugin.
func TestAllocs(t *testing.T) {
	z := newZoneVersion([]string{testApex})
	z.Next = nopHandler{}
	w := &recorder{}
	ctx := context.Background()
	plain := query(wwwName, dns.TypeA, &dns.EDNS0_NSID{Code: dns.EDNS0NSID})
	noEDNS := new(dns.Msg)
	noEDNS.SetQuestion(wwwName, dns.TypeA)
	v, err := NewVersion(testApex, wwwName, testSerial)
	if err != nil {
		t.Fatal(err)
	}
	enc := v.Encode()

	var failed error
	keep := func(err error) {
		if err != nil {
			failed = err
		}
	}
	for name, tc := range map[string]struct {
		fn   func()
		want float64
	}{
		"ServeDNS, no option": {func() { _, err := z.ServeDNS(ctx, w, plain); keep(err) }, 1},
		"ServeDNS, no EDNS":   {func() { _, err := z.ServeDNS(ctx, w, noEDNS); keep(err) }, 1},
		"classify":            {func() { _ = classify(plain.IsEdns0()) }, 0},
		"Encode":              {func() { _ = v.Encode() }, 0},
		"Decode":              {func() { _, err := Decode(enc[:]); keep(err) }, 0},
		"update":              {func() { _, _ = update(entry{serial: 1}, true, 2, testEpoch) }, 0},
	} {
		if got := testing.AllocsPerRun(100, tc.fn); got > tc.want {
			t.Errorf("%s: %v allocs, budget %v", name, got, tc.want)
		}
	}
	if failed != nil {
		t.Fatal(failed)
	}
}

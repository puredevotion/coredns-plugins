//go:build !race

package probe

import "testing"

// Allocation budgets for the per-query parse path. The race detector adds
// allocations, hence the build tag. A rise here means a value started escaping
// to the heap on a path every untrusted query goes through.
func TestParseQueryAllocs(t *testing.T) {
	for name, tc := range map[string]struct {
		sub  string
		want float64
	}{
		"baseline":   {testToken2, 0},
		"modifiers":  {"_badsig." + testToken2, 0},
		"mixed-case": {"_BadSig.DeadBeef", 1}, // DNS 0x20 case randomisation: one lowercase copy.
		"rejected":   {"nonsense", 0},
	} {
		if got := testing.AllocsPerRun(100, func() { _, _ = ParseQuery(tc.sub) }); got > tc.want {
			t.Errorf("%s: ParseQuery(%q) = %v allocs, budget %v", name, tc.sub, got, tc.want)
		}
	}
}

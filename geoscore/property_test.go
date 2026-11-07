package geoscore

import (
	"math/rand"
	"slices"
	"testing"
)

// Standard-library property tests with fixed seeds. Each checks a theorem of
// verification/lean/CorednsPlugins/GeoScore.lean against the Go code, over
// random inputs, so the model and the code are compared, not just the model.
const (
	propIterations = 4000
	propSeed       = 1794 // RFC 1794, DNS support for load balancing.
)

// randCands draws up to maxEndpoints candidates with frequent ties, zero
// weights and ineligible entries.
func randCands(r *rand.Rand, maxW int) []cand {
	cs := make([]cand, r.Intn(maxEndpoints+1))
	for i := range cs {
		cs[i] = cand{weight: randWeight(r, maxW), eligible: r.Intn(4) != 0}
		if cs[i].weight == 0 {
			cs[i].eligible = false // A zero weight is never eligible (classify).
		}
	}
	return cs
}

// refBest is the specification of best mode written as plainly as possible:
// the maximal eligible weight, then the first index carrying it.
func refBest(cs []cand) int {
	var maxW uint32
	found := false
	for _, c := range cs {
		if c.eligible && (!found || c.weight > maxW) {
			maxW, found = c.weight, true
		}
	}
	for i, c := range cs {
		if found && c.eligible && c.weight == maxW {
			return i
		}
	}
	return -1
}

// Lean best_spec, best_unique, best_none_iff: pickBest is the reference.
func TestProperty_BestMatchesSpec(t *testing.T) {
	r := rand.New(rand.NewSource(propSeed)) //nolint:gosec // G404: deterministic test generator.
	for range propIterations {
		cs := randCands(r, 3) // Small weights: many ties.
		got, want := pickBest(cs), refBest(cs)
		if got != want {
			t.Fatalf("pickBest(%v) = %d, spec says %d", cs, got, want)
		}
		if got >= 0 && !cs[got].eligible {
			t.Fatalf("pickBest(%v) chose ineligible %d", cs, got)
		}
		// Determinism in (weights, order): changing an ineligible candidate's
		// weight never changes the result.
		for i := range cs {
			if !cs[i].eligible {
				cs[i].weight = randWeight(r, weightScale)
			}
		}
		if again := pickBest(cs); again != got {
			t.Fatalf("pickBest depends on an ineligible weight: %d then %d", got, again)
		}
	}
}

// Lean pick_sound, pick_some, pick_count: over every draw r < total, each
// candidate is chosen exactly ew times, and nothing ineligible ever is.
func TestProperty_WeightedExactDistribution(t *testing.T) {
	r := rand.New(rand.NewSource(propSeed + 1)) //nolint:gosec // G404: deterministic test generator.
	for range propIterations {
		cs := randCands(r, 6)
		total := totalWeight(cs)
		counts := make([]uint64, len(cs))
		for x := range total {
			i := pickWeighted(cs, x)
			if i < 0 || !cs[i].eligible || cs[i].weight == 0 {
				t.Fatalf("pickWeighted(%v, %d) = %d: outside the support", cs, x, i)
			}
			counts[i]++
		}
		for i, c := range cs {
			if counts[i] != c.ew() {
				t.Fatalf("%v: candidate %d chosen %d times of %d, want %d", cs, i, counts[i], total, c.ew())
			}
		}
		if pickWeighted(cs, total) != -1 {
			t.Fatalf("pickWeighted(%v, total) selected", cs)
		}
	}
}

// Lean pick_monotone: raising one candidate's weight never lowers its share.
func TestProperty_WeightedMonotone(t *testing.T) {
	r := rand.New(rand.NewSource(propSeed + 2)) //nolint:gosec // G404: deterministic test generator.
	for range propIterations {
		cs := randCands(r, 10000)
		if len(cs) == 0 {
			continue
		}
		i := r.Intn(len(cs))
		before, totalBefore := cs[i].ew(), totalWeight(cs)
		raised := append([]cand(nil), cs...)
		raised[i].weight += randWeight(r, weightScale)
		if cs[i].weight == 0 && raised[i].weight > 0 {
			// A drained endpoint whose score rises becomes eligible, unless
			// it is unhealthy or stale too.
			raised[i].eligible = r.Intn(2) == 0
		}
		after, totalAfter := raised[i].ew(), totalWeight(raised)
		if before*totalAfter > after*totalBefore {
			t.Fatalf("raising %d in %v lowered its share: %d/%d then %d/%d", i, cs, before, totalBefore, after, totalAfter)
		}
	}
}

// Lean decide_mem, decide_eligible_or_fallback, select_none_iff, against the
// real Instance.decide over random snapshots and clocks.
func TestProperty_DecideMembershipAndFallback(t *testing.T) {
	r := rand.New(rand.NewSource(propSeed + 3)) //nolint:gosec // G404: deterministic test generator.
	for it := range propIterations {
		cfg := testConfig(t)
		cfg.Mode, cfg.Fallback = Mode(it%2), Fallback(it%3)
		f := newFixture(t, cfg)
		f.draw = r.Uint64()
		s := randSnapshot(r, len(cfg.Endpoints))
		now := t0.Unix() + int64(r.Intn(600)) - 300
		for fam := range numFamilies {
			checkDecision(t, f.g, fam, s, now)
		}
	}
}

func randSnapshot(r *rand.Rand, n int) *snapshot {
	s := &snapshot{slots: make([]slot, n)}
	for i := range s.slots {
		s.slots[i] = slot{
			found: r.Intn(6) != 0,
			ok:    r.Intn(6) != 0,
			entry: Entry{
				Score:   float64(r.Intn(4)) / 3,
				Healthy: r.Intn(4) != 0,
				Updated: t0.Unix() + int64(r.Intn(1000)) - 600,
			},
		}
	}
	return s
}

func checkDecision(t *testing.T, g *Instance, fam family, s *snapshot, now int64) {
	t.Helper()
	d := g.decide(fam, s, now)
	idx := g.byFam[fam]
	anyEligible := false
	for _, ep := range idx {
		if classify(&s.slots[ep], now, g.maxStale) == stateEligible {
			anyEligible = true
		}
	}
	switch d.outcome {
	case outBest, outWeighted:
		if !contains(idx, d.endpoint) || classify(&s.slots[d.endpoint], now, g.maxStale) != stateEligible {
			t.Fatalf("%v answered %d: not an eligible member of %v", fam, d.endpoint, idx)
		}
	case outStatic:
		if anyEligible || g.cfg.Fallback != FallbackStatic || d.endpoint != idx[0] {
			t.Fatalf("%v static fallback to %d with eligible=%v", fam, d.endpoint, anyEligible)
		}
	case outServfail, outNodata:
		if anyEligible || d.endpoint != -1 {
			t.Fatalf("%v fallback %v with eligible=%v", fam, d.outcome, anyEligible)
		}
	}
}

func contains(xs []int, x int) bool { return slices.Contains(xs, x) }

// randWeight draws a weight in [0, maxW].
func randWeight(r *rand.Rand, maxW int) uint32 {
	return uint32(r.Int31n(int32(maxW) + 1)) //nolint:gosec // G115: maxW <= weightScale, the draw is non-negative
}

// ParseEntry(Marshal(e)) == e for every valid entry: what a Go writer stores
// is what the plugin reads.
func TestProperty_EntryRoundTrip(t *testing.T) {
	r := rand.New(rand.NewSource(propSeed + 4)) //nolint:gosec // G404: deterministic test generator.
	for range propIterations {
		e := Entry{Score: r.Float64(), Healthy: r.Intn(2) == 0, Updated: 1 + r.Int63n(maxUpdated), Signal: "latency"}
		if r.Intn(3) == 0 {
			e.Note = "p50 12ms \"quoted\" \\ slash"
		}
		b, err := e.Marshal()
		if err != nil {
			t.Fatalf("Marshal(%+v): %v", e, err)
		}
		got, err := ParseEntry(b)
		if err != nil || got != e {
			t.Fatalf("round trip of %+v: %+v, %v", e, got, err)
		}
	}
}

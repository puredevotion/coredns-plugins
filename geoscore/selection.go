package geoscore

// Selection: the pure part, verified in verification/lean/CorednsPlugins/
// GeoScore.lean. Each function here mirrors the Lean definition named in its
// comment; keep them in step.

// futureSkew is how far ahead of the plugin's clock a writer's timestamp may
// be and still count as fresh (writer and plugin clocks differ a little). An
// entry dated further ahead is ineligible: a writer with a wrong clock must
// not be able to make a score look fresh for longer than max-staleness.
const futureSkew = 30

// state is why an endpoint is or is not eligible, for the rationale TXT and
// metrics. Only stateEligible is ever selected (R15).
type state uint8

const (
	stateMissing   state = iota // No entry in the store.
	stateInvalid                // The entry failed ParseEntry.
	stateStale                  // Updated more than max-staleness ago.
	stateFuture                 // Updated more than futureSkew ahead.
	stateUnhealthy              // Written with healthy=false.
	stateZero                   // Weight 0.
	stateEligible
)

var stateNames = [...]string{"missing", "invalid", "stale", "future", "unhealthy", "zero", "eligible"}

func (s state) String() string { return stateNames[s] }

// slot is one endpoint's entry in a snapshot.
type slot struct {
	entry Entry
	ok    bool // The key existed and the entry passed ParseEntry.
	found bool // The key existed.
}

// classify is Lean `eligible`, with the reason it fails. The clock and the
// entry's `updated` are Unix seconds; maxStale is seconds.
func classify(s *slot, now, maxStale int64) state {
	switch {
	case !s.found:
		return stateMissing
	case !s.ok:
		return stateInvalid
	case s.entry.Updated > now+futureSkew:
		return stateFuture
	case now-s.entry.Updated > maxStale:
		return stateStale
	case !s.entry.Healthy:
		return stateUnhealthy
	case s.entry.Weight() == 0:
		return stateZero
	}
	return stateEligible
}

// cand is a candidate as selection sees it: Lean `ew` is weight when
// eligible, else 0.
type cand struct {
	weight   uint32
	eligible bool
}

func (c cand) ew() uint64 {
	if c.eligible {
		return uint64(c.weight)
	}
	return 0
}

// pickBest is Lean `best`: the eligible candidate with the highest weight,
// the first one on a tie (a later one replaces it only when strictly
// heavier). It returns -1 when none is eligible.
func pickBest(cs []cand) int {
	best := -1
	for i, c := range cs {
		if !c.eligible {
			continue
		}
		if best < 0 || cs[best].weight < c.weight {
			best = i
		}
	}
	return best
}

// totalWeight is Lean `total`.
func totalWeight(cs []cand) uint64 {
	var t uint64
	for _, c := range cs {
		t += c.ew()
	}
	return t
}

// pickWeighted is Lean `pick`: the candidate whose cumulative-weight interval
// holds r. With r < totalWeight(cs) it always selects; it returns -1
// otherwise.
func pickWeighted(cs []cand, r uint64) int {
	for i, c := range cs {
		w := c.ew()
		if r < w {
			return i
		}
		r -= w
	}
	return -1
}

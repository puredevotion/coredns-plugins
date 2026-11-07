package zoneversion

import (
	"testing"
	"time"
)

func TestSerialGreater(t *testing.T) {
	for _, tc := range []struct {
		a, b uint32
		want bool
	}{
		{2, 1, true},
		{1, 2, false},
		{1, 1, false},
		{0, 0xffffffff, true}, // Across the wrap.
		{0xffffffff, 0, false},
		{1 << 31, 0, false}, // The antipodes: undefined, so neither.
		{0, 1 << 31, false},
		{(1 << 31) - 1, 0, true},
		{0, (1 << 31) + 1, true},
	} {
		if got := serialGreater(tc.a, tc.b); got != tc.want {
			t.Errorf("serialGreater(%d, %d) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestCacheObserve(t *testing.T) {
	c := newSerialCache()
	steps := []struct {
		at     time.Duration
		serial uint32
		want   outcome
		cached uint32
	}{
		{0, 10, outcomeNew, 10},
		{time.Second, 10, outcomeSame, 10},
		{2 * time.Second, 11, outcomeAdvanced, 11},
		{3 * time.Second, 9, outcomeRegressed, 11},             // Rollback: kept.
		{2*time.Second + maxEntryAge, 9, outcomeRegressed, 11}, // A regression does not refresh.
		{2*time.Second + maxEntryAge + 1, 9, outcomeNew, 9},    // Stale now: replaced.
	}
	for i, s := range steps {
		if got := c.observe(testApex, s.serial, testEpoch.Add(s.at)); got != s.want {
			t.Fatalf("step %d: outcome %d, want %d", i, got, s.want)
		}
		if got, ok := c.get(testApex, testEpoch.Add(s.at)); !ok || got != s.cached {
			t.Fatalf("step %d: cached %d (%v), want %d", i, got, ok, s.cached)
		}
	}
}

func TestCacheFreshness(t *testing.T) {
	c := newSerialCache()
	c.observe(testApex, 5, testEpoch)
	for _, tc := range []struct {
		at   time.Time
		want bool
	}{
		{testEpoch, true},
		{testEpoch.Add(maxEntryAge), true},
		{testEpoch.Add(maxEntryAge + 1), false},
		{testEpoch.Add(-time.Nanosecond), false}, // Clock went backwards.
	} {
		if _, ok := c.get(testApex, tc.at); ok != tc.want {
			t.Errorf("get at %v: fresh %v, want %v", tc.at.Sub(testEpoch), ok, tc.want)
		}
	}
	if _, ok := c.get("example.net.", testEpoch); ok {
		t.Error("a zone never observed is cached")
	}
}

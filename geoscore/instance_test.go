package geoscore

import (
	"errors"
	"testing"
	"time"
)

func TestBestPicksHighestThenFirstListed(t *testing.T) {
	f := newFixture(t, testConfig(t))
	f.put(t, eu1, 0.5, true, 0)
	f.put(t, us1, 0.9, true, 0)
	f.put(t, ap1, 0.9, true, 0)
	if id, out := f.pick(t, famA); id != us1 || out != outBest {
		t.Fatalf("A: %s %v, want us1 (tie with ap1, listed first)", id, out)
	}
	// The us1 endpoint has no IPv6, so for AAAA the tie is gone.
	if id, _ := f.pick(t, famAAAA); id != ap1 {
		t.Fatalf("AAAA: %s, want ap1", id)
	}
}

func TestIneligibleNeverChosen(t *testing.T) {
	f := newFixture(t, testConfig(t))
	f.put(t, eu1, 0.1, true, 0)
	f.put(t, us1, 1, false, 0)                    // Unhealthy.
	f.put(t, ap1, 1, true, defaultStalenessSec+1) // Stale.
	f.store.Set(f.g.cfg.KeyPrefix+":us1", []byte(`{"score":2}`))
	for _, mode := range []Mode{ModeBest, ModeWeighted} {
		f.g.cfg.Mode = mode
		for draw := range uint64(50) {
			f.draw = draw
			if id, _ := f.pick(t, famA); id != eu1 {
				t.Fatalf("%v draw %d: chose %s", mode, draw, id)
			}
		}
	}
}

const defaultStalenessSec = int64(defaultStaleness / time.Second)

func TestFutureDatedEntry(t *testing.T) {
	f := newFixture(t, testConfig(t))
	f.put(t, eu1, 1, true, -futureSkew) // At the skew limit: fresh.
	if id, _ := f.pick(t, famA); id != eu1 {
		t.Fatalf("entry %ds ahead rejected", futureSkew)
	}
	f.put(t, eu1, 1, true, -futureSkew-1)
	f.refetch()
	if _, out := f.pick(t, famA); out != outStatic {
		t.Fatalf("entry beyond the skew used: %v", out)
	}
}

// GeoScoreStaleness NeverServeStale, JudgeByFetch counterexample: the store
// stays up but the writer dies. Re-reading the same old entries must not
// make them fresh.
func TestWriterDeathEndsInFallback(t *testing.T) {
	cfg := testConfig(t)
	cfg.Fallback = FallbackServfail
	f := newFixture(t, cfg)
	f.put(t, eu1, 1, true, 0)
	maxStale := cfg.MaxStaleness
	for elapsed := time.Duration(0); elapsed <= maxStale+5*time.Second; elapsed += cfg.Refresh {
		_, out := f.pick(t, famA)
		if fresh := elapsed <= maxStale; fresh != (out == outBest) {
			t.Fatalf("at %v (max %v): outcome %v", elapsed, maxStale, out)
		}
		f.clk.advance(cfg.Refresh)
	}
}

// R25: a failing store keeps the last scores; they expire on their own
// timestamps, and the first successful read after recovery is used at once.
func TestStoreOutage(t *testing.T) {
	cfg := testConfig(t)
	cfg.MaxStaleness, cfg.TTL = 10*time.Second, 10
	f := newFixture(t, cfg)
	f.put(t, us1, 1, true, 0)
	if id, _ := f.pick(t, famA); id != us1 {
		t.Fatal("initial read")
	}
	f.store.Fail(errors.New("down"))
	f.clk.advance(10 * time.Second)
	if id, _ := f.pick(t, famA); id != us1 {
		t.Fatal("scores dropped before they went stale")
	}
	f.clk.advance(time.Second)
	if id, out := f.pick(t, famA); out != outStatic || id != eu1 {
		t.Fatalf("stale scores used during the outage: %s %v", id, out)
	}
	f.store.Fail(nil)
	f.put(t, us1, 1, true, 0)
	f.clk.advance(cfg.Refresh)
	if id, _ := f.pick(t, famA); id != us1 {
		t.Fatal("fresh scores not used after recovery")
	}
}

// The store is read at most once per refresh interval.
func TestRefreshInterval(t *testing.T) {
	cfg := testConfig(t)
	cfg.Refresh = 5 * time.Second
	f := newFixture(t, cfg)
	f.put(t, eu1, 1, true, 0)
	f.pick(t, famA)
	f.put(t, us1, 1, true, 0)
	f.put(t, eu1, 0.1, true, 0)
	f.clk.advance(4 * time.Second)
	if id, _ := f.pick(t, famA); id != eu1 {
		t.Fatal("re-read inside the refresh interval")
	}
	f.clk.advance(time.Second)
	if id, _ := f.pick(t, famA); id != us1 {
		t.Fatal("not re-read after the refresh interval")
	}
}

// R20: the static fallback is the first-listed endpoint OF THE FAMILY.
func TestStaticFallbackPerFamily(t *testing.T) {
	cfg := testConfig(t)
	cfg.Endpoints[0], cfg.Endpoints[1] = cfg.Endpoints[1], cfg.Endpoints[0] // The v4-only us1 first.
	f := newFixture(t, cfg)
	if id, out := f.pick(t, famA); id != us1 || out != outStatic {
		t.Fatalf("A: %s %v", id, out)
	}
	if id, out := f.pick(t, famAAAA); id != eu1 || out != outStatic {
		t.Fatalf("AAAA: %s %v", id, out)
	}
}

func TestWeightedFollowsDraw(t *testing.T) {
	cfg := testConfig(t)
	cfg.Mode = ModeWeighted
	f := newFixture(t, cfg)
	f.put(t, eu1, 0.25, true, 0) // Weight 2500.
	f.put(t, us1, 0, true, 0)    // Drained.
	f.put(t, ap1, 0.75, true, 0) // Weight 7500.
	for draw, want := range map[uint64]string{0: eu1, 2499: eu1, 2500: ap1, 9999: ap1, 10000: eu1} {
		f.draw = draw
		if id, out := f.pick(t, famA); id != want || out != outWeighted {
			t.Errorf("draw %d: %s %v, want %s", draw, id, out, want)
		}
	}
}

func TestMemStore(t *testing.T) {
	s := NewMemStore()
	s.Set("a", []byte("x"))
	s.Delete("a")
	got, err := s.Get(t.Context(), []string{"a"})
	if err != nil || got[0] != nil {
		t.Fatalf("%v %v", got, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := contextCancelled(t)
	defer cancel()
	if _, err := s.Get(ctx, nil); err == nil {
		t.Fatal("cancelled context ignored")
	}
}

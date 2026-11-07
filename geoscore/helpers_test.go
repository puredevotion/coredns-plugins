package geoscore

import (
	"net/netip"
	"sync"
	"testing"
	"time"
)

// t0 is the test clock's start, a plain Unix time.
var t0 = time.Unix(1_762_500_000, 0)

const (
	eu1      = "eu1"
	us1      = "us1"
	ap1      = "ap1"
	testName = "www.example.com."
	testZone = "example.com."
)

// clock is a settable time source.
type clock struct {
	t  time.Time
	mu sync.Mutex
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func addrs(tb testing.TB, ss ...string) []netip.Addr {
	tb.Helper()
	out := make([]netip.Addr, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParseAddr(s)
	}
	return out
}

// testConfig: eu1 (v4+v6), us1 (v4 only), ap1 (v4+v6), in that order.
func testConfig(tb testing.TB) Config {
	tb.Helper()
	c := DefaultConfig(testName, testZone)
	c.Endpoints = []Endpoint{
		{ID: eu1, Addrs: addrs(tb, "192.0.2.1", "2001:db8::1")},
		{ID: us1, Addrs: addrs(tb, "192.0.2.2", "192.0.2.22")},
		{ID: ap1, Addrs: addrs(tb, "198.51.100.3", "2001:db8::3")},
	}
	return c
}

// fixture is an instance on a MemStore with a settable clock and a
// scripted random draw.
type fixture struct {
	g     *Instance
	store *MemStore
	clk   *clock
	draw  uint64
}

func newFixture(tb testing.TB, cfg Config) *fixture { //nolint:gocritic // hugeParam: tests pass configs by value
	tb.Helper()
	f := &fixture{store: NewMemStore(), clk: &clock{t: t0}}
	g, err := New(cfg, f.store)
	if err != nil {
		tb.Fatalf("New: %v", err)
	}
	g.now = f.clk.now
	g.rnd = func(n uint64) uint64 { return f.draw % n }
	f.g = g
	return f
}

// put writes an entry for endpoint id, stamped age seconds before the clock.
func (f *fixture) put(tb testing.TB, id string, score float64, healthy bool, age int64) {
	tb.Helper()
	e := Entry{Score: score, Healthy: healthy, Updated: f.clk.now().Unix() - age}
	b, err := e.Marshal()
	if err != nil {
		tb.Fatalf("Marshal: %v", err)
	}
	f.store.Set(f.g.cfg.KeyPrefix+":"+id, b)
}

// refetch forces the next query to re-read the store.
func (f *fixture) refetch() {
	s := f.g.snap.Load()
	f.g.snap.Store(&snapshot{slots: s.slots})
}

// pick runs one decision for the family against the current snapshot.
func (f *fixture) pick(tb testing.TB, fam family) (id string, out outcome) {
	tb.Helper()
	now := f.clk.now()
	d := f.g.decide(fam, f.g.current(tb.Context(), now), now.Unix())
	if d.endpoint < 0 {
		return "", d.outcome
	}
	return f.g.cfg.Endpoints[d.endpoint].ID, d.outcome
}

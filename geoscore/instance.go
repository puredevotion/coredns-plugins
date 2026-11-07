package geoscore

import (
	"context"
	"math/rand/v2" // nosemgrep: go.lang.security.audit.crypto.math-random-used -- weighted-mode load spreading (rnd), not a security-sensitive value: the answers are public and a predictable pick gives an attacker nothing
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// family is the address family a query asks for.
type family uint8

const (
	famA family = iota
	famAAAA
	numFamilies
)

func (f family) String() string {
	if f == famAAAA {
		return "AAAA"
	}
	return "A"
}

// familyOf maps a qtype to the family it asks for.
func familyOf(qtype uint16) (family, bool) {
	switch qtype {
	case dns.TypeA:
		return famA, true
	case dns.TypeAAAA:
		return famAAAA, true
	}
	return 0, false
}

// outcome is what a decision answers.
type outcome uint8

const (
	outBest outcome = iota
	outWeighted
	outStatic
	outServfail
	outNodata
)

var outcomeNames = [...]string{modeBest, modeWeighted, "fallback_static", "fallback_servfail", "fallback_nodata"}

func (o outcome) String() string { return outcomeNames[o] }

// decision is the result of Instance.decide: an outcome, and for the
// answering outcomes the endpoint (an index into Config.Endpoints).
type decision struct {
	endpoint int
	outcome  outcome
}

// snapshot is the plugin's copy of the score map: one slot per endpoint, in
// Config.Endpoints order, and when it was read.
type snapshot struct {
	fetched time.Time
	slots   []slot
}

// Instance serves one `geoscore NAME` block.
type Instance struct {
	store Store
	snap  atomic.Pointer[snapshot]
	now   func() time.Time
	// Rnd returns a uniform draw in [0, n), n > 0. The draw only spreads load;
	// it is not a security boundary.
	rnd     func(n uint64) uint64
	txtName string
	keys    []string
	// ByFam lists, per family, the indices of the endpoints that have an
	// address of that family, in configuration order: the candidate set of a
	// query, already validated.
	byFam [numFamilies][]int
	// The answer templates, rr4 and rr6, are per endpoint index.
	rr4      [][]dns.A
	rr6      [][]dns.AAAA
	cfg      Config
	maxStale int64
	fetchMu  sync.Mutex
}

// New validates cfg and returns an instance reading scores from store. It is
// the only constructor; the Corefile parser goes through it too.
func New(cfg Config, store Store) (*Instance, error) { //nolint:gocritic // hugeParam: a value, so the caller cannot change it after validation
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if store == nil {
		return nil, errStoreClosed
	}
	g := &Instance{
		cfg:      cfg,
		store:    store,
		now:      time.Now,
		rnd:      rand.Uint64N,
		maxStale: int64(cfg.MaxStaleness / time.Second),
		keys:     make([]string, len(cfg.Endpoints)),
		rr4:      make([][]dns.A, len(cfg.Endpoints)),
		rr6:      make([][]dns.AAAA, len(cfg.Endpoints)),
	}
	if cfg.RationaleTXT {
		g.txtName = rationaleLabel + cfg.Name
	}
	hdr := func(t uint16) dns.RR_Header {
		return dns.RR_Header{Name: cfg.Name, Rrtype: t, Class: dns.ClassINET, Ttl: cfg.TTL}
	}
	for i, ep := range cfg.Endpoints {
		g.keys[i] = cfg.KeyPrefix + ":" + ep.ID
		for _, a := range ep.Addrs {
			b := a.AsSlice()
			if a.Is4() {
				g.rr4[i] = append(g.rr4[i], dns.A{Hdr: hdr(dns.TypeA), A: net.IP(b)})
			} else {
				g.rr6[i] = append(g.rr6[i], dns.AAAA{Hdr: hdr(dns.TypeAAAA), AAAA: net.IP(b)})
			}
		}
		if len(g.rr4[i]) > 0 {
			g.byFam[famA] = append(g.byFam[famA], i)
		}
		if len(g.rr6[i]) > 0 {
			g.byFam[famAAAA] = append(g.byFam[famAAAA], i)
		}
	}
	g.snap.Store(&snapshot{slots: make([]slot, len(cfg.Endpoints))})
	return g, nil
}

// current returns the snapshot to answer from, re-reading the store first
// when the snapshot is older than the refresh interval. At most one query
// does the read; the others answer from the snapshot they have. A failed
// read keeps the old entries, which go on ageing from their writers'
// timestamps, so an outage ends in the fallback within max-staleness (R25,
// GeoScoreStaleness.tla).
func (g *Instance) current(ctx context.Context, now time.Time) *snapshot {
	s := g.snap.Load()
	if now.Sub(s.fetched) < g.cfg.Refresh || !g.fetchMu.TryLock() {
		return s
	}
	defer g.fetchMu.Unlock()
	if s = g.snap.Load(); now.Sub(s.fetched) < g.cfg.Refresh {
		return s
	}
	ns := g.fetch(ctx, now, s)
	g.snap.Store(ns)
	return ns
}

func (g *Instance) fetch(ctx context.Context, now time.Time, old *snapshot) *snapshot {
	ctx, cancel := context.WithTimeout(ctx, g.cfg.Timeout)
	defer cancel()
	vals, err := g.store.Get(ctx, g.keys)
	if err == nil && len(vals) != len(g.keys) {
		err = errStoreClosed
	}
	if err != nil {
		storeErrors.WithLabelValues(g.cfg.Name).Inc()
		log.Warningf("%s: reading scores: %v; keeping the previous ones, which expire %v after they were written", g.cfg.Name, err, g.cfg.MaxStaleness)
		return &snapshot{slots: old.slots, fetched: now}
	}
	ns := &snapshot{slots: make([]slot, len(g.keys)), fetched: now}
	for i, v := range vals {
		if v == nil {
			continue
		}
		e, perr := ParseEntry(v)
		ns.slots[i] = slot{entry: e, found: true, ok: perr == nil}
		if perr != nil {
			invalidEntries.WithLabelValues(g.cfg.Name).Inc()
			log.Warningf("%s: ignoring the entry at %s: %v", g.cfg.Name, g.keys[i], perr)
		}
	}
	return ns
}

// candidates fills buf with the family's candidates as selection sees them.
func (g *Instance) candidates(buf *[maxEndpoints]cand, fam family, s *snapshot, now int64) []cand {
	idx := g.byFam[fam]
	cs := buf[:len(idx)]
	for i, ep := range idx {
		sl := &s.slots[ep]
		cs[i] = cand{weight: sl.entry.Weight(), eligible: classify(sl, now, g.maxStale) == stateEligible}
	}
	return cs
}

// decide is Lean `outcome`: select by mode among the eligible candidates of
// the family, or apply the fallback when none is. The family must have at
// least one endpoint.
func (g *Instance) decide(fam family, s *snapshot, now int64) decision {
	var buf [maxEndpoints]cand
	cs := g.candidates(&buf, fam, s, now)
	idx := g.byFam[fam]

	sel, out := -1, outBest
	if g.cfg.Mode == ModeWeighted {
		out = outWeighted
		if t := totalWeight(cs); t > 0 {
			sel = pickWeighted(cs, g.rnd(t))
		}
	} else {
		sel = pickBest(cs)
	}
	if sel >= 0 {
		return decision{endpoint: idx[sel], outcome: out}
	}
	switch g.cfg.Fallback {
	case FallbackServfail:
		return decision{endpoint: -1, outcome: outServfail}
	case FallbackNodata:
		return decision{endpoint: -1, outcome: outNodata}
	case FallbackStatic:
	}
	return decision{endpoint: idx[0], outcome: outStatic}
}

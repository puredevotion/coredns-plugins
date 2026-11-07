package zoneversion

import (
	"sync"
	"time"
)

// halfSerialSpace is 2^31, RFC 1982 §3.2's comparison bound for SERIAL_BITS 32.
const halfSerialSpace = 1 << 31

// serialGreater is RFC 1982 §3.2's "s1 > s2" for 32-bit serials, the same
// function as dynupdate's and as Serial.serialGreater in
// verification/lean/CorednsPlugins/Serial.lean (which proves it is exactly
// §3.2, irreflexive, asymmetric, and undefined only at the antipodes).
func serialGreater(a, b uint32) bool {
	return a != b && ((a < b && b-a > halfSerialSpace) || (a > b && a-b < halfSerialSpace))
}

// maxEntryAge bounds how old a cached observation may be when it is used as
// the "before" side of a bracket (see ServeDNS). The bracket is sound only if
// the zone's serial did not leave a value and come back to it in between
// (assumption A1 in docs/zoneversion-plugin.md); a short age bounds the
// window in which an operator rollback could do that. A constant, not a
// directive: it trades one extra internal SOA lookup per 30 seconds per zone
// against that window, and no setting makes the window zero except not
// caching at all.
const maxEntryAge = 30 * time.Second

// entry is one observation: the zone had serial at time at.
type entry struct {
	at     time.Time
	serial uint32
}

// serialCache remembers, per zone apex, the last serial observed for it. It
// holds only the configured zones, so it is as small as the Corefile.
//
// What it is for: a positive answer carries no SOA, so the serial must be
// looked up separately, after the answer. The cached observation is the
// "before" half of a bracket around the answer, saving a second lookup. It is
// never advertised by itself: only a serial observed after the answer is
// (guarantee G1).
type serialCache struct {
	m  map[string]entry
	mu sync.Mutex
}

func newSerialCache() *serialCache { return &serialCache{m: map[string]entry{}} }

// get returns the cached serial for apex if the observation is at most
// maxEntryAge old at now.
func (c *serialCache) get(apex string, now time.Time) (uint32, bool) {
	c.mu.Lock()
	e, ok := c.m[apex]
	c.mu.Unlock()
	if !ok || !fresh(e, now) {
		return 0, false
	}
	return e.serial, true
}

// fresh reports whether e may still be used at now. A clock that went
// backwards makes the entry stale too, rather than fresh forever.
func fresh(e entry, now time.Time) bool {
	age := now.Sub(e.at)
	return age >= 0 && age <= maxEntryAge
}

// outcome is what observe did, for the metrics and the tests.
type outcome uint8

const (
	outcomeNew       outcome = iota // No fresh entry: stored.
	outcomeSame                     // Same serial: refreshed.
	outcomeAdvanced                 // RFC 1982 greater: replaced.
	outcomeRegressed                // Not greater (or undefined): kept the old one.
)

// observe records that apex had serial at now. The update rule is `update` in
// ZoneVersion.lean, which proves it never moves a fresh entry backwards in
// RFC 1982 order and never stores a serial nobody observed:
//
//   - no entry, or a stale one: store the observation;
//   - the same serial: refresh its time (a later real observation of it);
//   - RFC 1982 greater: the zone advanced, replace;
//   - otherwise (smaller, or 2^31 away and so undefined): keep the entry
//     until it goes stale. This is how a rollback is detected: brackets keep
//     failing (and the option is withheld) for at most maxEntryAge, after
//     which the rolled-back serial is accepted as the new baseline.
func (c *serialCache) observe(apex string, serial uint32, now time.Time) outcome {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[apex]
	next, out := update(e, ok && fresh(e, now), serial, now)
	c.m[apex] = next
	return out
}

// update is the pure rule observe applies, separated so the property tests
// and the Lean model check the same function.
func update(e entry, isFresh bool, serial uint32, now time.Time) (entry, outcome) {
	switch {
	case !isFresh:
		return entry{serial: serial, at: now}, outcomeNew
	case serial == e.serial:
		return entry{serial: serial, at: now}, outcomeSame
	case serialGreater(serial, e.serial):
		return entry{serial: serial, at: now}, outcomeAdvanced
	default:
		return e, outcomeRegressed
	}
}

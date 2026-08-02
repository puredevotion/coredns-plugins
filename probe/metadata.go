package probe

import (
	"context"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/metadata"
	"github.com/coredns/coredns/request"
)

// Metadata implements metadata.Provider, and exists for exactly one consumer:
// the rrl plugin's wildcard-flooding mitigation.
//
// # Why this is not optional here
//
// rrl buckets a response by the FULL QNAME unless something publishes
// "zone/wildcard" (see coredns/rrl's responseToToken: it reads that value and
// strips the leading "*." to get the parent to account against). Every name in
// this zone is synthesized on demand from a caller-supplied random token, so
// without this provider every single query lands in a bucket of its own and the
// rate limiter can never accumulate anything to limit.
//
// That is not a corner case for this plugin, it is the entire grammar. An
// attacker reflecting off this zone does not need to discover a wildcard the
// way rrl's README imagines — they only have to vary the token, which is one
// line of a script, and rrl as configured would never fire. Publishing the
// wildcard parent collapses every synthesized answer under the zone apex, which
// is the behaviour the rate limits were written assuming.
//
// Both served zones get this treatment. The agent domain synthesizes per-report
// names the same way (the reported QNAME and EDE code are labels), so it has
// the identical evasion and needs the identical fix; they are accounted
// separately because they are different zones with very different expected
// rates.
//
// The value must be a wildcard in presentation form — rrl slices "*." off the
// front with a fixed offset rather than parsing, so anything not starting with
// those two bytes corrupts the parent name it accounts against.
func (p *Probe) Metadata(ctx context.Context, state request.Request) context.Context {
	qname := state.Name()

	// Agent domain first: it is a sibling of the probe zone, never a child (the
	// setup rejects nesting either way round), so the order only matters for
	// clarity rather than correctness.
	if p.AgentDomain != "" && plugin.Name(p.AgentDomain).Matches(qname) {
		metadata.SetValueFunc(ctx, "zone/wildcard", func() string {
			return "*." + p.AgentDomain
		})
		return ctx
	}

	if plugin.Name(p.Zone).Matches(qname) {
		metadata.SetValueFunc(ctx, "zone/wildcard", func() string {
			return "*." + p.Zone
		})
	}

	// A name in neither zone gets no value. rrl then falls back to the qname,
	// which is correct: we are not authoritative for it and will REFUSE it, and
	// a REFUSED answer is small enough not to be worth reflecting.
	return ctx
}

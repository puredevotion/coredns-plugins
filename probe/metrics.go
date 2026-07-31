package probe

import (
	"github.com/coredns/coredns/plugin"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Aggregate counters for the protocol properties this zone measures.
//
// These exist because the per-token store is deliberately short-lived (10m by
// default) and reachable only by whoever holds the token. That is right for the
// individual reading, and useless for the question "what fraction of resolvers
// reaching us are DELEG-aware?". Metrics answer the population question without
// retaining anything about a person: every series below is a count, labelled
// only by protocol state, never by address, prefix or token.
//
// Label cardinality is bounded by construction — every label is a small closed
// enum. Nothing here takes a resolver address, an ECS prefix or a token as a
// label, and nothing should ever be added that does: this endpoint is scraped
// and retained far longer than the observation store, so a high-cardinality
// label would quietly turn Prometheus into the long-term store of client
// network data that the store's TTL exists to prevent.
var (
	// probeObservations counts observed queries by the EDNS state that matters
	// for the three measurements this zone was extended to make.
	//
	// `deleg` and `ecs` are three-valued, not boolean, because in both cases
	// "said nothing" is a distinct and important reading from "said no" — see
	// delegLabel and ecsLabel.
	probeObservations = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: "probe",
		Name:      "observations_total",
		Help:      "Observed probe queries, by resolver protocol state.",
	}, []string{"proto", "family", "do", "co", "deleg", "ecs", "zoneversion"})

	// probeECSPrefixBits is the distribution of disclosed prefix lengths.
	//
	// A histogram rather than a gauge because the interesting question is the
	// shape ("how specific are the resolvers that do disclose?"), and buckets
	// are chosen at the boundaries operators actually argue about: /0 (declined
	// is excluded, see below), the common /24, and the IPv6 /48-/64 range.
	//
	// Only DISCLOSED observations are recorded. A declined disclosure is not a
	// zero-length prefix — putting it in this histogram would drag the
	// distribution toward zero and make the resolvers behaving best look like
	// the ones leaking least, which is a different claim.
	probeECSPrefixBits = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: plugin.Namespace,
		Subsystem: "probe",
		Name:      "ecs_prefix_bits",
		Help:      "Disclosed EDNS Client Subnet prefix length, for queries that disclosed one.",
		Buckets:   []float64{8, 16, 20, 24, 28, 32, 48, 56, 64},
	}, []string{"family"})

	// probeReports counts inbound RFC 9567 error reports.
	//
	// `ede` is the reported extended error code as a decimal string. The EDE
	// registry is small and closed-ish, but a hostile sender picks this value,
	// so unregistered codes are collapsed to "other" rather than minted as new
	// series — otherwise anyone could grow this metric without bound by walking
	// 0..65535.
	probeReports = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: "probe",
		Name:      "error_reports_total",
		Help:      "Inbound RFC 9567 DNS error reports, by extended error code and whether they correlated to a token.",
	}, []string{"ede", "correlated"})

	// probeKeyTagQueries counts inbound RFC 8145 Key Tag queries.
	//
	// `state` records whether the sender honoured §5.2's smallest-to-largest sort
	// requirement, plus "malformed" for names shaped like a Key Tag query that
	// were not one. Recording conformance rather than silently normalising it is
	// the point — this zone exists to see what implementations actually do.
	probeKeyTagQueries = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: "probe",
		Name:      "key_tag_queries_total",
		Help:      "Inbound RFC 8145 Key Tag queries, by whether the tag list was correctly sorted.",
	}, []string{"state"})

	// probeKeyTagKnowledge counts trust-anchor signals by whether this zone's own
	// key was among the tags.
	//
	// `source` separates the two RFC 8145 mechanisms, which are not equally
	// informative: "edns" (option 14, attached to any query — the half that
	// actually produces data) and "query" (a `_ta-` Key Tag query, which only
	// arrives if somebody pinned this zone as a configured trust anchor).
	//
	// `knows` is three-valued: "yes", "no", and "unknown" for when this zone has
	// no signer to compare against. A zone with no key cannot conclude a resolver
	// lacks its key.
	probeKeyTagKnowledge = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: "probe",
		Name:      "key_tag_knowledge_total",
		Help:      "RFC 8145 trust-anchor signals, by mechanism and whether this zone's key tag was signalled.",
	}, []string{"source", "knows"})

	// probeReportsRejected counts report names that did not parse. Separate from
	// probeReports because "someone is sending us garbage" and "a resolver
	// reported a failure" are different operational facts, and conflating them
	// would let noise look like signal.
	probeReportsRejected = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: "probe",
		Name:      "error_reports_rejected_total",
		Help:      "Inbound names under the agent domain that were not valid RFC 9567 reports.",
	}, []string{"reason"})
)

// Three-valued label helpers. The strings are part of the metric contract, so
// they match the web tier's readings (probereport.ECSDisclosure /
// probereport.DELEGReading) rather than inventing a second vocabulary for the
// same fact.

// delegLabel renders DELEG-awareness. "unknown" means the query carried no EDNS
// at all, so the DE bit could not have been present either way; counting that as
// "unaware" would understate adoption by every non-EDNS query.
func delegLabel(o Observation) string {
	switch {
	case !o.EDNS:
		return "unknown"
	case o.DELEGAware:
		return "aware"
	default:
		return "unaware"
	}
}

// ecsLabel renders the three ECS states. See Observation.ECS for why "declined"
// must not be folded into either neighbour.
func ecsLabel(o Observation) string {
	switch {
	case !o.ECS:
		return "silent"
	case o.ECSScope == 0:
		return "declined"
	default:
		return "disclosed"
	}
}

func familyLabel(o Observation) string {
	if o.IPv6 {
		return "inet6"
	}
	return "inet"
}

func ecsFamilyLabel(family uint16) string {
	switch family {
	case 1:
		return "inet"
	case 2:
		return "inet6"
	default:
		// A resolver can send anything here. Bounded to one bucket rather than
		// minting a series per bogus value.
		return "other"
	}
}

// recordMetrics updates the aggregate counters for one observation.
func recordMetrics(o Observation) {
	probeObservations.WithLabelValues(
		string(o.Transport),
		familyLabel(o),
		boolStr(o.DO),
		boolStr(o.CompactAware),
		delegLabel(o),
		ecsLabel(o),
		boolStr(o.ZoneVersionAsked),
	).Inc()

	// Only disclosures, deliberately — see probeECSPrefixBits.
	if o.ECS && o.ECSScope > 0 {
		probeECSPrefixBits.WithLabelValues(ecsFamilyLabel(o.ECSFamily)).Observe(float64(o.ECSScope))
	}

	// RFC 8145 via EDNS option 14. Only counted when the resolver actually sent
	// tags: silence is not a statement about which keys it holds, and counting it
	// as "no" would manufacture a finding out of the common case.
	if len(o.KeyTags) > 0 {
		knows := "no"
		if o.KnowsZoneKey {
			knows = "yes"
		}
		probeKeyTagKnowledge.WithLabelValues("edns", knows).Inc()
	}
}

package probe

import (
	"sync/atomic"

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
	// ProbeObservations counts observed queries by the EDNS state that matters
	// for the three measurements this zone was extended to make.
	//
	// `deleg` and `ecs` are three-valued, not boolean, because in both cases
	// "said nothing" is a distinct and important reading from "said no" — see
	// delegLabel and ecsLabel.
	probeObservations = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: pluginName,
		Name:      "observations_total",
		Help:      "Observed probe queries, by resolver protocol state.",
	}, []string{"proto", "family", "do", "co", "deleg", "ecs", "zoneversion"})

	// ProbeECSPrefixBits is the distribution of disclosed prefix lengths.
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
		Subsystem: pluginName,
		Name:      "ecs_prefix_bits",
		Help:      "Disclosed EDNS Client Subnet prefix length, for queries that disclosed one.",
		Buckets:   []float64{8, 16, 20, 24, 28, 32, 48, 56, 64},
	}, []string{"family"})

	// ProbeReports counts inbound RFC 9567 error reports.
	//
	// `ede` is the reported extended error code as a decimal string. The EDE
	// registry is small and closed-ish, but a hostile sender picks this value,
	// so unregistered codes are collapsed to "other" rather than minted as new
	// series — otherwise anyone could grow this metric without bound by walking
	// 0..65535.
	probeReports = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: pluginName,
		Name:      "error_reports_total",
		Help:      "Inbound RFC 9567 DNS error reports, by extended error code and whether they correlated to a token.",
	}, []string{"ede", "correlated"})

	// ProbeEncrypted counts queries by whether they arrived over an encrypted
	// transport, and how (RFC 9539).
	//
	// This is the series RFC 9539 adoption is invisible without: resolvers probe
	// opportunistically with no signalling, so the authoritative being probed is
	// the only party that can see an attempt at all.
	//
	// `version` and `group` are bounded enums produced by Go's own TLS stack
	// (tls.VersionName, CurveID.String()), not attacker-chosen strings — a
	// resolver cannot mint a series by offering a garbage cipher, because an
	// unsupported one fails the handshake before a query exists.
	probeEncrypted = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: pluginName,
		Name:      "encrypted_queries_total",
		Help:      "Queries by transport encryption, for measuring RFC 9539 opportunistic adoption.",
	}, []string{"proto", "encrypted", "version", "group", "resumed"})

	// ProbeKeyTagQueries counts inbound RFC 8145 Key Tag queries.
	//
	// `state` records whether the sender honoured §5.1's smallest-to-largest sort
	// requirement, plus "malformed" for names shaped like a Key Tag query that
	// were not one. Recording conformance rather than silently normalising it is
	// the point — this zone exists to see what implementations actually do.
	probeKeyTagQueries = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: pluginName,
		Name:      "key_tag_queries_total",
		Help:      "Inbound RFC 8145 Key Tag queries, by whether the tag list was correctly sorted.",
	}, []string{"state"})

	// ProbeKeyTagKnowledge counts trust-anchor signals by whether this zone's own
	// key was among the tags.
	//
	// `source` separates the two RFC 8145 mechanisms, which are not equally
	// informative: "dnskey" (option 14 on an apex DNSKEY query, where §4.2
	// has a validating resolver send it), "edns" (option 14 on a probe name;
	// §4.2 allows it only on DNSKEY queries, so this comes from senders that
	// break that rule) and "query" (a `_ta-` Key Tag query of type NULL,
	// which only arrives if somebody pinned this zone as a configured trust
	// anchor).
	//
	// `knows` is three-valued: "yes", "no", and "unknown" for when this zone has
	// no signer to compare against. A zone with no key cannot conclude a resolver
	// lacks its key.
	probeKeyTagKnowledge = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: pluginName,
		Name:      "key_tag_knowledge_total",
		Help:      "RFC 8145 trust-anchor signals, by mechanism and whether this zone's key tag was signalled.",
	}, []string{"source", "knows"})

	// ProbeReportsRejected counts report names that did not parse. Separate from
	// probeReports because "someone is sending us garbage" and "a resolver
	// reported a failure" are different operational facts, and conflating them
	// would let noise look like signal.
	probeReportsRejected = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: pluginName,
		Name:      "error_reports_rejected_total",
		Help:      "Inbound names under the agent domain that were not valid RFC 9567 reports.",
	}, []string{"reason"})
)

// Three-valued label helpers. The strings are part of the metric contract, so
// they match the web tier's readings (probereport.ECSDisclosure /
// probereport.DELEGReading) rather than inventing a second vocabulary for the
// same fact.
const (
	labelYes     = "yes"
	labelUnknown = "unknown"
	labelInet    = "inet"
	labelInet6   = "inet6"
	labelOther   = "other"
)

// delegLabel renders DELEG-awareness. "unknown" means the query carried no EDNS
// at all, so the DE bit could not have been present either way; counting that as
// "unaware" would understate adoption by every non-EDNS query.
func delegLabel(o *Observation) string {
	switch {
	case !o.EDNS:
		return labelUnknown
	case o.DELEGAware:
		return "aware"
	default:
		return "unaware"
	}
}

// ecsLabel renders the three ECS states. See Observation.ECS for why "declined"
// must not be folded into either neighbour.
func ecsLabel(o *Observation) string {
	switch {
	case !o.ECS:
		return "silent"
	case o.ECSScope == 0:
		return "declined"
	default:
		return "disclosed"
	}
}

func familyLabel(o *Observation) string {
	if o.IPv6 {
		return labelInet6
	}
	return labelInet
}

// ianaAFIPv6 is IANA Address Family Number 2, per RFC 7871's `FAMILY` field.
const ianaAFIPv6 = 2

func ecsFamilyLabel(family uint16) string {
	switch family {
	case 1:
		return labelInet
	case ianaAFIPv6:
		return labelInet6
	default:
		// A resolver can send anything here. Bounded to one bucket rather than
		// minting a series per bogus value.
		return labelOther
	}
}

// recordMetrics updates the aggregate counters for one observation.
func recordMetrics(o *Observation) {
	observationCounter(o).Inc()

	// Only disclosures, deliberately — see probeECSPrefixBits.
	if o.ECS && o.ECSScope > 0 {
		probeECSPrefixBits.WithLabelValues(ecsFamilyLabel(o.ECSFamily)).Observe(float64(o.ECSScope))
	}

	encryptedCounter(o).Inc()

	// RFC 8145 via EDNS option 14. Only counted when the resolver actually sent
	// tags: silence is not a statement about which keys it holds, and counting it
	// as "no" would manufacture a finding out of the common case.
	if len(o.KeyTags) > 0 {
		knows := "no"
		if o.KnowsZoneKey {
			knows = labelYes
		}
		probeKeyTagKnowledge.WithLabelValues("edns", knows).Inc()
	}
}

// Counter caches
//
// WithLabelValues validates every label, hashes all of them and takes the
// vector's lock on every call, which came to a quarter of a microsecond per
// query — a tenth of the whole unsigned answer path. Every label on the two
// per-query counters is a small closed enum, so each combination's child is
// resolved once and then found by indexing: the enums are packed into one
// small integer and the child is kept in an atomic slot for it. A label value
// outside the enum (a transport this file does not know) bypasses the cache
// and takes the slow path, so the cache can never attach a count to the wrong
// series.

// Enum widths for the observationCounters index, in the order the labels are
// declared on probeObservations.
const (
	transportKinds = 5 // The five transports, see transportIndex.
	familyKinds    = 2
	flagKinds      = 2 // Any boolean label.
	delegKinds     = 3 // Unknown, aware, unaware.
	ecsKinds       = 3 // Silent, declined, disclosed.

	observationKinds = transportKinds * familyKinds * flagKinds * flagKinds * delegKinds * ecsKinds * flagKinds
)

// Transport ordinals for the counter caches.
const (
	transportUDPIndex = iota
	transportTCPIndex
	transportTLSIndex
	transportQUICIndex
	transportHTTPIndex
)

var (
	observationCounters [observationKinds]atomic.Pointer[prometheus.Counter]
	cleartextCounters   [transportKinds]atomic.Pointer[prometheus.Counter]
)

// transportIndex maps a Transport onto 0..transportKinds-1, or -1 for one this
// file does not know, which must not be cached under a borrowed index.
func transportIndex(t Transport) int {
	switch t {
	case TransportUDP:
		return transportUDPIndex
	case TransportTCP:
		return transportTCPIndex
	case TransportTLS:
		return transportTLSIndex
	case TransportQUIC:
		return transportQUICIndex
	case TransportHTTP:
		return transportHTTPIndex
	}
	return -1
}

func flagIndex(v bool) int {
	if v {
		return 1
	}
	return 0
}

// delegIndex and ecsIndex number the three-valued readings in the order
// their label functions enumerate them.
func delegIndex(o *Observation) int {
	switch {
	case !o.EDNS:
		return 0
	case o.DELEGAware:
		return 1
	default:
		return 2 //nolint:mnd // The third of the three delegLabel states.
	}
}

func ecsIndex(o *Observation) int {
	switch {
	case !o.ECS:
		return 0
	case o.ECSScope == 0:
		return 1
	default:
		return 2 //nolint:mnd // The third of the three ecsLabel states.
	}
}

// observationCounter returns probeObservations' child for o's labels.
func observationCounter(o *Observation) prometheus.Counter {
	labels := func() prometheus.Counter {
		return probeObservations.WithLabelValues(
			string(o.Transport),
			familyLabel(o),
			boolStr(o.DO),
			boolStr(o.CompactAware),
			delegLabel(o),
			ecsLabel(o),
			boolStr(o.ZoneVersionAsked),
		)
	}
	t := transportIndex(o.Transport)
	if t < 0 {
		return labels()
	}
	// Mixed radix, innermost label last, matching the declaration order above.
	idx := t
	idx = idx*familyKinds + flagIndex(o.IPv6)
	idx = idx*flagKinds + flagIndex(o.DO)
	idx = idx*flagKinds + flagIndex(o.CompactAware)
	idx = idx*delegKinds + delegIndex(o)
	idx = idx*ecsKinds + ecsIndex(o)
	idx = idx*flagKinds + flagIndex(o.ZoneVersionAsked)
	return cachedCounter(&observationCounters[idx], labels)
}

// encryptedCounter returns probeEncrypted's child for o's labels. Only the
// cleartext children are cached: their TLS labels are all empty, so the
// transport alone names the series. An encrypted query carries version and
// group strings produced by the TLS stack, and its handshake already cost a
// thousand times what the label lookup does.
func encryptedCounter(o *Observation) prometheus.Counter {
	labels := func() prometheus.Counter {
		var version, group, resumed string
		if o.TLS != nil {
			version, group, resumed = o.TLS.Version, o.TLS.NamedGroup, boolStr(o.TLS.DidResume)
		}
		return probeEncrypted.WithLabelValues(
			string(o.Transport), boolStr(o.Encrypted()), version, group, resumed,
		)
	}
	t := transportIndex(o.Transport)
	if t < 0 || o.TLS != nil {
		return labels()
	}
	return cachedCounter(&cleartextCounters[t], labels)
}

// cachedCounter returns the counter in slot, resolving it through lookup the
// first time. Two first callers may both resolve it; they get the same child
// from the vector, so the race is benign and the slot ends up holding it.
func cachedCounter(slot *atomic.Pointer[prometheus.Counter], lookup func() prometheus.Counter) prometheus.Counter {
	if c := slot.Load(); c != nil {
		return *c
	}
	c := lookup()
	slot.Store(&c)
	return c
}

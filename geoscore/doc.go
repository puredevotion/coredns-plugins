// Package geoscore is a CoreDNS plugin that answers A and AAAA for a
// configured owner name with the endpoint that scores best on a live signal
// (latency, carbon intensity, cost, health), read from a score map in Valkey,
// instead of a static address.
//
// The candidate set is fixed in the Corefile and validated at startup; the
// scores are validated when read; selection is a pure function proved in
// verification/lean/CorednsPlugins/GeoScore.lean, and the staleness and
// fallback lifecycle is model-checked in
// verification/tla/GeoScoreStaleness.tla. The design and every requirement
// are in docs/geoscore-plugin.md.
package geoscore

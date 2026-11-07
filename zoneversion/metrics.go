package zoneversion

import (
	"github.com/coredns/coredns/plugin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// result is what happened to one ZONEVERSION request, as the `result` label.
// Bounded: nothing from a request ever becomes a label.
type result string

const (
	resultAdded         result = "added"          // The option is on the response.
	resultFormErr       result = "formerr"        // §3.2.1: non-empty or repeated option.
	resultIneligible    result = "ineligible"     // Not an authoritative response for the zone.
	resultLookupFailed  result = "lookup_failed"  // The internal SOA lookup did not give a serial.
	resultSerialChanged result = "serial_changed" // The serial moved during the query: withheld.
)

var (
	requests = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: pluginName,
		Name:      "requests_total",
		Help:      "ZONEVERSION requests for a configured zone, by result.",
	}, []string{"result"})

	regressions = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: pluginName,
		Name:      "serial_regressions_total",
		Help:      "Observed SOA serials not greater (RFC 1982) than the cached one: a zone rolled back.",
	})
)

func count(r result) { requests.WithLabelValues(string(r)).Inc() }

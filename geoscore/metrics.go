package geoscore

import (
	"github.com/coredns/coredns/plugin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Label values are bounded: `name` comes from the Corefile, `family` and
// `outcome` from fixed sets. Nothing from a query becomes a label.
const labelName = "name"

var (
	answers = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: pluginName,
		Name:      "answers_total",
		Help:      "Address answers by owner name, family and outcome (best, weighted, fallback_static, fallback_servfail, fallback_nodata).",
	}, []string{labelName, "family", "outcome"})

	storeErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: pluginName,
		Name:      "store_errors_total",
		Help:      "Failed reads of the score map; the previous scores are kept until they go stale.",
	}, []string{labelName})

	invalidEntries = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: pluginName,
		Name:      "invalid_entries_total",
		Help:      "Score entries rejected by the validator when read; such an endpoint is never selected.",
	}, []string{labelName})
)

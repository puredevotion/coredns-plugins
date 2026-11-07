package resinfo

import (
	"github.com/coredns/coredns/plugin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// responses counts RESINFO answers written. Only the server label: nothing
// from a request becomes a label.
var responses = promauto.NewCounterVec(prometheus.CounterOpts{
	Namespace: plugin.Namespace,
	Subsystem: pluginName,
	Name:      "responses_total",
	Help:      "RESINFO (RFC 9606) responses written.",
}, []string{"server"})

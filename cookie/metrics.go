package cookie

import (
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// The cases of RFC 7873 §5.2, as `case` label values. Bounded: nothing from a
// request ever becomes a label.
const (
	caseNoCookie      = "no_cookie"      // No OPT, or no COOKIE option (§5.2.1).
	caseMalformed     = "malformed"      // Length other than 8 and 16..40 (§5.2.2).
	caseClientOnly    = "client_only"    // §5.2.3
	caseInvalidServer = "invalid_server" // §5.2.4
	caseValid         = "valid"          // §5.2.5, under the generating secret.
	caseValidPrevious = "valid_previous" // §5.2.5, under a verify-only secret (§7.1).
)

var (
	// RFC 7873 §7.2: "It is RECOMMENDED that implementations include counters
	// of the occurrences of the various types of requests and responses
	// described in Section 5" (§7.2).
	requests = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: pluginName,
		Name:      "requests_total",
		Help:      "Requests by DNS Cookie case (RFC 7873 section 5.2).",
	}, []string{"case"})

	badCookies = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: pluginName,
		Name:      "badcookie_responses_total",
		Help:      "Responses with extended RCODE BADCOOKIE (23).",
	})

	formerrs = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: pluginName,
		Name:      "formerr_responses_total",
		Help:      "FORMERR responses to a malformed COOKIE option.",
	})

	// RFC 7873 §7.1: a server secret MUST NOT be used for more than 36 days
	// and SHOULD NOT for more than 26 hours; RFC 9018 §4 relaxes the
	// recommendation to about a month. The plugin does not rotate by itself
	// (that would break anycast consistency), so this is what to alert on.
	_ = promauto.NewGaugeFunc(prometheus.GaugeOpts{
		Namespace: plugin.Namespace,
		Subsystem: pluginName,
		Name:      "secret_age_seconds",
		Help:      "Seconds since the generating secret was installed (file mtime for secret_file, plugin start otherwise).",
	}, func() float64 {
		since := secretSince.Load()
		if since == 0 {
			return 0
		}
		return time.Since(time.Unix(since, 0)).Seconds()
	})
)

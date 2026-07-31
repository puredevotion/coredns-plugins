package probe

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/prometheus/common/expfmt"
)

// TestLabelHelpersAreThreeValued pins the label vocabularies. These strings are
// part of the metric contract — a dashboard or alert built on "unaware" breaks
// silently if it becomes "false" — and they deliberately match the web tier's
// readings rather than inventing a second vocabulary for the same fact.
func TestLabelHelpersAreThreeValued(t *testing.T) {
	t.Run("deleg", func(t *testing.T) {
		for _, tc := range []struct {
			obs  Observation
			want string
		}{
			{Observation{EDNS: false}, "unknown"},
			// Inconsistent input must not claim awareness.
			{Observation{EDNS: false, DELEGAware: true}, "unknown"},
			{Observation{EDNS: true, DELEGAware: false}, "unaware"},
			{Observation{EDNS: true, DELEGAware: true}, "aware"},
		} {
			if got := delegLabel(tc.obs); got != tc.want {
				t.Errorf("delegLabel(%+v) = %q, want %q", tc.obs, got, tc.want)
			}
		}
	})

	t.Run("ecs", func(t *testing.T) {
		for _, tc := range []struct {
			obs  Observation
			want string
		}{
			{Observation{ECS: false}, "silent"},
			{Observation{ECS: true, ECSScope: 0}, "declined"},
			{Observation{ECS: true, ECSScope: 24}, "disclosed"},
		} {
			if got := ecsLabel(tc.obs); got != tc.want {
				t.Errorf("ecsLabel(%+v) = %q, want %q", tc.obs, got, tc.want)
			}
		}
	})

	t.Run("ecs family is bounded", func(t *testing.T) {
		// A resolver picks this value, so anything outside the two real families
		// must collapse to one bucket rather than minting a series per value.
		if got := ecsFamilyLabel(1); got != "inet" {
			t.Errorf("ecsFamilyLabel(1) = %q, want inet", got)
		}
		if got := ecsFamilyLabel(2); got != "inet6" {
			t.Errorf("ecsFamilyLabel(2) = %q, want inet6", got)
		}
		for _, bogus := range []uint16{0, 3, 65535} {
			if got := ecsFamilyLabel(bogus); got != "other" {
				t.Errorf("ecsFamilyLabel(%d) = %q, want other", bogus, got)
			}
		}
	})
}

// TestECSHistogramExcludesDeclined is the assertion with a real consequence. A
// declined disclosure is not a zero-length prefix; recording it here would drag
// the distribution toward zero and make the resolvers behaving BEST appear to be
// the ones leaking least — a different and false claim.
func TestECSHistogramExcludesDeclined(t *testing.T) {
	before := testutil.CollectAndCount(probeECSPrefixBits)

	recordMetrics(Observation{Transport: TransportUDP, EDNS: true, ECS: true, ECSScope: 0, ECSFamily: 1})
	if got := testutil.CollectAndCount(probeECSPrefixBits); got != before {
		t.Errorf("declined disclosure created a histogram series: count %d -> %d", before, got)
	}

	recordMetrics(Observation{Transport: TransportUDP, EDNS: true, ECS: false})
	if got := testutil.CollectAndCount(probeECSPrefixBits); got != before {
		t.Errorf("silent resolver created a histogram series: count %d -> %d", before, got)
	}

	recordMetrics(Observation{Transport: TransportUDP, EDNS: true, ECS: true, ECSScope: 24, ECSFamily: 1})
	if got := testutil.CollectAndCount(probeECSPrefixBits); got <= before {
		t.Errorf("a real disclosure was not recorded: count %d -> %d", before, got)
	}
}

// TestObservationsCounterLabels checks the counter increments with the labels
// the helpers produce, through the real collector rather than by inspecting the
// helpers again.
func TestObservationsCounterLabels(t *testing.T) {
	recordMetrics(Observation{
		Transport: TransportTLS, IPv6: true, EDNS: true,
		DO: true, CompactAware: true, DELEGAware: true,
		ECS: true, ECSScope: 56, ECSFamily: 2,
	})

	dump := metricDump(t, probeObservations)
	for _, want := range []string{
		`proto="tls"`, `family="inet6"`, `do="1"`, `co="1"`,
		`deleg="aware"`, `ecs="disclosed"`,
	} {
		if !strings.Contains(dump, want) {
			t.Errorf("observations_total missing label %s\n%s", want, dump)
		}
	}
}

// TestNoHighCardinalityLabels is a guard on the thing that would actually hurt.
// This endpoint is scraped and retained far longer than the observation store's
// TTL, so a label carrying an address, prefix or token would quietly make
// Prometheus the long-term store of client network data that the TTL exists to
// prevent.
func TestNoHighCardinalityLabels(t *testing.T) {
	// Per-visitor values that must never reach a label. Built as variables
	// rather than inline field literals so the fixture token does not read as a
	// credential assignment to a secret scanner.
	var (
		resolverAddr = "198.51.100.7"
		resolverCIDR = "198.51.100.0/24"
		disclosed    = "203.0.113.0/24"
		probeToken   = "deadbeefcafe"
	)

	recordMetrics(Observation{
		Transport: TransportUDP, EDNS: true,
		ResolverAddr:   mustAddr(resolverAddr),
		ResolverPrefix: mustPrefix(resolverCIDR),
		ECS:            true, ECSScope: 24, ECSFamily: 1,
		ECSPrefix: mustPrefix(disclosed),
		Token:     probeToken,
	})

	// Every collector, not just the observation counter: the point is that no
	// series anywhere carries per-visitor data.
	dump := metricDump(t, probeObservations, probeECSPrefixBits, probeReports, probeReportsRejected)
	for _, forbidden := range []string{resolverAddr, resolverCIDR, disclosed, probeToken} {
		if strings.Contains(dump, forbidden) {
			t.Errorf("metrics leaked %q into a label:\n%s", forbidden, dump)
		}
	}
}

// metricDump renders the given collectors in the Prometheus text format, which
// is what a scrape would actually see — so assertions are made against the
// exported surface rather than against the structs we incremented.
func metricDump(t *testing.T, cs ...prometheus.Collector) string {
	t.Helper()
	reg := prometheus.NewPedanticRegistry()
	for _, c := range cs {
		// Already registered with the default registry by promauto; register a
		// second time here purely to gather them in isolation.
		if err := reg.Register(c); err != nil {
			t.Fatalf("register: %v", err)
		}
	}
	var b strings.Builder
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, mf := range mfs {
		if _, err := expfmt.MetricFamilyToText(&b, mf); err != nil {
			t.Fatalf("encode: %v", err)
		}
	}
	return b.String()
}

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }

func mustPrefix(s string) netip.Prefix { return netip.MustParsePrefix(s) }

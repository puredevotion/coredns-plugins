package probe

import (
	"context"
	"strings"
	"testing"

	"github.com/coredns/coredns/plugin/metadata"
	"github.com/coredns/coredns/plugin/test"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
)

// wildcardFor runs the metadata provider for a QNAME and returns the published
// "zone/wildcard" value, plus whether one was published at all.
func wildcardFor(t *testing.T, p *Probe, qname string) (string, bool) {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(qname), dns.TypeTXT)
	state := request.Request{W: &test.ResponseWriter{}, Req: m}

	ctx := metadata.ContextWithMetadata(context.Background())
	ctx = p.Metadata(ctx, state)

	f := metadata.ValueFunc(ctx, "zone/wildcard")
	if f == nil {
		return "", false
	}
	return f(), true
}

func TestMetadataPublishesProbeZoneWildcard(t *testing.T) {
	p := newTestAgentProbe(t, true)

	got, ok := wildcardFor(t, p, "a1b2c3d4."+testZone)
	if !ok {
		t.Fatal("no zone/wildcard published for a probe-zone name; rrl would bucket by full QNAME and never limit anything")
	}
	if want := "*." + testZone; got != want {
		t.Fatalf("zone/wildcard = %q, want %q", got, want)
	}
}

func TestMetadataPublishesAgentZoneWildcard(t *testing.T) {
	p := newTestAgentProbe(t, true)

	got, ok := wildcardFor(t, p, reportName(dns.TypeTXT, "_badsig.a1b2c3d4."+testZone, 6))
	if !ok {
		t.Fatal("no zone/wildcard published for an agent-zone name")
	}
	if want := "*." + testAgent; got != want {
		t.Fatalf("zone/wildcard = %q, want %q", got, want)
	}
}

// The two zones must not share a rate-limit bucket. They are different zones
// with very different expected rates, and collapsing them would let report
// traffic consume the probe zone's allowance.
func TestMetadataKeepsTheTwoZonesSeparate(t *testing.T) {
	p := newTestAgentProbe(t, true)

	probeW, _ := wildcardFor(t, p, "a1b2c3d4."+testZone)
	agentW, _ := wildcardFor(t, p, reportName(dns.TypeTXT, "_badsig.a1b2c3d4."+testZone, 6))
	if probeW == agentW {
		t.Fatalf("both zones published the same wildcard %q", probeW)
	}
}

// rrl does `f()[2:]` with a fixed offset rather than parsing, so a value that
// does not literally begin with "*." silently corrupts the parent name it
// accounts against — it would rate-limit against a nonsense token instead of
// failing loudly.
func TestMetadataValueIsSliceableByRRL(t *testing.T) {
	p := newTestAgentProbe(t, true)

	for _, qname := range []string{
		"a1b2c3d4." + testZone,
		reportName(dns.TypeTXT, "_badsig.a1b2c3d4."+testZone, 6),
	} {
		got, ok := wildcardFor(t, p, qname)
		if !ok {
			t.Fatalf("%s: nothing published", qname)
		}
		if !strings.HasPrefix(got, "*.") {
			t.Fatalf("%s: zone/wildcard = %q, must start with %q", qname, got, "*.")
		}
		// What rrl actually accounts against.
		if parent := got[2:]; !dns.IsFqdn(parent) || parent == "" {
			t.Fatalf("%s: rrl would account against %q, which is not a usable owner name", qname, parent)
		}
	}
}

func TestMetadataSilentOutsideBothZones(t *testing.T) {
	p := newTestAgentProbe(t, true)

	if got, ok := wildcardFor(t, p, "www.example.net."); ok {
		t.Fatalf("published %q for an out-of-zone name; rrl should fall back to the QNAME there", got)
	}
}

// With reporting disabled there is no agent zone, so a name that would have
// matched it must not be claimed.
func TestMetadataIgnoresAgentZoneWhenReportingDisabled(t *testing.T) {
	p := newTestProbe(t, true) // no AgentDomain

	if got, ok := wildcardFor(t, p, "_er.16.x."+testAgent); ok {
		t.Fatalf("published %q for the agent zone while reporting is disabled", got)
	}
}

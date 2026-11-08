package probe

import (
	"context"
	"strings"
	"testing"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/plugin/metadata"
	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

const bigName = "_big." + testToken + "." + testZone

// bigQuery sends a `_big` TXT query with an optional cookie verdict in the
// request metadata (as the metadata plugin would have set it from the cookie
// plugin), over UDP or TCP, advertising a 4096-byte buffer.
func bigQuery(t *testing.T, p *Probe, verdict string, tcp bool) (req, resp *dns.Msg) {
	t.Helper()
	req = new(dns.Msg)
	req.SetQuestion(bigName, dns.TypeTXT)
	req.SetEdns0(4096, false)
	ctx := metadata.ContextWithMetadata(context.Background())
	if verdict != "" {
		metadata.SetValueFunc(ctx, "cookie/status", func() string { return verdict })
	}
	rec := dnstest.NewRecorder(&test.ResponseWriter{TCP: tcp})
	if _, err := p.ServeDNS(ctx, rec, req); err != nil {
		t.Fatalf("ServeDNS: %v", err)
	}
	if rec.Msg == nil {
		t.Fatal("no message written")
	}
	return req, rec.Msg
}

func newBigCookieProbe(t *testing.T) *Probe {
	t.Helper()
	p := newTestProbe(t, false)
	p.BigNeedsCookie = true
	return p
}

func TestBigOverUDPWithoutAValidCookieIsTruncatedAndSmall(t *testing.T) {
	// Every status the cookie plugin can report that is not a verified cookie,
	// plus "no verdict at all" (cookie or metadata plugin absent): all fail safe.
	for _, verdict := range []string{"", "none", "client_only", "invalid", "unknown-future-value"} {
		t.Run("verdict="+verdict, func(t *testing.T) {
			p := newBigCookieProbe(t)
			req, resp := bigQuery(t, p, verdict, false)

			if !resp.Truncated {
				t.Fatal("an unproven UDP _big must come back with TC=1")
			}
			if len(resp.Answer) != 0 {
				t.Fatalf("truncated reply carries %d answer RRs, want none", len(resp.Answer))
			}
			// The property that matters: whatever a spoofed source triggers is
			// not bigger than the query that triggered it (plus the OPT/header
			// slack of an empty reply).
			if factor := float64(resp.Len()) / float64(req.Len()); factor > 2 {
				t.Fatalf("amplification factor %.2f (%d -> %d bytes), want <= 2", factor, req.Len(), resp.Len())
			}
		})
	}
}

func TestBigOverUDPWithAValidCookieIsAnswered(t *testing.T) {
	for _, verdict := range []string{"valid", "valid_previous"} {
		t.Run(verdict, func(t *testing.T) {
			p := newBigCookieProbe(t)
			_, resp := bigQuery(t, p, verdict, false)

			if resp.Truncated {
				t.Fatal("a client with a verified server cookie must get the big answer over UDP")
			}
			if len(resp.Answer) != 1 {
				t.Fatalf("got %d answers, want 1", len(resp.Answer))
			}
			txt, ok := resp.Answer[0].(*dns.TXT)
			if !ok {
				t.Fatalf("answer is %T, want *dns.TXT", resp.Answer[0])
			}
			if n := len(strings.Join(txt.Txt, "")); n < p.BigSize {
				t.Fatalf("payload %d bytes, want >= big_size %d", n, p.BigSize)
			}
		})
	}
}

func TestBigOverTCPNeedsNoCookie(t *testing.T) {
	p := newBigCookieProbe(t)
	_, resp := bigQuery(t, p, "", true)
	if resp.Truncated || len(resp.Answer) != 1 {
		t.Fatalf("TCP completes a handshake, so the address is real: truncated=%v answers=%d", resp.Truncated, len(resp.Answer))
	}
}

func TestBigCookieGateLeavesEverythingElseAlone(t *testing.T) {
	p := newBigCookieProbe(t)
	ctx := metadata.ContextWithMetadata(context.Background())
	for _, tc := range []struct {
		name  string
		qname string
		qtype uint16
	}{
		{"plain TXT", testToken + "." + testZone, dns.TypeTXT},
		{"plain A", testToken + "." + testZone, dns.TypeA},
		{"_big but A", bigName, dns.TypeA},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := new(dns.Msg)
			m.SetQuestion(tc.qname, tc.qtype)
			m.SetEdns0(4096, false)
			rec := dnstest.NewRecorder(&test.ResponseWriter{})
			if _, err := p.ServeDNS(ctx, rec, m); err != nil {
				t.Fatalf("ServeDNS: %v", err)
			}
			if rec.Msg.Truncated || len(rec.Msg.Answer) == 0 {
				t.Fatalf("unrelated query was gated: truncated=%v answers=%d", rec.Msg.Truncated, len(rec.Msg.Answer))
			}
		})
	}
}

func TestBigIsUnchangedWhenTheGateIsOff(t *testing.T) {
	p := newTestProbe(t, false) // BigNeedsCookie false: the pre-existing behaviour.
	_, resp := bigQuery(t, p, "", false)
	if resp.Truncated || len(resp.Answer) != 1 {
		t.Fatalf("with the gate off a UDP _big with a big buffer is served: truncated=%v answers=%d", resp.Truncated, len(resp.Answer))
	}
}

func TestBigCookieGateCountsOutcomesWithBoundedLabels(t *testing.T) {
	p := newBigCookieProbe(t)
	trunc0 := testutil.ToFloat64(probeBigRequests.WithLabelValues(bigTruncated))
	served0 := testutil.ToFloat64(probeBigRequests.WithLabelValues(bigServed))
	bigQuery(t, p, "", false)
	bigQuery(t, p, "valid", false)
	bigQuery(t, p, "", true)
	if got := testutil.ToFloat64(probeBigRequests.WithLabelValues(bigTruncated)) - trunc0; got != 1 {
		t.Errorf("truncated counter rose by %v, want 1", got)
	}
	if got := testutil.ToFloat64(probeBigRequests.WithLabelValues(bigServed)) - served0; got != 2 {
		t.Errorf("served counter rose by %v, want 2", got)
	}
	if n := testutil.CollectAndCount(probeBigRequests); n != 2 {
		t.Errorf("%d series, want exactly 2 (the label set is a closed enum)", n)
	}
}

func TestSetupParsesBigRequiresCookie(t *testing.T) {
	p, err := parse(caddy.NewTestController("dns", "probe check.example.com {\n\tbig_requires_cookie\n}"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !p.BigNeedsCookie {
		t.Error("big_requires_cookie did not set BigNeedsCookie")
	}
	if p2, err := parse(caddy.NewTestController("dns", "probe check.example.com")); err != nil || p2.BigNeedsCookie {
		t.Errorf("default must be off (err=%v on=%v): the gate needs the cookie and metadata plugins", err, p2 != nil && p2.BigNeedsCookie)
	}
	if _, err := parse(caddy.NewTestController("dns", "probe check.example.com {\n\tbig_requires_cookie yes\n}")); err == nil {
		t.Error("an argument to the bare flag must be rejected")
	}
}

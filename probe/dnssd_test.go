package probe

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// TestParseDNSSDLevels pins the three levels and, more importantly, what must NOT
// be mistaken for them.
func TestParseDNSSDLevels(t *testing.T) {
	for _, tc := range []struct {
		name  string
		sub   string
		kind  dnssdKind
		token string
	}{
		{"browse", "_services._dns-sd._udp.deadbeef", dnssdBrowse, "deadbeef"},
		{"enumerate", "_probe._tcp.deadbeef", dnssdEnumerate, "deadbeef"},
		{"instance", "probe._probe._tcp.deadbeef", dnssdInstanceName, "deadbeef"},
		// A resolver doing 0x20 randomization sends these mixed-case; rejecting
		// them would drop precisely the most careful clients.
		{"mixed case", "_SERVICES._DNS-SD._UDP.deadbeef", dnssdBrowse, "deadbeef"},

		{"bare token is not DNS-SD", "deadbeef", dnssdNone, ""},
		{"modifier query is not DNS-SD", "_badsig.deadbeef", dnssdNone, ""},
		{"wrong proto", "_probe._udp.deadbeef", dnssdNone, ""},
		{"unknown service type", "_other._tcp.deadbeef", dnssdNone, ""},
		{"meta with wrong proto", "_services._dns-sd._tcp.deadbeef", dnssdNone, ""},
		{"no token", "_probe._tcp", dnssdNone, ""},
		{"invalid token", "_probe._tcp.not-hex", dnssdNone, ""},
		{"too deep", "x.probe._probe._tcp.deadbeef", dnssdNone, ""},
		{"empty", "", dnssdNone, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			kind, token := parseDNSSD(tc.sub)
			if kind != tc.kind {
				t.Errorf("kind = %d, want %d", kind, tc.kind)
			}
			if token != tc.token {
				t.Errorf("token = %q, want %q", token, tc.token)
			}
		})
	}
}

// TestDNSSDNamesAreTokenScoped is the design assertion. A fixed DNS-SD name would be
// cacheable, so the first visitor's query would populate every cache on the path and
// no later visitor would ever be observed — implemented, measuring nothing.
func TestDNSSDNamesAreTokenScoped(t *testing.T) {
	p := newTestProbe(t, false)
	b1, e1, i1 := p.dnssdNames("deadbeef")
	b2, e2, i2 := p.dnssdNames("cafebabe")

	for _, pair := range [][2]string{{b1, b2}, {e1, e2}, {i1, i2}} {
		if pair[0] == pair[1] {
			t.Errorf("two tokens share a DNS-SD name: %q", pair[0])
		}
	}
	for _, n := range []string{b1, e1, i1} {
		if !strings.Contains(n, "deadbeef") {
			t.Errorf("%q does not carry the token, so it is cacheable across visitors", n)
		}
		if !strings.HasSuffix(n, p.Zone) {
			t.Errorf("%q is not under the zone", n)
		}
	}
}

// TestDNSSDBrowseChainWalks follows the whole chain through ServeDNS, which is the
// behaviour a client performs and the thing being measured.
func TestDNSSDBrowseChainWalks(t *testing.T) {
	p := newTestProbe(t, false)
	browse, enumerate, instance := p.dnssdNames("deadbeef")

	// Step 1: browse -> the service type.
	m := query(t, p, browse, dns.TypePTR, true)
	if m.Rcode != dns.RcodeSuccess || len(m.Answer) != 1 {
		t.Fatalf("browse: rcode=%s answers=%d", dns.RcodeToString[m.Rcode], len(m.Answer))
	}
	ptr, ok := m.Answer[0].(*dns.PTR)
	if !ok || !strings.EqualFold(ptr.Ptr, enumerate) {
		t.Fatalf("browse PTR = %v, want %s", m.Answer[0], enumerate)
	}

	// Step 2: enumerate -> the instance, with SRV+TXT in ADDITIONAL so a
	// conforming client needs no third round trip (RFC 6763 §12).
	m = query(t, p, enumerate, dns.TypePTR, true)
	if len(m.Answer) != 1 {
		t.Fatalf("enumerate: answers=%d", len(m.Answer))
	}
	ptr, ok = m.Answer[0].(*dns.PTR)
	if !ok || !strings.EqualFold(ptr.Ptr, instance) {
		t.Fatalf("enumerate PTR = %v, want %s", m.Answer[0], instance)
	}
	var sawSRV, sawTXT bool
	for _, rr := range m.Extra {
		switch rr.(type) {
		case *dns.SRV:
			sawSRV = true
		case *dns.TXT:
			sawTXT = true
		}
	}
	if !sawSRV || !sawTXT {
		t.Errorf("additional section lacks SRV/TXT hint (srv=%v txt=%v); a client would need an extra round trip", sawSRV, sawTXT)
	}

	// Step 3: the instance itself.
	m = query(t, p, instance, dns.TypeSRV, true)
	if len(m.Answer) == 0 {
		t.Fatal("instance SRV: no answer")
	}
	if _, ok := m.Answer[0].(*dns.SRV); !ok {
		t.Errorf("instance SRV answer = %T", m.Answer[0])
	}
	m = query(t, p, instance, dns.TypeTXT, true)
	if len(m.Answer) == 0 {
		t.Fatal("instance TXT: no answer")
	}
}

// TestDNSSDWrongTypeIsNODATA — a client asking SRV at the enumerate level made a
// type mistake; the name exists, so NXDOMAIN would be wrong.
func TestDNSSDWrongTypeIsNODATA(t *testing.T) {
	p := newTestProbe(t, false)
	_, enumerate, _ := p.dnssdNames("deadbeef")

	m := query(t, p, enumerate, dns.TypeSRV, true)
	if m.Rcode != dns.RcodeSuccess {
		t.Errorf("Rcode = %s, want NOERROR/NODATA", dns.RcodeToString[m.Rcode])
	}
	if len(m.Answer) != 0 {
		t.Errorf("answers=%d, want 0", len(m.Answer))
	}
	if len(m.Ns) == 0 {
		t.Error("NODATA should carry the SOA")
	}
}

// TestDNSSDIsObserved — the walk is only a measurement if it is recorded, and each
// level must be attributable to the same visitor.
func TestDNSSDIsObserved(t *testing.T) {
	p := newTestProbe(t, false)
	browse, enumerate, instance := p.dnssdNames("deadbeef")

	query(t, p, browse, dns.TypePTR, true)
	query(t, p, enumerate, dns.TypePTR, true)
	query(t, p, instance, dns.TypeSRV, true)

	obs, err := p.Store.Lookup("deadbeef")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if len(obs) != 3 {
		t.Fatalf("recorded %d observations, want 3 (one per level)", len(obs))
	}
	want := []string{"PTR", "PTR", "SRV"}
	for i, w := range want {
		if obs[i].Qtype != w {
			t.Errorf("observation %d Qtype = %q, want %q", i, obs[i].Qtype, w)
		}
	}
}

// TestDNSSDPacksOnTheWire — PTR/SRV/TXT plus an additional section is where a
// malformed name or an over-long TXT string would surface.
func TestDNSSDPacksOnTheWire(t *testing.T) {
	p := newTestProbe(t, false)
	_, enumerate, _ := p.dnssdNames("deadbeef")

	m := query(t, p, enumerate, dns.TypePTR, true)
	wire, err := m.Pack()
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	var got dns.Msg
	if err := got.Unpack(wire); err != nil {
		t.Fatalf("Unpack: %v", err)
	}
	if len(got.Answer) != 1 {
		t.Errorf("answer did not survive the round trip")
	}
}

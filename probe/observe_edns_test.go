package probe

import (
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// query builds a minimal probe query carrying the given EDNS state. Nil opt
// means no OPT record at all, which is a distinct case from an OPT with no
// options set.
func ednsQuery(opt *dns.OPT) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion("deadbeef.check.example.com.", dns.TypeTXT)
	if opt != nil {
		m.Extra = append(m.Extra, opt)
	}
	return m
}

func newOpt() *dns.OPT {
	o := new(dns.OPT)
	o.Hdr.Name = "."
	o.Hdr.Rrtype = dns.TypeOPT
	o.SetUDPSize(1232)
	return o
}

func observeWith(t *testing.T, m *dns.Msg) Observation {
	t.Helper()
	return Observe(
		Query{Token: "deadbeef"},
		"deadbeef.check.example.com.",
		netip.MustParseAddr("192.0.2.53"),
		TransportUDP,
		dns.TypeTXT,
		m,
	)
}

// TestEDNSFlagBits pins the DO/CO/DE bit positions. These are masked by hand
// off OPT.Hdr.Ttl because miekg/dns exposes an accessor only for DO, so a wrong
// mask would produce a plausible-looking but false measurement rather than a
// compile error — exactly what this test exists to prevent.
func TestEDNSFlagBits(t *testing.T) {
	for _, tc := range []struct {
		name          string
		ttl           uint32
		do, co, deleg bool
	}{
		{name: "no flags"},
		// DO is the one bit with a library accessor, so it doubles as proof the
		// hand-rolled masks are reading the same field Do() reads.
		{name: "DO only", ttl: 1 << 15, do: true},
		{name: "CO only", ttl: 1 << 14, co: true},
		{name: "DE only", ttl: 1 << 13, deleg: true},
		{name: "DO+CO+DE", ttl: 1<<15 | 1<<14 | 1<<13, do: true, co: true, deleg: true},
		// Adjacent bits must not bleed into CO/DE. Bit 3 is reserved (Z).
		{name: "reserved Z bit only", ttl: 1 << 12},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := newOpt()
			o.Hdr.Ttl |= tc.ttl
			obs := observeWith(t, ednsQuery(o))

			if obs.DO != tc.do {
				t.Errorf("DO = %v, want %v", obs.DO, tc.do)
			}
			if obs.CompactAware != tc.co {
				t.Errorf("CompactAware (CO) = %v, want %v", obs.CompactAware, tc.co)
			}
			if obs.DELEGAware != tc.deleg {
				t.Errorf("DELEGAware (DE) = %v, want %v", obs.DELEGAware, tc.deleg)
			}
		})
	}
}

// TestEDNSAbsentIsNotFalse guards the distinction the web tier depends on: a
// resolver that sent no OPT at all has not told us it is DELEG-unaware, it has
// told us nothing. EDNS=false is what carries that, and every flag must read
// false rather than being left indeterminate.
func TestEDNSAbsentIsNotFalse(t *testing.T) {
	obs := observeWith(t, ednsQuery(nil))
	if obs.EDNS {
		t.Fatal("EDNS = true for a query with no OPT record")
	}
	for name, got := range map[string]bool{
		"DO": obs.DO, "CompactAware": obs.CompactAware,
		"DELEGAware": obs.DELEGAware, "ECS": obs.ECS,
	} {
		if got {
			t.Errorf("%s = true with no OPT record", name)
		}
	}
}

// TestECSThreeStates is the core of the ECS work. RFC 7871 §7.1.2 lets a
// resolver send the option with SOURCE PREFIX-LENGTH 0 to say "deliberately
// disclosing nothing", which is the OPPOSITE finding from disclosing a prefix —
// and a bare ecs=true/false flag cannot tell the two apart.
func TestECSThreeStates(t *testing.T) {
	t.Run("absent", func(t *testing.T) {
		obs := observeWith(t, ednsQuery(newOpt()))
		if obs.ECS {
			t.Error("ECS = true with no SUBNET option")
		}
		if obs.ECSPrefix.IsValid() {
			t.Errorf("ECSPrefix = %v, want zero", obs.ECSPrefix)
		}
	})

	t.Run("declined: option present, source netmask 0", func(t *testing.T) {
		o := newOpt()
		o.Option = append(o.Option, &dns.EDNS0_SUBNET{
			Family: 1, SourceNetmask: 0, Address: net.ParseIP("0.0.0.0"),
		})
		obs := observeWith(t, ednsQuery(o))

		if !obs.ECS {
			t.Error("ECS = false, want true: the resolver did send the option")
		}
		if obs.ECSScope != 0 {
			t.Errorf("ECSScope = %d, want 0", obs.ECSScope)
		}
		// The critical assertion: a declined disclosure must NOT become a 0-bit
		// prefix, which would render as "leaked 0.0.0.0/0" — i.e. everything.
		if obs.ECSPrefix.IsValid() {
			t.Errorf("ECSPrefix = %v for a declined disclosure, want zero", obs.ECSPrefix)
		}
	})

	t.Run("disclosed", func(t *testing.T) {
		o := newOpt()
		o.Option = append(o.Option, &dns.EDNS0_SUBNET{
			Family: 1, SourceNetmask: 24, Address: net.ParseIP("198.51.100.42"),
		})
		obs := observeWith(t, ednsQuery(o))

		if !obs.ECS || obs.ECSScope != 24 || obs.ECSFamily != 1 {
			t.Errorf("ECS=%v scope=%d family=%d; want true/24/1", obs.ECS, obs.ECSScope, obs.ECSFamily)
		}
		if got, want := obs.ECSPrefix.String(), "198.51.100.0/24"; got != want {
			t.Errorf("ECSPrefix = %s, want %s", got, want)
		}
	})

	t.Run("disclosed IPv6", func(t *testing.T) {
		o := newOpt()
		o.Option = append(o.Option, &dns.EDNS0_SUBNET{
			Family: 2, SourceNetmask: 56, Address: net.ParseIP("2001:db8:dead:beef::1"),
		})
		obs := observeWith(t, ednsQuery(o))

		if obs.ECSFamily != 2 {
			t.Errorf("ECSFamily = %d, want 2", obs.ECSFamily)
		}
		if got, want := obs.ECSPrefix.String(), "2001:db8:dead:be00::/56"; got != want {
			t.Errorf("ECSPrefix = %s, want %s", got, want)
		}
	})
}

// TestECSMalformedDoesNotPanicOrLie feeds a SOURCE PREFIX-LENGTH wider than the
// family permits. A resolver can send this; it must cost neither a panic nor a
// fabricated prefix, and the fact that ECS was present must still be recorded.
func TestECSMalformedDoesNotPanicOrLie(t *testing.T) {
	o := newOpt()
	o.Option = append(o.Option, &dns.EDNS0_SUBNET{
		Family: 1, SourceNetmask: 99, Address: net.ParseIP("198.51.100.42"),
	})
	obs := observeWith(t, ednsQuery(o))

	if !obs.ECS {
		t.Error("ECS = false; the option was present even though malformed")
	}
	if obs.ECSPrefix.IsValid() {
		t.Errorf("ECSPrefix = %v from a malformed netmask, want zero", obs.ECSPrefix)
	}
}

// TestSummaryCarriesAllThreeECSStates checks the in-band TXT readout, which is
// what a bare `dig` user sees. It has to preserve the declined/leaked
// distinction too, not just the JSON.
func TestSummaryCarriesAllThreeECSStates(t *testing.T) {
	mk := func(o *dns.OPT) string { return observeWith(t, ednsQuery(o)).Summary() }

	absent := mk(newOpt())
	if !strings.Contains(absent, "ecs=0 ecs_src=0") {
		t.Errorf("absent summary lacks ecs=0 ecs_src=0: %s", absent)
	}
	if strings.Contains(absent, "ecs_prefix=") {
		t.Errorf("absent summary should not carry ecs_prefix: %s", absent)
	}

	declined := newOpt()
	declined.Option = append(declined.Option, &dns.EDNS0_SUBNET{
		Family: 1, SourceNetmask: 0, Address: net.ParseIP("0.0.0.0"),
	})
	d := mk(declined)
	if !strings.Contains(d, "ecs=1 ecs_src=0") {
		t.Errorf("declined summary lacks ecs=1 ecs_src=0: %s", d)
	}
	if strings.Contains(d, "ecs_prefix=") {
		t.Errorf("declined summary must not claim a leaked prefix: %s", d)
	}

	leaked := newOpt()
	leaked.Option = append(leaked.Option, &dns.EDNS0_SUBNET{
		Family: 1, SourceNetmask: 24, Address: net.ParseIP("198.51.100.42"),
	})
	l := mk(leaked)
	for _, want := range []string{"ecs=1", "ecs_src=24", "ecs_prefix=198.51.100.0/24"} {
		if !strings.Contains(l, want) {
			t.Errorf("leaked summary lacks %q: %s", want, l)
		}
	}
}

// TestSummaryCarriesFlagBits keeps the terminal readout in step with the JSON
// for the two new flags.
func TestSummaryCarriesFlagBits(t *testing.T) {
	o := newOpt()
	o.Hdr.Ttl |= 1<<14 | 1<<13 // CO + DE
	s := observeWith(t, ednsQuery(o)).Summary()
	for _, want := range []string{"co=1", "deleg=1"} {
		if !strings.Contains(s, want) {
			t.Errorf("summary lacks %q: %s", want, s)
		}
	}

	s = observeWith(t, ednsQuery(newOpt())).Summary()
	for _, want := range []string{"co=0", "deleg=0"} {
		if !strings.Contains(s, want) {
			t.Errorf("summary lacks %q: %s", want, s)
		}
	}
}

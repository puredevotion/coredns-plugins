package radnr

import (
	"strings"
	"testing"

	"github.com/coredns/caddy"
)

func TestSetup_Happy(t *testing.T) {
	cfg := `radnr {
		interface eth0
		adn dns.example.com
		addr fde3:6ad1:6501::240
		alpn dot doq
		port 853
		dohpath /dns-query{?dns}
	}`
	c := caddy.NewTestController("dns", cfg)
	if err := setup(c); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestSetup_DryRunAndUnicast(t *testing.T) {
	cfg := `radnr {
		interface eth0
		adn dns.example.com
		addr fde3:6ad1:6501::240
		dry-run
		unicast fe80::99
		rdnss
	}`
	c := caddy.NewTestController("dns", cfg)
	if err := setup(c); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestSetup_MinimalRequiredOnly(t *testing.T) {
	cfg := `radnr {
		interface eth0
		adn dns.example.com
		addr fde3:6ad1:6501::240
	}`
	c := caddy.NewTestController("dns", cfg)
	if err := setup(c); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestSetup_ParseErrors(t *testing.T) {
	cases := []struct {
		name string
		cfg  string
	}{
		{"missing interface", `radnr { adn dns.example.com
			addr fde3:6ad1:6501::240 }`},
		{"missing adn", `radnr { interface eth0
			addr fde3:6ad1:6501::240 }`},
		{"missing addr", `radnr { interface eth0
			adn dns.example.com }`},
		{"ipv4 addr rejected", `radnr { interface eth0
			adn dns.example.com
			addr 192.0.2.1 }`},
		{"unknown property", `radnr { interface eth0
			adn dns.example.com
			addr fde3:6ad1:6501::240
			bogus value }`},
		{"interface no arg", `radnr { interface }`},
		{"port not a number", `radnr { interface eth0
			adn dns.example.com
			addr fde3:6ad1:6501::240
			port notanumber }`},
		{"router-lifetime nonzero without override", `radnr { interface eth0
			adn dns.example.com
			addr fde3:6ad1:6501::240
			router-lifetime 1800 }`},
		{"advertise-prefix forbidden", `radnr { interface eth0
			adn dns.example.com
			addr fde3:6ad1:6501::240
			advertise-prefix fde3:6ad1:6501::/64 }`},
		{"bare directive (no block, missing required)", `radnr`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := caddy.NewTestController("dns", tc.cfg)
			if err := setup(c); err == nil {
				t.Fatalf("expected error for %s, got nil", tc.name)
			} else if !strings.Contains(err.Error(), "radnr") {
				t.Fatalf("error should be wrapped with plugin name: %v", err)
			}
		})
	}
}

func TestSetup_RouterLifetimeOverride(t *testing.T) {
	cfg := `radnr {
		interface eth0
		adn dns.example.com
		addr fde3:6ad1:6501::240
		router-lifetime 1800
		allow-default-router
	}`
	c := caddy.NewTestController("dns", cfg)
	if err := setup(c); err != nil {
		t.Fatalf("override should allow nonzero router-lifetime: %v", err)
	}
}

func TestSetup_ArgErrorsPerProperty(t *testing.T) {
	// Each property that takes an arg must error when the arg is missing. Each
	// case is a single-property block so the failing line is that property's
	// ArgErr (not a downstream Validate error).
	cases := []string{
		`radnr { interface }`,
		`radnr { adn }`,
		`radnr { addr }`,
		`radnr { alpn }`,
		`radnr { port }`,
		`radnr { dohpath }`,
		`radnr { unicast }`,
		`radnr { router-lifetime }`,
		`radnr { advertise-prefix }`,
		// flags that take NO arg must error when given one
		`radnr { rdnss extra }`,
		`radnr { dry-run extra }`,
		`radnr { allow-default-router extra }`,
	}
	for _, cfg := range cases {
		t.Run(cfg, func(t *testing.T) {
			c := caddy.NewTestController("dns", cfg)
			if err := setup(c); err == nil {
				t.Fatalf("expected error for %q", cfg)
			}
		})
	}
}

func TestSetup_MultipleAddrs(t *testing.T) {
	cfg := `radnr {
		interface eth0
		adn dns.example.com
		addr fde3:6ad1:6501::240 fde3:6ad1:6501::241
	}`
	c := caddy.NewTestController("dns", cfg)
	if err := setup(c); err != nil {
		t.Fatalf("multiple addrs should parse: %v", err)
	}
}

func TestSetup_AllPropertiesParsed(t *testing.T) {
	cfg := `radnr {
		interface eth0
		adn dns.example.com
		addr fde3:6ad1:6501::240
		alpn dot doq h2 h3
		port 853
		dohpath /dns-query{?dns}
		unicast fe80::99
		rdnss
	}`
	c := caddy.NewTestController("dns", cfg)
	if err := setup(c); err != nil {
		t.Fatalf("all-properties config should parse: %v", err)
	}
}

func TestSetup_EmptyRemainingArgs(t *testing.T) {
	// Properties using RemainingArgs must error on zero args.
	cases := []string{
		`radnr {
			interface eth0
			adn dns.example.com
			alpn
		}`,
	}
	for _, cfg := range cases {
		c := caddy.NewTestController("dns", cfg)
		if err := setup(c); err == nil {
			t.Fatalf("expected error for empty RemainingArgs: %q", cfg)
		}
	}
}

func TestSetup_PortAndDohpathAndUnicastHappy(t *testing.T) {
	// Drives the success branches of port/dohpath/unicast parsing.
	cfg := `radnr {
		interface eth0
		adn dns.example.com
		addr fde3:6ad1:6501::240
		port 443
		dohpath /q
		unicast fe80::1
	}`
	c := caddy.NewTestController("dns", cfg)
	if err := setup(c); err != nil {
		t.Fatalf("happy port/dohpath/unicast parse: %v", err)
	}
}

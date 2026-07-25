package config

import "testing"

func validBase() Config {
	return Config{
		Interface: "eth0",
		ADN:       "dns.example.com",
		Addrs:     []string{"fde3:6ad1:6501::240"},
		ALPN:      []string{"dot", "doq"},
		Port:      853,
	}
}

func TestValidate_Happy(t *testing.T) {
	c := validBase()
	if err := c.Validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	if c.RouterLifetime != 0 {
		t.Fatalf("RouterLifetime default must be 0, got %d", c.RouterLifetime)
	}
}

func TestValidate_SafetyInvariants(t *testing.T) {
	t.Run("nonzero RouterLifetime rejected without override", func(t *testing.T) {
		c := validBase()
		c.RouterLifetime = 1800
		if err := c.Validate(); err == nil {
			t.Fatalf("nonzero RouterLifetime must be rejected without explicit override")
		}
	})
	t.Run("nonzero RouterLifetime allowed with override", func(t *testing.T) {
		c := validBase()
		c.RouterLifetime = 1800
		c.AllowDefaultRouter = true
		if err := c.Validate(); err != nil {
			t.Fatalf("override should allow nonzero RouterLifetime: %v", err)
		}
	})
	t.Run("prefix advertisement rejected", func(t *testing.T) {
		c := validBase()
		c.AdvertisePrefixes = []string{"fde3:6ad1:6501::/64"}
		if err := c.Validate(); err == nil {
			t.Fatalf("advertising prefixes must be rejected (never touch SLAAC)")
		}
	})
}

func TestValidate_FieldErrors(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*Config)
	}{
		{"empty interface", func(c *Config) { c.Interface = "" }},
		{"empty ADN", func(c *Config) { c.ADN = "" }},
		{"bad ADN", func(c *Config) { c.ADN = "no spaces allowed!" }},
		{"no addrs", func(c *Config) { c.Addrs = nil }},
		{"ipv4 addr", func(c *Config) { c.Addrs = []string{"192.0.2.1"} }},
		{"malformed addr", func(c *Config) { c.Addrs = []string{"not-an-ip"} }},
		{"bad unicast target", func(c *Config) { c.UnicastTarget = "nope" }},
		{"ipv4 unicast target", func(c *Config) { c.UnicastTarget = "192.0.2.2" }},
		{"empty alpn id", func(c *Config) { c.ALPN = []string{""} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := validBase()
			tc.mut(&c)
			if err := c.Validate(); err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
		})
	}
}

func TestValidate_UnicastTargetHappy(t *testing.T) {
	c := validBase()
	c.UnicastTarget = "fe80::1"
	if err := c.Validate(); err != nil {
		t.Fatalf("valid unicast target rejected: %v", err)
	}
}

func TestValidate_DryRunIsValid(t *testing.T) {
	c := validBase()
	c.DryRun = true
	if err := c.Validate(); err != nil {
		t.Fatalf("dry-run config rejected: %v", err)
	}
}

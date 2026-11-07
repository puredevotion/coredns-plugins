package geoscore

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestValidateAcceptsTestConfig(t *testing.T) {
	c := testConfig(t)
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	c.RationaleTXT, c.Mode, c.Fallback = true, ModeWeighted, FallbackNodata
	c.Zone = "."
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}

// Every rule of R13 and R22 has a rejecting case.
func TestValidateRejects(t *testing.T) {
	for name, mutate := range map[string]func(*Config){
		"relative name":       func(c *Config) { c.Name = "www.example.com" },
		"root name":           func(c *Config) { c.Name, c.Zone = ".", "." },
		"uppercase name":      func(c *Config) { c.Name = "WWW.example.com." },
		"outside zone":        func(c *Config) { c.Name = "www.example.net." },
		"label too long":      func(c *Config) { c.Name = strings.Repeat("a", 64) + ".example.com." },
		"no endpoints":        func(c *Config) { c.Endpoints = nil },
		"too many endpoints":  func(c *Config) { c.Endpoints = manyEndpoints(t, maxEndpoints+1) },
		"duplicate id":        func(c *Config) { c.Endpoints[1].ID = eu1 },
		"bad id":              func(c *Config) { c.Endpoints[0].ID = "EU1" },
		"id leading dash":     func(c *Config) { c.Endpoints[0].ID = "-eu" },
		"id too long":         func(c *Config) { c.Endpoints[0].ID = strings.Repeat("a", maxIDLen+1) },
		"no addresses":        func(c *Config) { c.Endpoints[0].Addrs = nil },
		"shared address":      func(c *Config) { c.Endpoints[1].Addrs = addrs(t, "192.0.2.1") },
		"mapped address":      func(c *Config) { c.Endpoints[0].Addrs = addrs(t, "::ffff:192.0.2.9") },
		"unspecified":         func(c *Config) { c.Endpoints[0].Addrs = addrs(t, "0.0.0.0") },
		"multicast":           func(c *Config) { c.Endpoints[0].Addrs = addrs(t, "ff02::1") },
		"loopback":            func(c *Config) { c.Endpoints[0].Addrs = addrs(t, "127.0.0.1") },
		"zoned":               func(c *Config) { c.Endpoints[0].Addrs = addrs(t, "fe80::1%eth0") },
		"invalid address":     func(c *Config) { c.Endpoints[0].Addrs = []netip.Addr{{}} },
		"empty key":           func(c *Config) { c.KeyPrefix = "" },
		"key with space":      func(c *Config) { c.KeyPrefix = "geo score" },
		"key too long":        func(c *Config) { c.KeyPrefix = strings.Repeat("k", maxKeyPrefixLen+1) },
		"ttl over staleness":  func(c *Config) { c.MaxStaleness, c.TTL = 10*time.Second, 11 },
		"staleness too small": func(c *Config) { c.MaxStaleness = 500 * time.Millisecond },
		"staleness too big":   func(c *Config) { c.MaxStaleness = 25 * time.Hour },
		"staleness fraction":  func(c *Config) { c.MaxStaleness = 1500 * time.Millisecond },
		"refresh too small":   func(c *Config) { c.Refresh = time.Millisecond },
		"refresh over stale":  func(c *Config) { c.Refresh = c.MaxStaleness + time.Second },
		"timeout zero":        func(c *Config) { c.Timeout = 0 },
		"timeout too big":     func(c *Config) { c.Timeout = time.Minute },
		"mode":                func(c *Config) { c.Mode = 7 },
		"fallback":            func(c *Config) { c.Fallback = 7 },
	} {
		c := testConfig(t)
		mutate(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: accepted %+v", name, c)
		}
		if _, err := New(c, NewMemStore()); err == nil {
			t.Errorf("%s: New accepted what Validate rejects", name)
		}
	}
}

func TestValidateRationaleNameLength(t *testing.T) {
	c := testConfig(t)
	// 250 characters: fits as a name, not with "_geoscore." in front.
	long := strings.Repeat(strings.Repeat("a", 63)+".", 3) + strings.Repeat("b", 45) + ".example.com."
	c.Name = long
	if err := c.Validate(); err != nil {
		t.Fatalf("long name without rationale: %v", err)
	}
	c.RationaleTXT = true
	if err := c.Validate(); err == nil {
		t.Fatal("accepted a name whose _geoscore sibling is too long")
	}
}

func TestEightAddressesPerFamily(t *testing.T) {
	c := testConfig(t)
	c.Endpoints = c.Endpoints[:1]
	as := make([]netip.Addr, 0, maxAddrsPerFam+1)
	for i := range maxAddrsPerFam + 1 {
		as = append(as, netip.AddrFrom4([4]byte{192, 0, 2, byte(100 + i)}))
	}
	c.Endpoints[0].Addrs = as[:maxAddrsPerFam]
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	c.Endpoints[0].Addrs = as
	if err := c.Validate(); err == nil {
		t.Fatal("accepted nine IPv4 addresses")
	}
}

func TestNewRejectsNilStore(t *testing.T) {
	if _, err := New(testConfig(t), nil); err == nil {
		t.Fatal("New accepted a nil store")
	}
}

func manyEndpoints(tb testing.TB, n int) []Endpoint {
	tb.Helper()
	eps := make([]Endpoint, n)
	for i := range eps {
		eps[i] = Endpoint{
			ID:    "e" + strings.Repeat("x", i%3) + string(rune('a'+i%26)) + string(rune('a'+i/26)),
			Addrs: []netip.Addr{netip.AddrFrom4([4]byte{198, 51, 100, byte(i + 1)})},
		}
	}
	return eps
}

func TestStringers(t *testing.T) {
	for got, want := range map[string]string{
		ModeBest.String(): "best", ModeWeighted.String(): "weighted",
		FallbackStatic.String(): "static", FallbackServfail.String(): "servfail", FallbackNodata.String(): "nodata",
		famA.String(): "A", famAAAA.String(): "AAAA", stateEligible.String(): "eligible", outNodata.String(): "fallback_nodata",
	} {
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	}
	if defaultKeyPrefix(".") != "geoscore:." {
		t.Error(defaultKeyPrefix("."))
	}
}

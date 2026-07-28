// Package config holds the ra-dnr daemon configuration and its safety
// validation. The validation enforces the invariants that keep a second RA
// sender from disrupting a live LAN: RouterLifetime defaults to 0 (this is NOT
// a default router) and prefix advertisement is forbidden (never touch SLAAC).
package config

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"unicode/utf8"
)

// invalidLabelChar matches the first character NOT in the LDH (letters,
// digits, hyphen) set a DNS label may contain.
var invalidLabelChar = regexp.MustCompile(`[^0-9A-Za-z-]`)

// Config is the validated daemon configuration.
type Config struct {
	Interface string   // required: the single interface to advertise on
	ADN       string   // required: encrypted-DNS authentication domain name
	Addrs     []string // required: IPv6 addresses of the resolver
	ALPN      []string // e.g. {"dot","doq","h2","h3"}
	Port      uint16
	DohPath   string

	// AdvertiseRDNSS also includes an RFC 8106 RDNSS option (plaintext resolver
	// hint) alongside the DNR option, for clients that read RDNSS but not DNR.
	AdvertiseRDNSS bool

	// RouterLifetime is the RA Router Lifetime in seconds. MUST be 0 (default)
	// unless AllowDefaultRouter is explicitly set — a nonzero lifetime makes
	// this host a default router and can hijack LAN routing.
	RouterLifetime     uint16
	AllowDefaultRouter bool

	// AdvertisePrefixes MUST be empty — advertising prefixes would interfere
	// with the existing router's SLAAC. Present only so we can reject it loudly.
	AdvertisePrefixes []string

	// UnicastTarget, if set, sends solicited unicast RAs to this address only
	// (spike-safe mode) instead of multicast to ff02::1.
	UnicastTarget string

	// DryRun marshals and logs the RA but never transmits.
	DryRun bool
}

// Validate checks all fields and safety invariants.
func (c Config) Validate() error {
	if c.Interface == "" {
		return fmt.Errorf("config: interface is required")
	}
	if c.ADN == "" {
		return fmt.Errorf("config: ADN is required")
	}
	if err := validateADN(c.ADN); err != nil {
		return err
	}
	if len(c.Addrs) == 0 {
		return fmt.Errorf("config: at least one IPv6 address is required")
	}
	for _, a := range c.Addrs {
		addr, err := netip.ParseAddr(a)
		if err != nil {
			return fmt.Errorf("config: invalid address %q: %w", a, err)
		}
		if !addr.Is6() || addr.Is4In6() {
			return fmt.Errorf("config: address %q is not IPv6", a)
		}
	}
	for _, id := range c.ALPN {
		if id == "" {
			return fmt.Errorf("config: empty ALPN id")
		}
	}
	if c.RouterLifetime != 0 && !c.AllowDefaultRouter {
		return fmt.Errorf("config: RouterLifetime != 0 requires AllowDefaultRouter " +
			"(refusing to become a default router by default)")
	}
	if len(c.AdvertisePrefixes) != 0 {
		return fmt.Errorf("config: advertising prefixes is forbidden (would disrupt SLAAC)")
	}
	if c.UnicastTarget != "" {
		addr, err := netip.ParseAddr(c.UnicastTarget)
		if err != nil {
			return fmt.Errorf("config: invalid unicast target %q: %w", c.UnicastTarget, err)
		}
		if !addr.Is6() || addr.Is4In6() {
			return fmt.Errorf("config: unicast target %q is not IPv6", c.UnicastTarget)
		}
	}
	return nil
}

// validateADN does a light syntactic check on the domain name.
func validateADN(name string) error {
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return fmt.Errorf("config: empty ADN")
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" {
			return fmt.Errorf("config: empty label in ADN %q", name)
		}
		if loc := invalidLabelChar.FindStringIndex(label); loc != nil {
			r, _ := utf8.DecodeRuneInString(label[loc[0]:])
			return fmt.Errorf("config: invalid character %q in ADN %q", r, name)
		}
	}
	return nil
}

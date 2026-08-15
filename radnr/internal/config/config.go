// Package config holds the ra-dnr daemon configuration and its safety
// validation. The validation enforces the invariants that keep a second RA
// sender from disrupting a live LAN: RouterLifetime defaults to 0 (this is NOT
// a default router) and prefix advertisement is forbidden (never touch SLAAC).
//
//nolint:misspell // ADN throughout this file: RFC 9463 Authentication Domain Name, not a typo for AND
package config

import (
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"
)

// invalidLabelChar matches the first character NOT in the LDH (letters,
// digits, hyphen) set a DNS label may contain.
var invalidLabelChar = regexp.MustCompile(`[^0-9A-Za-z-]`)

// Config is the validated daemon configuration.
type Config struct {
	Interface string // Required: the single interface to advertise on.
	ADN       string // Required: encrypted-DNS authentication domain name.
	DohPath   string

	// UnicastTarget, if set, sends solicited unicast RAs to this address only
	// (spike-safe mode) instead of multicast to ff02::1.
	UnicastTarget string

	Addrs []string // Required: IPv6 addresses of the resolver.
	ALPN  []string // E.g. {"dot","doq","h2","h3"}.

	// AdvertisePrefixes MUST be empty — advertising prefixes would interfere
	// with the existing router's SLAAC. Present only so we can reject it loudly.
	AdvertisePrefixes []string

	Port uint16

	// RouterLifetime is the RA Router Lifetime in seconds. MUST be 0 (default)
	// unless AllowDefaultRouter is explicitly set — a nonzero lifetime makes
	// this host a default router and can hijack LAN routing.
	RouterLifetime uint16

	// AdvertiseRDNSS also includes an RFC 8106 RDNSS option (plaintext resolver
	// hint) alongside the DNR option, for clients that read RDNSS but not DNR.
	AdvertiseRDNSS bool

	AllowDefaultRouter bool

	// DryRun marshals and logs the RA but never transmits.
	DryRun bool
}

// validateAddrs checks that addrs is non-empty and every entry is a valid
// IPv6 (non-4-in-6) address.
func validateAddrs(addrs []string) error {
	if len(addrs) == 0 {
		return fmt.Errorf("config: at least one IPv6 address is required")
	}
	for _, a := range addrs {
		addr, err := netip.ParseAddr(a)
		if err != nil {
			return fmt.Errorf("config: invalid address %q: %w", a, err)
		}
		if !addr.Is6() || addr.Is4In6() {
			return fmt.Errorf("config: address %q is not IPv6", a)
		}
	}
	return nil
}

// validateUnicastTarget checks that, if set, target is a valid IPv6
// (non-4-in-6) address.
func validateUnicastTarget(target string) error {
	if target == "" {
		return nil
	}
	addr, err := netip.ParseAddr(target)
	if err != nil {
		return fmt.Errorf("config: invalid unicast target %q: %w", target, err)
	}
	if !addr.Is6() || addr.Is4In6() {
		return fmt.Errorf("config: unicast target %q is not IPv6", target)
	}
	return nil
}

// Validate checks all fields and safety invariants.
func (c *Config) Validate() error {
	if c.Interface == "" {
		return fmt.Errorf("config: interface is required")
	}
	if c.ADN == "" {
		return fmt.Errorf("config: ADN is required")
	}
	if err := validateADN(c.ADN); err != nil {
		return err
	}
	if err := validateAddrs(c.Addrs); err != nil {
		return err
	}
	if slices.Contains(c.ALPN, "") {
		return fmt.Errorf("config: empty ALPN id")
	}
	if c.RouterLifetime != 0 && !c.AllowDefaultRouter {
		return fmt.Errorf("config: RouterLifetime != 0 requires AllowDefaultRouter " +
			"(refusing to become a default router by default)")
	}
	if len(c.AdvertisePrefixes) != 0 {
		return fmt.Errorf("config: advertising prefixes is forbidden (would disrupt SLAAC)")
	}
	return validateUnicastTarget(c.UnicastTarget)
}

// validateADN does a light syntactic check on the domain name.
func validateADN(name string) error {
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return fmt.Errorf("config: empty ADN")
	}
	for label := range strings.SplitSeq(name, ".") {
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

package geoscore

import (
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/miekg/dns"
)

// Mode is how an endpoint is chosen among the eligible ones (docs/geoscore-plugin.md R18, R19).
type Mode uint8

const (
	// ModeBest answers the eligible endpoint with the highest score; on a tie,
	// the one listed first.
	ModeBest Mode = iota
	// ModeWeighted answers an eligible endpoint at random, with probability
	// proportional to its score.
	ModeWeighted
)

func (m Mode) String() string {
	if m == ModeWeighted {
		return modeWeighted
	}
	return modeBest
}

// Fallback is what to answer when no endpoint is eligible (R20).
type Fallback uint8

const (
	// FallbackStatic answers the first-listed endpoint of the family, the
	// address the name would have without this plugin.
	FallbackStatic Fallback = iota
	// FallbackServfail answers SERVFAIL (RFC 1035 §4.1.1).
	FallbackServfail
	// FallbackNodata answers NOERROR with no answer and the zone's SOA in the
	// authority section (RFC 2308 §2.2, §3).
	FallbackNodata
)

func (f Fallback) String() string {
	switch f {
	case FallbackServfail:
		return "servfail"
	case FallbackNodata:
		return "nodata"
	case FallbackStatic:
	}
	return "static"
}

// Bounds of the configuration (R13, R22, R25).
const (
	maxEndpoints     = 16
	maxAddrsPerFam   = 8
	maxIDLen         = 32
	maxKeyPrefixLen  = 64
	minMaxStaleness  = time.Second
	maxMaxStaleness  = 24 * time.Hour
	minRefresh       = 100 * time.Millisecond
	minTimeout       = time.Millisecond
	maxTimeout       = 5 * time.Second
	defaultStaleness = 5 * time.Minute
	defaultTTL       = 30
	defaultRefresh   = time.Second
	defaultTimeout   = 100 * time.Millisecond
	// The underscored leaf the TXT sibling lives at (RFC 8552 §1.1).
	rationaleLabel = "_geoscore."
)

// Endpoint is one candidate: an identifier, which is also its key suffix in
// the store, and the addresses answered when it is chosen.
type Endpoint struct {
	ID    string
	Addrs []netip.Addr
}

// Config is one `geoscore NAME { ... }` block. Validate is the only gate:
// New refuses a Config it rejects, and the Corefile parser builds a Config and
// calls New, so no instance exists with an illegal configuration.
type Config struct {
	// Name is the owner name answered, fully qualified, lowercase.
	Name string
	// Zone is the server block's zone. Name must be at or below it, and the
	// NODATA fallback asks the next plugin for its SOA.
	Zone string
	// KeyPrefix: the entry for endpoint ID is at KeyPrefix + ":" + ID.
	KeyPrefix string
	// Endpoints is the candidate set, in tie-break order.
	Endpoints    []Endpoint
	MaxStaleness time.Duration
	Refresh      time.Duration
	Timeout      time.Duration
	TTL          uint32
	Mode         Mode
	Fallback     Fallback
	RationaleTXT bool
}

// DefaultConfig returns the defaults the Corefile starts from.
func DefaultConfig(name, zone string) Config {
	return Config{
		Name:         name,
		Zone:         zone,
		KeyPrefix:    defaultKeyPrefix(name),
		MaxStaleness: defaultStaleness,
		Refresh:      defaultRefresh,
		Timeout:      defaultTimeout,
		TTL:          defaultTTL,
		Mode:         ModeBest,
		Fallback:     FallbackStatic,
	}
}

// defaultKeyPrefix is "geoscore:" plus the name without its trailing dot.
func defaultKeyPrefix(name string) string {
	if n := len(name); n > 1 && name[n-1] == '.' {
		name = name[:n-1]
	}
	return "geoscore:" + name
}

const (
	modeBest     = "best"
	modeWeighted = "weighted"
)

var (
	errNoEndpoints = errors.New("geoscore: at least one endpoint is required")
	errMode        = errors.New("geoscore: unknown mode")
	errFallback    = errors.New("geoscore: unknown fallback")
)

// Validate reports whether c is a configuration the plugin can serve.
func (c *Config) Validate() error {
	if err := validateName(c.Name, c.Zone, c.RationaleTXT); err != nil {
		return err
	}
	if err := validateKeyPrefix(c.KeyPrefix); err != nil {
		return err
	}
	if err := validateTimes(c); err != nil {
		return err
	}
	if c.Mode > ModeWeighted {
		return errMode
	}
	if c.Fallback > FallbackNodata {
		return errFallback
	}
	return validateEndpoints(c.Endpoints)
}

func validateName(name, zone string, rationale bool) error {
	if !isLowerFQDN(name) || name == "." {
		return fmt.Errorf("geoscore: name %q must be a lowercase, fully qualified, non-root domain name", name)
	}
	if !isLowerFQDN(zone) {
		return fmt.Errorf("geoscore: zone %q must be a lowercase, fully qualified domain name", zone)
	}
	if !dns.IsSubDomain(zone, name) {
		return fmt.Errorf("geoscore: name %s is not inside the server block's zone %s", name, zone)
	}
	if rationale {
		if _, ok := dns.IsDomainName(rationaleLabel + name); !ok || len(rationaleLabel)+len(name) > 255 {
			return fmt.Errorf("geoscore: %s%s is too long for the rationale TXT name", rationaleLabel, name)
		}
	}
	return nil
}

// isLowerFQDN: a valid, fully qualified name, with no ASCII uppercase (the
// handler compares names folding ASCII case only, RFC 4343 §3).
func isLowerFQDN(s string) bool {
	if !dns.IsFqdn(s) {
		return false
	}
	if _, ok := dns.IsDomainName(s); !ok {
		return false
	}
	for i := range len(s) {
		if c := s[i]; c >= 'A' && c <= 'Z' {
			return false
		}
	}
	return true
}

func validateKeyPrefix(p string) error {
	if p == "" || len(p) > maxKeyPrefixLen {
		return fmt.Errorf("geoscore: key prefix must be 1 to %d bytes", maxKeyPrefixLen)
	}
	for i := range len(p) {
		c := p[i]
		if !isAlnum(c) && c != ':' && c != '.' && c != '_' && c != '-' {
			return fmt.Errorf("geoscore: key prefix %q: only letters, digits and : . _ - are allowed", p)
		}
	}
	return nil
}

func validateTimes(c *Config) error {
	if c.MaxStaleness < minMaxStaleness || c.MaxStaleness > maxMaxStaleness || c.MaxStaleness%time.Second != 0 {
		return fmt.Errorf("geoscore: max-staleness %v must be whole seconds in [%v, %v]", c.MaxStaleness, minMaxStaleness, maxMaxStaleness)
	}
	// R22: an answer is cached no longer than a score may age.
	if time.Duration(c.TTL)*time.Second > c.MaxStaleness {
		return fmt.Errorf("geoscore: ttl %d exceeds max-staleness %v", c.TTL, c.MaxStaleness)
	}
	if c.Refresh < minRefresh || c.Refresh > c.MaxStaleness {
		return fmt.Errorf("geoscore: refresh %v must be in [%v, max-staleness]", c.Refresh, minRefresh)
	}
	if c.Timeout < minTimeout || c.Timeout > maxTimeout {
		return fmt.Errorf("geoscore: timeout %v must be in [%v, %v]", c.Timeout, minTimeout, maxTimeout)
	}
	return nil
}

func validateEndpoints(eps []Endpoint) error {
	if len(eps) == 0 {
		return errNoEndpoints
	}
	if len(eps) > maxEndpoints {
		return fmt.Errorf("geoscore: at most %d endpoints, got %d", maxEndpoints, len(eps))
	}
	ids := make(map[string]struct{}, len(eps))
	addrs := map[netip.Addr]string{}
	for _, ep := range eps {
		if err := ValidateID(ep.ID); err != nil {
			return err
		}
		if _, dup := ids[ep.ID]; dup {
			return fmt.Errorf("geoscore: endpoint %s listed twice", ep.ID)
		}
		ids[ep.ID] = struct{}{}
		if err := validateAddrs(ep, addrs); err != nil {
			return err
		}
	}
	return nil
}

func validateAddrs(ep Endpoint, seen map[netip.Addr]string) error {
	if len(ep.Addrs) == 0 {
		return fmt.Errorf("geoscore: endpoint %s has no addresses", ep.ID)
	}
	var n4, n6 int
	for _, a := range ep.Addrs {
		if err := validateAddr(a); err != nil {
			return fmt.Errorf("geoscore: endpoint %s: %w", ep.ID, err)
		}
		if other, dup := seen[a]; dup {
			return fmt.Errorf("geoscore: address %s is in both %s and %s", a, other, ep.ID)
		}
		seen[a] = ep.ID
		if a.Is4() {
			n4++
		} else {
			n6++
		}
	}
	if n4 > maxAddrsPerFam || n6 > maxAddrsPerFam {
		return fmt.Errorf("geoscore: endpoint %s: at most %d addresses per family", ep.ID, maxAddrsPerFam)
	}
	return nil
}

// validateAddr accepts a unicast address an A or AAAA record can carry
// (RFC 1035 §3.4.1, RFC 3596 §2.2). An IPv4-mapped IPv6 address is refused:
// it would be answered as AAAA for what is an IPv4 endpoint.
func validateAddr(a netip.Addr) error {
	switch {
	case !a.IsValid():
		return errors.New("invalid address")
	case a.Zone() != "":
		return fmt.Errorf("address %s has a zone", a)
	case a.Is4In6():
		return fmt.Errorf("address %s is IPv4-mapped; write it as IPv4", a)
	case a.IsUnspecified(), a.IsMulticast(), a.IsLoopback():
		return fmt.Errorf("address %s is not a unicast endpoint address", a)
	}
	return nil
}

// ValidateID accepts an endpoint identifier: 1 to 32 of [a-z0-9-], starting
// with a letter or digit. It is a store key suffix and appears in the
// rationale TXT, so it is kept to characters that need no escaping in either.
func ValidateID(id string) error {
	if id == "" || len(id) > maxIDLen {
		return fmt.Errorf("geoscore: endpoint id %q must be 1 to %d characters", id, maxIDLen)
	}
	for i := range len(id) {
		c := id[i]
		if !isLowerAlnum(c) && (c != '-' || i == 0) {
			return fmt.Errorf("geoscore: endpoint id %q: only a-z, 0-9 and '-' (not first)", id)
		}
	}
	return nil
}

func isLowerAlnum(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') }

func isAlnum(c byte) bool { return isLowerAlnum(c) || (c >= 'A' && c <= 'Z') }

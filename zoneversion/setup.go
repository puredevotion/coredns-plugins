package zoneversion

import (
	"errors"
	"fmt"
	"slices"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/miekg/dns"
)

func init() { plugin.Register(pluginName, setup) }

func setup(c *caddy.Controller) error {
	zones, err := parse(c)
	if err != nil {
		return plugin.Error(pluginName, err) //nolint:wrapcheck // plugin.Error is coredns's own setup-error convention
	}
	z := newZoneVersion(zones)
	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		z.Next = next
		return z
	})
	return nil
}

var (
	errBlock = errors.New("zoneversion takes no block")
	errTwice = errors.New("the zoneversion plugin may be given once per server block")
)

// parse reads `zoneversion [ZONES...]`. With no zones, the server block's
// zones are used, as file and most other plugins do. The root zone is refused
// either way: listing it would claim authority for every name the server
// answers, including what forward or a cache produced (R7, R18 in
// docs/zoneversion-plugin.md). That fails at startup, loudly, rather than
// versioning answers this server is not the source of.
func parse(c *caddy.Controller) ([]string, error) {
	if !c.Next() {
		return nil, c.ArgErr() //nolint:wrapcheck // caddy's own error
	}
	args := c.RemainingArgs()
	if c.NextBlock() {
		return nil, errBlock
	}
	if c.Next() {
		return nil, errTwice
	}

	origins := plugin.OriginsFromArgsOrServerBlock(args, c.ServerBlockKeys)
	zones := make([]string, 0, len(origins))
	for _, o := range origins {
		z, err := canonicalZone(o)
		if err != nil {
			return nil, err
		}
		if !slices.Contains(zones, z) {
			zones = append(zones, z)
		}
	}
	if len(zones) == 0 {
		return nil, errors.New("no zones")
	}
	return zones, nil
}

// canonicalZone validates a zone name and returns it lower case and fully
// qualified, the form ServeDNS compares against.
func canonicalZone(s string) (string, error) {
	if _, ok := dns.IsDomainName(s); !ok {
		return "", fmt.Errorf("zone %q: %w", s, errBadName)
	}
	z := dns.CanonicalName(s)
	if z == "." {
		return "", fmt.Errorf("zone %q: %w: list the zones this server is authoritative for", s, errRootZone)
	}
	return z, nil
}

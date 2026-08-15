package dynupdate

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/file"
	"github.com/coredns/coredns/plugin/transfer"

	"github.com/miekg/dns"
)

func init() { plugin.Register(pluginName, setup) }

func setup(c *caddy.Controller) error {
	d, err := parse(c)
	if err != nil {
		return plugin.Error(pluginName, err) //nolint:wrapcheck // plugin.Error is coredns's own setup-error convention; every plugin's setup() returns it unwrapped
	}

	cfg := dnsserver.GetConfig(c)
	cfg.AddPlugin(func(next plugin.Handler) plugin.Handler {
		d.Next = next
		// Rebuild once Next is known: the file view falls through to it for
		// names outside this zone, and a view built at parse time would carry
		// a nil Next and terminate the chain.
		d.mu.Lock()
		defer d.mu.Unlock()
		if err := d.swap(d.rrs); err != nil {
			log.Errorf("building %s: %v", d.Zone, err)
		}
		return d
	})

	c.OnStartup(func() error {
		// The transfer plugin registers itself in the same server block, so it
		// can only be found after every setup function has run.
		if t := dnsserver.GetConfig(c).Handler("transfer"); t != nil {
			if xfer, ok := t.(*transfer.Transfer); ok {
				d.Xfer = xfer
			}
		}
		return nil
	})

	return nil
}

func parse(c *caddy.Controller) (*DynUpdate, error) {
	if !c.Next() {
		return nil, c.ArgErr() //nolint:wrapcheck // caddyfile Dispenser errors are already user-facing config errors
	}

	origin, err := parseOrigin(c)
	if err != nil {
		return nil, err
	}

	d := &DynUpdate{Zone: origin}
	seed, err := parseBlock(c, d)
	if err != nil {
		return nil, err
	}

	if seed == "" {
		return nil, c.Err("a `file` seed zone is required: an UPDATE is applied to a zone, and a zone without an SOA cannot have its serial advanced or be transferred") //nolint:wrapcheck // caddyfile Dispenser errors are already user-facing config errors
	}

	rrs, err := readZone(seed, origin)
	if err != nil {
		return nil, err
	}
	if soaOf(rrs) == nil {
		return nil, fmt.Errorf("%s has no SOA at %s", seed, origin)
	}
	d.rrs = rrs

	return d, nil
}

// parseOrigin resolves the zone this block serves: the single explicit
// argument, or the server block's own zone if none was given.
func parseOrigin(c *caddy.Controller) (string, error) {
	args := c.RemainingArgs()

	var origin string
	switch len(args) {
	case 0:
		// Default to the server block's own zone, the convention every other
		// zone-serving plugin follows.
		if len(c.ServerBlockKeys) == 0 {
			return "", c.Err("no zone given and none inferable from the server block") //nolint:wrapcheck // caddyfile Dispenser errors are already user-facing config errors
		}
		origin = plugin.Host(c.ServerBlockKeys[0]).NormalizeExact()[0]
	case 1:
		origin = plugin.Host(args[0]).NormalizeExact()[0]
	default:
		// One zone per block, deliberately. Two zones would share one record
		// slice and one rebuild, so an update to either would take a lock the
		// other's readers are waiting on, and the blast radius of a bad
		// update would be both zones.
		return "", c.Err("exactly one zone per dynupdate block") //nolint:wrapcheck // caddyfile Dispenser errors are already user-facing config errors
	}

	return strings.ToLower(dns.CanonicalName(origin)), nil
}

// parseBlock reads the dynupdate block's properties into d, and returns the
// seed zone file path (empty if none was given).
func parseBlock(c *caddy.Controller, d *DynUpdate) (string, error) {
	var seed string

	for c.NextBlock() {
		switch c.Val() {
		case "file":
			if !c.NextArg() {
				return "", c.ArgErr() //nolint:wrapcheck // caddyfile Dispenser errors are already user-facing config errors
			}
			seed = c.Val()

		case "mutable":
			if err := parseMutable(c, d); err != nil {
				return "", err
			}

		default:
			return "", c.Errf("unknown property %q", c.Val()) //nolint:wrapcheck // caddyfile Dispenser errors are already user-facing config errors
		}
	}

	return seed, nil
}

// parseMutable reads the `mutable` directive's RR type allowlist into d.
func parseMutable(c *caddy.Controller, d *DynUpdate) error {
	types := c.RemainingArgs()
	if len(types) == 0 {
		return c.ArgErr() //nolint:wrapcheck // caddyfile Dispenser errors are already user-facing config errors
	}

	d.mutable = map[uint16]bool{}
	for _, t := range types {
		code, ok := dns.StringToType[strings.ToUpper(t)]
		if !ok {
			return c.Errf("unknown RR type %q", t) //nolint:wrapcheck // caddyfile Dispenser errors are already user-facing config errors
		}
		d.mutable[code] = true
	}

	return nil
}

// readZone parses a seed zone file into a flat record slice.
//
// This uses os.OpenRoot rather than a bare os.Open: the path comes from a
// config file, and this keeps a symlink inside the zone directory from
// reading something outside it.
func readZone(path, origin string) ([]dns.RR, error) {
	dir, name := filepath.Split(path)
	if name == "" {
		return nil, fmt.Errorf("zone file %q has no file component", path)
	}
	if dir == "" {
		dir = "."
	}

	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("opening zone directory %s: %w", dir, err)
	}
	defer func() {
		if cerr := root.Close(); cerr != nil {
			log.Warningf("closing zone directory %s: %v", dir, cerr)
		}
	}()

	f, err := root.Open(name)
	if err != nil {
		return nil, fmt.Errorf("opening zone file %s: %w", path, err)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil {
			log.Warningf("closing zone file %s: %v", path, cerr)
		}
	}()

	// Parsing through file.Parse rather than a bare zone parser keeps $INCLUDE
	// handling, $ORIGIN and the generate directive identical to what the
	// `file` plugin would have done with the same file.
	z, err := file.Parse(f, origin, path, 0)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}

	var rrs []dns.RR
	if z.SOA != nil {
		rrs = append(rrs, z.SOA)
	}
	rrs = append(rrs, z.NS...)
	rrs = append(rrs, z.SIGSOA...)
	rrs = append(rrs, z.SIGNS...)
	for _, e := range z.All() {
		rrs = append(rrs, e.All()...)
	}
	return rrs, nil
}

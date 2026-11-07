package geoscore

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/miekg/dns"
)

var log = clog.NewWithPlugin(pluginName)

// propEndpoint is the one property that may repeat.
const propEndpoint = "endpoint"

func init() { plugin.Register(pluginName, setup) }

func setup(c *caddy.Controller) error {
	h, err := parse(c, dnsserver.GetConfig(c).Zone)
	if err != nil {
		return plugin.Error(pluginName, err) //nolint:wrapcheck // plugin.Error is coredns's own setup-error convention
	}
	c.OnShutdown(func() error {
		errs := make([]error, 0, len(h.instances))
		for _, g := range h.instances {
			errs = append(errs, g.store.Close())
		}
		return errors.Join(errs...)
	})
	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		h.Next = next
		return h
	})
	return nil
}

// storeSpec is what `store` and `tls_ca` said; the store is only built once
// the whole block has validated.
type storeSpec struct {
	kind  string
	ca    string
	addrs []string
}

// block is one `geoscore NAME { ... }` being parsed.
type block struct {
	store storeSpec
	cfg   Config
}

// parse reads every geoscore block of a server block into one handler. The
// zone is the server block's zone. If any block fails, the stores of the
// blocks already built are closed: setup returns an error, so OnShutdown is
// never registered and nothing else would close them.
func parse(c *caddy.Controller, zone string) (*GeoScore, error) {
	h := &GeoScore{}
	if err := h.parseBlocks(c, zone); err != nil {
		for _, g := range h.instances {
			if cerr := g.store.Close(); cerr != nil {
				log.Warningf("%s: closing store after a setup error: %v", g.cfg.Name, cerr)
			}
		}
		return nil, err
	}
	return h, nil
}

func (h *GeoScore) parseBlocks(c *caddy.Controller, zone string) error {
	// Every owner name a block answers: NAME, and _geoscore.NAME with
	// rationale-txt. One name answered by two blocks would be served by
	// whichever comes first, so it is refused.
	names := map[string]bool{}
	for c.Next() {
		args := c.RemainingArgs()
		if len(args) != 1 {
			return c.ArgErr() //nolint:wrapcheck // caddy's own argument error
		}
		zone = lowerASCII(zone)
		b := block{cfg: DefaultConfig(qualify(lowerASCII(args[0]), zone), zone)}
		if err := b.parseBody(c); err != nil {
			return err
		}
		owned := []string{b.cfg.Name}
		if b.cfg.RationaleTXT {
			owned = append(owned, rationaleLabel+b.cfg.Name)
		}
		for _, n := range owned {
			if names[n] {
				return fmt.Errorf("geoscore: %s configured twice", n)
			}
			names[n] = true
		}
		g, err := b.build()
		if err != nil {
			return err
		}
		h.instances = append(h.instances, g)
	}
	return nil
}

func (b *block) parseBody(c *caddy.Controller) error {
	seen := map[string]bool{}
	for c.NextBlock() {
		name := c.Val()
		if seen[name] && name != propEndpoint {
			return fmt.Errorf("geoscore: duplicate %s", name)
		}
		seen[name] = true
		if err := b.property(name, c.RemainingArgs()); err != nil {
			return err
		}
	}
	return nil
}

// property applies one line of the block.
func (b *block) property(name string, args []string) error {
	if name == "rationale-txt" {
		if len(args) != 0 {
			return errors.New("geoscore: rationale-txt takes no arguments")
		}
		b.cfg.RationaleTXT = true
		return nil
	}
	if name == propEndpoint || name == "store" {
		if len(args) == 0 {
			return fmt.Errorf("geoscore: %s needs arguments", name)
		}
		if name == propEndpoint {
			return b.endpoint(args)
		}
		return b.storeLine(args)
	}
	if len(args) != 1 {
		return fmt.Errorf("geoscore: %s takes exactly one argument", name)
	}
	return b.single(name, args[0])
}

func (b *block) single(name, v string) error {
	var err error
	switch name {
	case "tls_ca":
		b.store.ca = v
	case "key":
		b.cfg.KeyPrefix = v
	case "mode":
		b.cfg.Mode, err = parseMode(v)
	case "fallback":
		b.cfg.Fallback, err = parseFallback(v)
	case "max-staleness":
		b.cfg.MaxStaleness, err = time.ParseDuration(v)
	case "refresh":
		b.cfg.Refresh, err = time.ParseDuration(v)
	case "timeout":
		b.cfg.Timeout, err = time.ParseDuration(v)
	case "ttl":
		var n uint64
		n, err = strconv.ParseUint(v, 10, 31) // RFC 2181 §8: at most 2^31 - 1.
		b.cfg.TTL = uint32(n)
	default:
		return fmt.Errorf("geoscore: unknown property %q", name)
	}
	if err != nil {
		return fmt.Errorf("geoscore: %s: %w", name, err)
	}
	return nil
}

func (b *block) endpoint(args []string) error {
	ep := Endpoint{ID: args[0]}
	for _, s := range args[1:] {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return fmt.Errorf("geoscore: endpoint %s: %w", args[0], err)
		}
		ep.Addrs = append(ep.Addrs, a)
	}
	b.cfg.Endpoints = append(b.cfg.Endpoints, ep)
	return nil
}

func (b *block) storeLine(args []string) error {
	switch args[0] {
	case "memory":
		if len(args) != 1 {
			return errors.New("geoscore: store memory takes no addresses")
		}
	case "valkey":
		if len(args) == 1 {
			return errors.New("geoscore: store valkey needs at least one address")
		}
	default:
		return fmt.Errorf("geoscore: store %q: want valkey or memory", args[0])
	}
	b.store = storeSpec{kind: args[0], addrs: args[1:], ca: b.store.ca}
	return nil
}

func parseMode(s string) (Mode, error) {
	switch s {
	case modeBest:
		return ModeBest, nil
	case modeWeighted:
		return ModeWeighted, nil
	}
	return 0, fmt.Errorf("%q: want best or weighted", s)
}

func parseFallback(s string) (Fallback, error) {
	switch s {
	case "static":
		return FallbackStatic, nil
	case "servfail":
		return FallbackServfail, nil
	case "nodata":
		return FallbackNodata, nil
	}
	return 0, fmt.Errorf("%q: want static, servfail or nodata", s)
}

// build validates the configuration, then opens the store: an invalid block
// never connects anywhere.
func (b *block) build() (*Instance, error) {
	if err := b.cfg.Validate(); err != nil {
		return nil, err
	}
	var st Store
	switch b.store.kind {
	case "valkey":
		if b.store.ca == "" {
			return nil, errors.New("geoscore: store valkey requires tls_ca: the scores decide where clients are sent")
		}
		vs, err := NewValkeyStore(ValkeyConfig{Addrs: b.store.addrs, CAFile: b.store.ca})
		if err != nil {
			return nil, err
		}
		st = vs
	case "memory":
		if b.store.ca != "" {
			return nil, errors.New("geoscore: tls_ca applies to store valkey only")
		}
		log.Warningf("%s: store memory has no writer; every answer is the %s fallback", b.cfg.Name, b.cfg.Fallback)
		st = NewMemStore()
	default:
		return nil, errors.New("geoscore: store is required (valkey ADDR... or memory)")
	}
	return New(b.cfg, st)
}

// qualify makes a name without a trailing dot relative to the server
// block's zone, as a zone file does (RFC 1035 §5.1): `www` in a block for
// example.com is www.example.com. A name with the dot is taken as written.
func qualify(name, zone string) string {
	if dns.IsFqdn(name) {
		return name
	}
	if zone == "." || zone == "" {
		return dns.Fqdn(name)
	}
	return name + "." + zone
}

// lowerASCII folds ASCII letters only (RFC 4343 §3).
func lowerASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

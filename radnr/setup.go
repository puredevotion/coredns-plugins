//nolint:misspell // adn/ADN throughout this file: RFC 9463 Authentication Domain Name, not a typo for and/AND
package radnr

import (
	"fmt"
	"strconv"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/plugin"

	"github.com/puredevotion/coredns-plugins/radnr/internal/config"
)

// advInterval is the RA advertisement interval. Fixed for the spike.
const advInterval = 30 * time.Second

func init() { plugin.Register(pluginName, setup) }

// setup parses the Corefile block, validates it, and registers lifecycle hooks.
// Like the health/metrics plugins it does NOT call AddPlugin — radnr is a
// listener-only plugin, not a DNS handler.
func setup(c *caddy.Controller) error {
	cfg, err := parse(c)
	if err != nil {
		return fmt.Errorf("setup: %w", plugin.Error(pluginName, err))
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("validate config: %w", plugin.Error(pluginName, err))
	}

	r := &RADNR{Cfg: cfg}
	c.OnStartup(r.OnStartup)
	c.OnRestart(r.OnShutdown)
	c.OnFinalShutdown(r.OnShutdown)
	c.OnRestartFailed(r.OnStartup)
	return nil
}

// directiveParsers maps each Corefile property name to the function that
// parses it. Table-driven so parse itself stays a simple dispatch loop.
var directiveParsers = map[string]func(c *caddy.Controller, cfg *config.Config) error{
	"interface":            parseInterfaceDirective,
	"adn":                  parseADNDirective,
	"addr":                 parseAddrDirective,
	"alpn":                 parseALPNDirective,
	"port":                 parsePortDirective,
	"dohpath":              parseDohPathDirective,
	"unicast":              parseUnicastDirective,
	"rdnss":                parseRDNSSDirective,
	"dry-run":              parseDryRunDirective,
	"router-lifetime":      parseRouterLifetimeDirective,
	"allow-default-router": parseAllowDefaultRouterDirective,
	"advertise-prefix":     parseAdvertisePrefixDirective,
}

func parse(c *caddy.Controller) (config.Config, error) {
	var cfg config.Config
	for c.Next() { // The "radnr" directive token.
		for c.NextBlock() {
			fn, ok := directiveParsers[c.Val()]
			if !ok {
				return cfg, c.Errf("unknown property %q", c.Val()) //nolint:wrapcheck // caddyfile Dispenser errors are already user-facing config errors
			}
			if err := fn(c, &cfg); err != nil {
				return cfg, err
			}
		}
	}
	return cfg, nil
}

func parseInterfaceDirective(c *caddy.Controller, cfg *config.Config) error {
	if !c.NextArg() {
		return c.ArgErr() //nolint:wrapcheck // caddyfile Dispenser errors are already user-facing config errors
	}
	cfg.Interface = c.Val()
	return nil
}

func parseADNDirective(c *caddy.Controller, cfg *config.Config) error {
	if !c.NextArg() {
		return c.ArgErr() //nolint:wrapcheck // caddyfile Dispenser errors are already user-facing config errors
	}
	cfg.ADN = c.Val()
	return nil
}

func parseAddrDirective(c *caddy.Controller, cfg *config.Config) error {
	args := c.RemainingArgs()
	if len(args) == 0 {
		return c.ArgErr() //nolint:wrapcheck // caddyfile Dispenser errors are already user-facing config errors
	}
	cfg.Addrs = append(cfg.Addrs, args...)
	return nil
}

func parseALPNDirective(c *caddy.Controller, cfg *config.Config) error {
	args := c.RemainingArgs()
	if len(args) == 0 {
		return c.ArgErr() //nolint:wrapcheck // caddyfile Dispenser errors are already user-facing config errors
	}
	cfg.ALPN = args
	return nil
}

func parsePortDirective(c *caddy.Controller, cfg *config.Config) error {
	if !c.NextArg() {
		return c.ArgErr() //nolint:wrapcheck // caddyfile Dispenser errors are already user-facing config errors
	}
	p, err := strconv.ParseUint(c.Val(), 10, 16)
	if err != nil {
		return c.Errf("invalid port %q: %v", c.Val(), err) //nolint:wrapcheck // caddyfile Dispenser errors are already user-facing config errors
	}
	cfg.Port = uint16(p)
	return nil
}

func parseDohPathDirective(c *caddy.Controller, cfg *config.Config) error {
	if !c.NextArg() {
		return c.ArgErr() //nolint:wrapcheck // caddyfile Dispenser errors are already user-facing config errors
	}
	cfg.DohPath = c.Val()
	return nil
}

func parseUnicastDirective(c *caddy.Controller, cfg *config.Config) error {
	if !c.NextArg() {
		return c.ArgErr() //nolint:wrapcheck // caddyfile Dispenser errors are already user-facing config errors
	}
	cfg.UnicastTarget = c.Val()
	return nil
}

func parseRDNSSDirective(c *caddy.Controller, cfg *config.Config) error {
	if c.NextArg() {
		return c.ArgErr() //nolint:wrapcheck // caddyfile Dispenser errors are already user-facing config errors
	}
	cfg.AdvertiseRDNSS = true
	return nil
}

func parseDryRunDirective(c *caddy.Controller, cfg *config.Config) error {
	if c.NextArg() {
		return c.ArgErr() //nolint:wrapcheck // caddyfile Dispenser errors are already user-facing config errors
	}
	cfg.DryRun = true
	return nil
}

func parseRouterLifetimeDirective(c *caddy.Controller, cfg *config.Config) error {
	if !c.NextArg() {
		return c.ArgErr() //nolint:wrapcheck // caddyfile Dispenser errors are already user-facing config errors
	}
	v, err := strconv.ParseUint(c.Val(), 10, 16)
	if err != nil {
		return c.Errf("invalid router-lifetime %q: %v", c.Val(), err) //nolint:wrapcheck // caddyfile Dispenser errors are already user-facing config errors
	}
	cfg.RouterLifetime = uint16(v)
	return nil
}

func parseAllowDefaultRouterDirective(c *caddy.Controller, cfg *config.Config) error {
	if c.NextArg() {
		return c.ArgErr() //nolint:wrapcheck // caddyfile Dispenser errors are already user-facing config errors
	}
	cfg.AllowDefaultRouter = true
	return nil
}

func parseAdvertisePrefixDirective(c *caddy.Controller, cfg *config.Config) error {
	args := c.RemainingArgs()
	if len(args) == 0 {
		return c.ArgErr() //nolint:wrapcheck // caddyfile Dispenser errors are already user-facing config errors
	}
	cfg.AdvertisePrefixes = append(cfg.AdvertisePrefixes, args...)
	return nil
}

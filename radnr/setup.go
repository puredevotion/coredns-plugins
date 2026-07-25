package radnr

import (
	"strconv"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/plugin"

	"github.com/puredevotion/coredns-plugins/radnr/internal/config"
)

// advInterval is the RA advertisement interval. Fixed for the spike.
const advInterval = 30 * time.Second

func init() { plugin.Register("radnr", setup) }

// setup parses the Corefile block, validates it, and registers lifecycle hooks.
// Like the health/metrics plugins it does NOT call AddPlugin — radnr is a
// listener-only plugin, not a DNS handler.
func setup(c *caddy.Controller) error {
	cfg, err := parse(c)
	if err != nil {
		return plugin.Error("radnr", err)
	}
	if err := cfg.Validate(); err != nil {
		return plugin.Error("radnr", err)
	}

	r := &RADNR{Cfg: cfg}
	c.OnStartup(r.OnStartup)
	c.OnRestart(r.OnShutdown)
	c.OnFinalShutdown(r.OnShutdown)
	c.OnRestartFailed(r.OnStartup)
	return nil
}

func parse(c *caddy.Controller) (config.Config, error) {
	var cfg config.Config
	for c.Next() { // "radnr"
		for c.NextBlock() {
			switch c.Val() {
			case "interface":
				if !c.NextArg() {
					return cfg, c.ArgErr()
				}
				cfg.Interface = c.Val()
			case "adn":
				if !c.NextArg() {
					return cfg, c.ArgErr()
				}
				cfg.ADN = c.Val()
			case "addr":
				args := c.RemainingArgs()
				if len(args) == 0 {
					return cfg, c.ArgErr()
				}
				cfg.Addrs = append(cfg.Addrs, args...)
			case "alpn":
				args := c.RemainingArgs()
				if len(args) == 0 {
					return cfg, c.ArgErr()
				}
				cfg.ALPN = args
			case "port":
				if !c.NextArg() {
					return cfg, c.ArgErr()
				}
				p, err := strconv.ParseUint(c.Val(), 10, 16)
				if err != nil {
					return cfg, c.Errf("invalid port %q: %v", c.Val(), err)
				}
				cfg.Port = uint16(p)
			case "dohpath":
				if !c.NextArg() {
					return cfg, c.ArgErr()
				}
				cfg.DohPath = c.Val()
			case "unicast":
				if !c.NextArg() {
					return cfg, c.ArgErr()
				}
				cfg.UnicastTarget = c.Val()
			case "rdnss":
				if c.NextArg() {
					return cfg, c.ArgErr()
				}
				cfg.AdvertiseRDNSS = true
			case "dry-run":
				if c.NextArg() {
					return cfg, c.ArgErr()
				}
				cfg.DryRun = true
			case "router-lifetime":
				if !c.NextArg() {
					return cfg, c.ArgErr()
				}
				v, err := strconv.ParseUint(c.Val(), 10, 16)
				if err != nil {
					return cfg, c.Errf("invalid router-lifetime %q: %v", c.Val(), err)
				}
				cfg.RouterLifetime = uint16(v)
			case "allow-default-router":
				if c.NextArg() {
					return cfg, c.ArgErr()
				}
				cfg.AllowDefaultRouter = true
			case "advertise-prefix":
				args := c.RemainingArgs()
				if len(args) == 0 {
					return cfg, c.ArgErr()
				}
				cfg.AdvertisePrefixes = append(cfg.AdvertisePrefixes, args...)
			default:
				return cfg, c.Errf("unknown property %q", c.Val())
			}
		}
	}
	return cfg, nil
}

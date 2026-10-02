// Package snitls registers the sni_tls plugin with CoreDNS. See ../docs/sni-tls-plugin.md
// for the full design rationale (SNI-multiplexed cert selection replacing the stock tls
// plugin's single-cert-per-listener limitation).
package snitls

import (
	ctls "crypto/tls"
	"strings"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
)

// pluginName is the CoreDNS plugin/Corefile directive name; kept separate from
// the Go package identifier (snitls) since CoreDNS plugin names conventionally
// use underscores.
const pluginName = "sni_tls"

// setupArgsCertKey is the number of Corefile arguments a `sni_tls <cert> <key>`
// line takes.
const setupArgsCertKey = 2

func init() {
	plugin.Register(pluginName, setup)
}

// setup parses one or more `sni_tls <cert> <key>` lines from the Corefile, plus an
// optional `sni_tls { strict; no_sni ... }` block-only line: strict mode (no
// fallback cert; an unmatched SNI hard-fails the handshake instead of guessing —
// see docs/sni-tls-plugin.md's verified-DDR caveat), and what a ClientHello
// without SNI gets (refused, the fallback cert, or a cert of its own). Cert/key
// lines accumulate (append, not overwrite) so adding a third hostname later is
// a one-line diff. Mirrors the
// stock tls plugin's guard against a server block configuring TLS twice (see
// coredns plugin/tls's parseTLS).
func setup(c *caddy.Controller) error {
	config := dnsserver.GetConfig(c)
	if config.TLSConfig != nil {
		return plugin.Error(pluginName, c.Errf("TLS already configured for this server instance")) //nolint:wrapcheck // caddyfile Dispenser errors are already user-facing config errors; plugin.Error is the conventional coredns setup-parsing wrapper (see plugin/tls's parseTLS)
	}

	cfg, err := parseConfig(c)
	if err != nil {
		return err
	}

	store, err := buildCertStore(cfg)
	if err != nil {
		return plugin.Error(pluginName, err) //nolint:wrapcheck // plugin.Error is the conventional coredns setup-parsing wrapper (see plugin/tls's parseTLS); err itself is already wrapped by buildCertStore/loadCert
	}

	live := newLiveStore(cfg, store, digestPairs(cfg.files()))
	live.owner = c.Context()
	c.OnStartup(live.OnStartup)
	c.OnRestart(live.OnShutdown)
	c.OnFinalShutdown(live.OnShutdown)
	c.OnRestartFailed(live.OnStartup)

	// #nosec G402 -- MinVersion set explicitly below, matching plugin/pkg/tls's default.
	config.TLSConfig = &ctls.Config{
		GetCertificate: live.GetCertificate,
		MinVersion:     ctls.VersionTLS12,
	}

	return nil
}

// parseConfig reads every `sni_tls` line of the server block into a
// storeConfig, without touching any file.
func parseConfig(c *caddy.Controller) (storeConfig, error) {
	var cfg storeConfig
	for c.Next() {
		args := c.RemainingArgs()
		switch len(args) {
		case setupArgsCertKey:
			cfg.pairs = append(cfg.pairs, [2]string{args[0], args[1]})
		case 0:
			if !c.NextBlock() {
				return cfg, plugin.Error(pluginName, c.ArgErr()) //nolint:wrapcheck // caddyfile Dispenser errors are already user-facing config errors; plugin.Error is the conventional coredns setup-parsing wrapper (see plugin/tls's parseTLS)
			}
			if err := parseBlockOptions(c, &cfg); err != nil {
				return cfg, err
			}
		default:
			return cfg, plugin.Error(pluginName, c.ArgErr()) //nolint:wrapcheck // caddyfile Dispenser errors are already user-facing config errors; plugin.Error is the conventional coredns setup-parsing wrapper (see plugin/tls's parseTLS)
		}
	}
	if len(cfg.pairs) == 0 {
		return cfg, plugin.Error(pluginName, c.ArgErr()) //nolint:wrapcheck // caddyfile Dispenser errors are already user-facing config errors; plugin.Error is the conventional coredns setup-parsing wrapper (see plugin/tls's parseTLS)
	}
	return cfg, nil
}

// parseBlockOptions parses the body of a `sni_tls { ... }` block into cfg:
// the bare `strict` option, and `no_sni` (see parseNoSNI). Extracted from
// setup so the caller's Corefile line-dispatch switch stays simple.
func parseBlockOptions(c *caddy.Controller, cfg *storeConfig) error {
	for {
		switch c.Val() {
		case "strict":
			if len(c.RemainingArgs()) != 0 {
				return plugin.Error(pluginName, c.ArgErr()) //nolint:wrapcheck // caddyfile Dispenser errors are already user-facing config errors; plugin.Error is the conventional coredns setup-parsing wrapper (see plugin/tls's parseTLS)
			}
			cfg.strict = true
		case "no_sni":
			if err := parseNoSNI(c, cfg); err != nil {
				return err
			}
		default:
			return plugin.Error(pluginName, c.Errf("unknown sni_tls option %q", c.Val())) //nolint:wrapcheck // caddyfile Dispenser errors are already user-facing config errors; plugin.Error is the conventional coredns setup-parsing wrapper (see plugin/tls's parseTLS)
		}
		if !c.NextBlock() {
			return nil
		}
	}
}

// parseNoSNI parses `no_sni refuse`, `no_sni fallback` or `no_sni cert
// <cert> <key>`: what a ClientHello without SNI gets (see noSNIPolicy). It
// may appear once per server block.
func parseNoSNI(c *caddy.Controller, cfg *storeConfig) error {
	if cfg.noSNI != noSNIAsUnmatched {
		return plugin.Error(pluginName, c.Err("no_sni given more than once")) //nolint:wrapcheck // caddyfile Dispenser errors are already user-facing config errors; plugin.Error is the conventional coredns setup-parsing wrapper (see plugin/tls's parseTLS)
	}
	args := c.RemainingArgs()
	switch {
	case len(args) == 1 && args[0] == "refuse":
		cfg.noSNI = noSNIRefuse
	case len(args) == 1 && args[0] == "fallback":
		cfg.noSNI = noSNIFallback
	case len(args) == 1+setupArgsCertKey && args[0] == "cert":
		cfg.noSNI = noSNICertificate
		cfg.noSNIPair = [2]string{args[1], args[2]}
	default:
		return plugin.Error(pluginName, c.Errf("no_sni takes refuse, fallback, or cert <cert> <key>; got %q", strings.Join(args, " "))) //nolint:wrapcheck // caddyfile Dispenser errors are already user-facing config errors; plugin.Error is the conventional coredns setup-parsing wrapper (see plugin/tls's parseTLS)
	}
	return nil
}

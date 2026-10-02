// Package snitls registers the sni_tls plugin with CoreDNS. See ../docs/sni-tls-plugin.md
// for the full design rationale (SNI-multiplexed cert selection replacing the stock tls
// plugin's single-cert-per-listener limitation).
package snitls

import (
	ctls "crypto/tls"

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
// optional `sni_tls { strict }` block-only line to enable strict mode (no fallback
// cert; unmatched/absent SNI hard-fails the handshake instead of guessing — see
// docs/sni-tls-plugin.md's verified-DDR caveat). Cert/key lines accumulate (append,
// not overwrite) so adding a third hostname later is a one-line diff. Mirrors the
// stock tls plugin's guard against a server block configuring TLS twice (see
// coredns plugin/tls's parseTLS).
func setup(c *caddy.Controller) error {
	config := dnsserver.GetConfig(c)
	if config.TLSConfig != nil {
		return plugin.Error(pluginName, c.Errf("TLS already configured for this server instance")) //nolint:wrapcheck // caddyfile Dispenser errors are already user-facing config errors; plugin.Error is the conventional coredns setup-parsing wrapper (see plugin/tls's parseTLS)
	}

	var pairs [][2]string
	var strict bool

	for c.Next() {
		args := c.RemainingArgs()
		switch len(args) {
		case setupArgsCertKey:
			pairs = append(pairs, [2]string{args[0], args[1]})
		case 0:
			if !c.NextBlock() {
				return plugin.Error(pluginName, c.ArgErr()) //nolint:wrapcheck // caddyfile Dispenser errors are already user-facing config errors; plugin.Error is the conventional coredns setup-parsing wrapper (see plugin/tls's parseTLS)
			}
			if err := parseBlockOptions(c, &strict); err != nil {
				return err
			}
		default:
			return plugin.Error(pluginName, c.ArgErr()) //nolint:wrapcheck // caddyfile Dispenser errors are already user-facing config errors; plugin.Error is the conventional coredns setup-parsing wrapper (see plugin/tls's parseTLS)
		}
	}

	if len(pairs) == 0 {
		return plugin.Error(pluginName, c.ArgErr()) //nolint:wrapcheck // caddyfile Dispenser errors are already user-facing config errors; plugin.Error is the conventional coredns setup-parsing wrapper (see plugin/tls's parseTLS)
	}

	store, err := buildCertStore(pairs, strict)
	if err != nil {
		return plugin.Error(pluginName, err) //nolint:wrapcheck // plugin.Error is the conventional coredns setup-parsing wrapper (see plugin/tls's parseTLS); err itself is already wrapped by buildCertStore/loadCert
	}

	live := newLiveStore(pairs, strict, store, digestPairs(pairs))
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

// parseBlockOptions parses the body of a `sni_tls { ... }` block, currently
// only the bare `strict` option, setting *strict when found. Extracted from
// setup so the caller's Corefile line-dispatch switch stays simple.
func parseBlockOptions(c *caddy.Controller, strict *bool) error {
	for {
		switch c.Val() {
		case "strict":
			if len(c.RemainingArgs()) != 0 {
				return plugin.Error(pluginName, c.ArgErr()) //nolint:wrapcheck // caddyfile Dispenser errors are already user-facing config errors; plugin.Error is the conventional coredns setup-parsing wrapper (see plugin/tls's parseTLS)
			}
			*strict = true
		default:
			return plugin.Error(pluginName, c.Errf("unknown sni_tls option %q", c.Val())) //nolint:wrapcheck // caddyfile Dispenser errors are already user-facing config errors; plugin.Error is the conventional coredns setup-parsing wrapper (see plugin/tls's parseTLS)
		}
		if !c.NextBlock() {
			return nil
		}
	}
}

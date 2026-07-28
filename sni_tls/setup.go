// Package sni_tls registers the sni_tls plugin with CoreDNS. See ../docs/sni-tls-plugin.md
// for the full design rationale (SNI-multiplexed cert selection replacing the stock tls
// plugin's single-cert-per-listener limitation).
package sni_tls

import (
	ctls "crypto/tls"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
)

func init() {
	plugin.Register("sni_tls", setup)
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
		return plugin.Error("sni_tls", c.Errf("TLS already configured for this server instance"))
	}

	var pairs [][2]string
	var strict bool

	for c.Next() {
		args := c.RemainingArgs()
		switch len(args) {
		case 2:
			pairs = append(pairs, [2]string{args[0], args[1]})
		case 0:
			if !c.NextBlock() {
				return plugin.Error("sni_tls", c.ArgErr())
			}
			for {
				switch c.Val() {
				case "strict":
					if len(c.RemainingArgs()) != 0 {
						return plugin.Error("sni_tls", c.ArgErr())
					}
					strict = true
				default:
					return plugin.Error("sni_tls", c.Errf("unknown sni_tls option %q", c.Val()))
				}
				if !c.NextBlock() {
					break
				}
			}
		default:
			return plugin.Error("sni_tls", c.ArgErr())
		}
	}

	if len(pairs) == 0 {
		return plugin.Error("sni_tls", c.ArgErr())
	}

	store, err := buildCertStore(pairs, strict)
	if err != nil {
		return plugin.Error("sni_tls", err)
	}

	live := newLiveStore(pairs, strict, store, digestPairs(pairs))
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

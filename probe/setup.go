package probe

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/miekg/dns"
)

func init() { plugin.Register("probe", setup) }

// Corefile syntax
//
//	probe ZONE {
//	    key      BASENAME     # <BASENAME>.key + <BASENAME>.private
//	    ttl      SECONDS
//	    ns       NAME
//	    mbox     NAME
//	    validity DURATION
//	    store_ttl DURATION
//	    max_tokens N
//	    max_per_token N
//	    big_size BYTES
//	}
//
// Only ZONE is required. Without `key` the zone is unsigned, which is a valid
// configuration but disables most of what the zone is for — setup logs a
// warning rather than failing, because an unsigned zone is genuinely useful
// while keys are still being generated.
func setup(c *caddy.Controller) error {
	p, err := parse(c)
	if err != nil {
		return plugin.Error("probe", err)
	}
	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		p.Next = next
		return p
	})
	return nil
}

// Defaults. The TTL is deliberately tiny: these answers describe one visitor at
// one moment, and a cached answer is a wrong answer for the next visitor.
const (
	defaultTTL = 10

	// defaultBigSize sits above the DNS-flag-day-2020 consensus EDNS cap of
	// 1232 bytes — so the answer demonstrably exceeds what a resolver should be
	// advertising room for — but below the ~1500-byte Ethernet MTU, so it still
	// arrives.
	//
	// Measured, not guessed: on a path with a 1500-byte MTU, a response of
	// ~1419 bytes is delivered over UDP and anything past ~1540 silently
	// vanishes (confirmed at 1420/1450/1500/2000/2500, all timing out, while
	// the same 3125-byte answer arrived intact over TCP). A larger default
	// would therefore make the amplification demonstration present as "the
	// server is broken" rather than "look how large this answer is", which
	// teaches the wrong lesson to anyone loading the page.
	//
	// Configuring a bigger value is a legitimate experiment — it tests path-MTU
	// behaviour and fragment filtering, which is a real and interesting failure
	// mode — but it is a poor default.
	defaultBigSize = 1400
)

func parse(c *caddy.Controller) (*Probe, error) {
	p := &Probe{TTL: defaultTTL, BigSize: defaultBigSize}

	var (
		keyBase                string
		validity, storeTTL     time.Duration
		maxTokens, maxPerToken int
		seenZone               bool
		valkeyCfg              ValkeyConfig
	)

	for c.Next() { // "probe"
		args := c.RemainingArgs()
		if len(args) != 1 {
			return nil, c.ArgErr()
		}
		if seenZone {
			// Two `probe` blocks in one server block would silently mean the
			// second wins, since each AddPlugin call wraps the chain.
			return nil, fmt.Errorf("only one probe block per server block")
		}
		seenZone = true
		p.Zone = dns.CanonicalName(args[0])

		for c.NextBlock() {
			switch c.Val() {
			case "key":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				keyBase = c.Val()
			case "ttl":
				v, err := parseUint32Arg(c)
				if err != nil {
					return nil, err
				}
				p.TTL = v
			case "ns":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				p.NSName = dns.CanonicalName(c.Val())
			case "mbox":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				p.Mbox = dns.CanonicalName(c.Val())
			case "validity":
				d, err := parseDurationArg(c)
				if err != nil {
					return nil, err
				}
				validity = d
			case "store_ttl":
				d, err := parseDurationArg(c)
				if err != nil {
					return nil, err
				}
				storeTTL = d
			case "max_tokens":
				v, err := parseIntArg(c)
				if err != nil {
					return nil, err
				}
				maxTokens = v
			case "max_per_token":
				v, err := parseIntArg(c)
				if err != nil {
					return nil, err
				}
				maxPerToken = v
			case "valkey":
				// Repeatable and/or multi-valued, so a Corefile can list every
				// endpoint without a delimiter convention.
				vs := c.RemainingArgs()
				if len(vs) == 0 {
					return nil, c.ArgErr()
				}
				valkeyCfg.Addrs = append(valkeyCfg.Addrs, vs...)
			case "valkey_ca":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				valkeyCfg.CAFile = c.Val()
			case "valkey_timeout":
				d, err := parseDurationArg(c)
				if err != nil {
					return nil, err
				}
				valkeyCfg.Timeout = d
			case "big_size":
				v, err := parseIntArg(c)
				if err != nil {
					return nil, err
				}
				// A modifier that exists to demonstrate amplification must not
				// become an unbounded one. 4096 keeps a single answer inside
				// what a resolver will accept over TCP without this turning
				// into a memory knob.
				if v < 1 || v > 4096 {
					return nil, fmt.Errorf("big_size %d out of range (1-4096)", v)
				}
				p.BigSize = v
			default:
				return nil, c.Errf("unknown property %q", c.Val())
			}
		}
	}

	if !seenZone {
		return nil, c.ArgErr()
	}
	if p.NSName == "" {
		p.NSName = "ns." + p.Zone
	}
	if p.Mbox == "" {
		p.Mbox = "hostmaster." + p.Zone
	}

	if keyBase != "" {
		s, err := LoadSigner(keyBase, validity)
		if err != nil {
			return nil, err
		}
		// A key whose owner name is not this zone produces signatures every
		// validator rejects, and the symptom is "everything is bogus" with no
		// error logged anywhere. Refuse at startup instead.
		if s.Owner() != p.Zone {
			return nil, fmt.Errorf("key is for zone %s but this block serves %s",
				s.Owner(), p.Zone)
		}
		p.Signer = s
	} else {
		log.Warningf("zone %s has no signing key: the unsigned/badsig/expiredsig/futuresig modifiers will be no-ops", p.Zone)
	}

	store, err := buildStore(c, valkeyCfg, storeTTL, maxTokens, maxPerToken)
	if err != nil {
		return nil, err
	}
	p.Store = store

	// Build the ECH transport canary. Deliberately NOT configurable and NOT
	// random: the measurement compares bytes that arrive against bytes we serve,
	// so it has to be stable across restarts and identical on every replica. The
	// key is derived from the zone name rather than generated, which gives both
	// properties for free and makes it distinct per zone.
	//
	// Nothing holds the private half. See echconfig.go — publishing a USABLE ECH
	// config from a zone that serves no TLS would invite clients to attempt real
	// ECH against names that cannot complete it.
	echKey := sha256.Sum256([]byte("probe-ech-canary/" + p.Zone))
	echList, err := BuildECHConfigList(echConfigID, echKey[:], strings.TrimSuffix(p.Zone, "."))
	if err != nil {
		// Only reachable if the zone name exceeds 255 bytes, which CoreDNS would
		// have rejected earlier. Surfaced rather than ignored so the zone never
		// comes up serving HTTPS records with no ech= to measure.
		return nil, c.Errf("building ECH canary for %s: %v", p.Zone, err)
	}
	p.ECHConfigList = echList

	return p, nil
}

// echConfigID is fixed. RFC 9848 uses it to select among several configs; there is
// only ever one here, and a stable value keeps the served bytes comparable.
const echConfigID = 0x01

// buildStore picks the observation store. In-process by default so the plugin
// works with no external dependency; Valkey when configured, which is required
// for anything the separate web tier has to read and for more than one replica.
func buildStore(c *caddy.Controller, vc ValkeyConfig, ttl time.Duration, maxTokens, maxPerToken int) (Store, error) {
	if len(vc.Addrs) == 0 {
		if vc.CAFile != "" || vc.Timeout != 0 {
			return nil, c.Err("valkey_ca / valkey_timeout set without any `valkey` address")
		}
		return NewMemStore(ttl, maxTokens, maxPerToken), nil
	}
	if vc.CAFile == "" {
		// Verified TLS is mandatory, with no bypass. The fleet's Valkey has no
		// authentication of its own (the chart cannot do it), so the server
		// certificate is the only thing distinguishing it from anything else
		// that answers on that address — and what travels over the link is
		// observations about other people's networks.
		return nil, c.Err("valkey requires valkey_ca so the server certificate can be verified")
	}
	vc.TTL, vc.MaxPerToken = ttl, maxPerToken
	return NewValkeyStore(vc)
}

func parseIntArg(c *caddy.Controller) (int, error) {
	if !c.NextArg() {
		return 0, c.ArgErr()
	}
	var v int
	if _, err := fmt.Sscanf(c.Val(), "%d", &v); err != nil {
		return 0, c.Errf("%q is not a number", c.Val())
	}
	return v, nil
}

func parseUint32Arg(c *caddy.Controller) (uint32, error) {
	v, err := parseIntArg(c)
	if err != nil {
		return 0, err
	}
	if v < 0 || v > int(^uint32(0)) {
		return 0, c.Errf("value %d out of range", v)
	}
	return uint32(v), nil
}

func parseDurationArg(c *caddy.Controller) (time.Duration, error) {
	if !c.NextArg() {
		return 0, c.ArgErr()
	}
	d, err := time.ParseDuration(c.Val())
	if err != nil {
		return 0, c.Errf("%q is not a duration", c.Val())
	}
	if d <= 0 {
		return 0, c.Errf("duration %q must be positive", c.Val())
	}
	return d, nil
}

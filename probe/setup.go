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

func init() { plugin.Register(pluginName, setup) }

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
//	    agent_domain NAME
//	    agent_ttl SECONDS
//	}
//
// Only ZONE is required. Without `key` the zone is unsigned, which is a valid
// configuration but disables most of what the zone is for — setup logs a
// warning rather than failing, because an unsigned zone is genuinely useful
// while keys are still being generated.
func setup(c *caddy.Controller) error {
	p, err := parse(c)
	if err != nil {
		return fmt.Errorf("configure probe plugin: %w", plugin.Error(pluginName, err))
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

	// DefaultBigSize sits above the DNS-flag-day-2020 consensus EDNS cap of
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

// parseState holds the setup values that do not live on Probe directly —
// either because they are consumed before the signer/store are built, or
// because several directives feed one field (valkeyCfg).
type parseState struct {
	keyBase     string
	valkeyCfg   ValkeyConfig
	validity    time.Duration
	storeTTL    time.Duration
	maxTokens   int
	maxPerToken int
}

func parse(c *caddy.Controller) (*Probe, error) {
	p := &Probe{TTL: defaultTTL, BigSize: defaultBigSize}

	var st parseState
	var seenZone bool

	for c.Next() { // "probe".
		args := c.RemainingArgs()
		if len(args) != 1 {
			//nolint:wrapcheck // caddyfile Dispenser errors are already user-facing config errors
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
			if err := applyDirective(c, p, &st); err != nil {
				return nil, err
			}
		}
	}

	if !seenZone {
		//nolint:wrapcheck // caddyfile Dispenser errors are already user-facing config errors
		return nil, c.ArgErr()
	}
	if p.NSName == "" {
		p.NSName = "ns." + p.Zone
	}
	if p.Mbox == "" {
		p.Mbox = "hostmaster." + p.Zone
	}

	if err := p.validateAgentDomain(c); err != nil {
		return nil, err
	}

	if err := p.loadSignerFromState(&st); err != nil {
		return nil, err
	}

	store, err := buildStore(c, st.valkeyCfg, st.storeTTL, st.maxTokens, st.maxPerToken)
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
		//nolint:wrapcheck // caddyfile Dispenser errors are already user-facing config errors
		return nil, c.Errf("building ECH canary for %s: %v", p.Zone, err)
	}
	p.ECHConfigList = echList

	return p, nil
}

// applyValkeyDirective handles the three `valkey*` directives, reporting
// whether c.Val() named one of them. Split out of applyDirective purely to
// keep that function's cognitive complexity down; every check is unchanged.
func applyValkeyDirective(c *caddy.Controller, st *parseState) (handled bool, err error) {
	switch c.Val() {
	case "valkey":
		// Repeatable and/or multi-valued, so a Corefile can list every
		// endpoint without a delimiter convention.
		vs := c.RemainingArgs()
		if len(vs) == 0 {
			//nolint:wrapcheck // caddyfile Dispenser errors are already user-facing config errors
			return true, c.ArgErr()
		}
		st.valkeyCfg.Addrs = append(st.valkeyCfg.Addrs, vs...)
		return true, nil
	case "valkey_ca":
		if !c.NextArg() {
			//nolint:wrapcheck // caddyfile Dispenser errors are already user-facing config errors
			return true, c.ArgErr()
		}
		st.valkeyCfg.CAFile = c.Val()
		return true, nil
	case "valkey_timeout":
		d, err := parseDurationArg(c)
		if err != nil {
			return true, err
		}
		st.valkeyCfg.Timeout = d
		return true, nil
	}
	return false, nil
}

// applySimpleDirective handles the directives that are just "parse one arg,
// assign it" with no extra validation, reporting whether c.Val() named one of
// them. Split out of applyDirective purely to keep that function's cognitive
// complexity down; every check is unchanged.
func applySimpleDirective(c *caddy.Controller, p *Probe, st *parseState) (handled bool, err error) {
	switch c.Val() {
	case "ttl":
		v, err := parseUint32Arg(c)
		if err != nil {
			return true, err
		}
		p.TTL = v
		return true, nil
	case "ns":
		if !c.NextArg() {
			//nolint:wrapcheck // caddyfile Dispenser errors are already user-facing config errors
			return true, c.ArgErr()
		}
		p.NSName = dns.CanonicalName(c.Val())
		return true, nil
	case "mbox":
		if !c.NextArg() {
			//nolint:wrapcheck // caddyfile Dispenser errors are already user-facing config errors
			return true, c.ArgErr()
		}
		p.Mbox = dns.CanonicalName(c.Val())
		return true, nil
	case "validity":
		d, err := parseDurationArg(c)
		if err != nil {
			return true, err
		}
		st.validity = d
		return true, nil
	}
	return false, nil
}

// applyStoreLimitDirective handles the store-sizing directives (store_ttl,
// max_tokens, max_per_token), reporting whether c.Val() named one of them.
// Split out of applySimpleDirective purely to keep that function's length
// down; every check is unchanged.
func applyStoreLimitDirective(c *caddy.Controller, st *parseState) (handled bool, err error) {
	switch c.Val() {
	case "store_ttl":
		d, err := parseDurationArg(c)
		if err != nil {
			return true, err
		}
		st.storeTTL = d
		return true, nil
	case "max_tokens":
		v, err := parseIntArg(c)
		if err != nil {
			return true, err
		}
		st.maxTokens = v
		return true, nil
	case "max_per_token":
		v, err := parseIntArg(c)
		if err != nil {
			return true, err
		}
		st.maxPerToken = v
		return true, nil
	}
	return false, nil
}

// applyDirective handles one Corefile directive inside a probe block. Split
// out of parse purely to keep that function's cognitive complexity down —
// every check, default and error message is unchanged.
func applyDirective(c *caddy.Controller, p *Probe, st *parseState) error {
	if handled, err := applyValkeyDirective(c, st); handled || err != nil {
		return err
	}
	if handled, err := applySimpleDirective(c, p, st); handled || err != nil {
		return err
	}
	if handled, err := applyStoreLimitDirective(c, st); handled || err != nil {
		return err
	}

	switch c.Val() {
	case "key":
		if !c.NextArg() {
			//nolint:wrapcheck // caddyfile Dispenser errors are already user-facing config errors
			return c.ArgErr()
		}
		st.keyBase = c.Val()
	case "agent_domain":
		if !c.NextArg() {
			//nolint:wrapcheck // caddyfile Dispenser errors are already user-facing config errors
			return c.ArgErr()
		}
		p.AgentDomain = dns.CanonicalName(c.Val())
	case "agent_ttl":
		v, err := parseUint32Arg(c)
		if err != nil {
			return err
		}
		if v == 0 {
			// Zero would mean "never cache a report answer", which RFC
			// 9567 §6.2 specifically warns against: caching is what limits
			// a reporting resolver to one report per TTL for the same
			// problem, so disabling it turns every persistent failure into
			// an unbounded stream of report queries at us.
			//nolint:wrapcheck // caddyfile Dispenser errors are already user-facing config errors
			return c.Err("agent_ttl must be greater than zero")
		}
		p.AgentTTL = v
	case "big_size":
		v, err := parseIntArg(c)
		if err != nil {
			return err
		}
		// A modifier that exists to demonstrate amplification must not
		// become an unbounded one. 4096 keeps a single answer inside
		// what a resolver will accept over TCP without this turning
		// into a memory knob.
		if v < 1 || v > 4096 {
			return fmt.Errorf("big_size %d out of range (1-4096)", v)
		}
		p.BigSize = v
	default:
		//nolint:wrapcheck // caddyfile Dispenser errors are already user-facing config errors
		return c.Errf("unknown property %q", c.Val())
	}
	return nil
}

// loadSignerFromState loads and validates the signing key named by
// st.keyBase, if any. Split out of parse purely to keep that function's
// cognitive complexity down; every check and error message is unchanged.
func (p *Probe) loadSignerFromState(st *parseState) error {
	if st.keyBase == "" {
		log.Warningf("zone %s has no signing key: the unsigned/badsig/expiredsig/futuresig modifiers will be no-ops", p.Zone)
		return nil
	}
	s, err := LoadSigner(st.keyBase, st.validity)
	if err != nil {
		return err
	}
	// A key whose owner name is not this zone produces signatures every
	// validator rejects, and the symptom is "everything is bogus" with no
	// error logged anywhere. Refuse at startup instead.
	if s.Owner() != p.Zone {
		return fmt.Errorf("key is for zone %s but this block serves %s",
			s.Owner(), p.Zone)
	}
	p.Signer = s
	return nil
}

// defaultAgentTTL governs agent-zone answers, and through the SOA MINIMUM the
// negative caching of everything else under the agent domain.
//
// Five minutes, against the probe zone's ten seconds, because the two TTLs are
// answering opposite questions. A probe answer describes one visitor at one
// moment and must not be reused. A report answer exists to be reused: RFC 9567
// §6.2 leans on this cache to hold a reporting resolver to one report query per
// TTL for the same problem, so a short value here converts a persistently broken
// resolver into a flood of reports about the same failure. Long enough to dampen
// that, short enough that a repeat inside a ten-minute store TTL still lands.
const defaultAgentTTL = 300

// validateAgentDomain checks the RFC 9567 configuration and applies defaults.
//
// The subdomain checks are normative, not tidiness. RFC 9567 §6.3: "The agent
// domain MUST NOT be a subdomain of the domain it is reporting on." The reason
// is a deadlock — if resolving the agent domain requires first resolving the
// zone that is failing, the report can never be delivered, and the failure
// modes this lab manufactures on purpose are exactly the ones that would trip
// it. The reverse nesting is rejected too, on this plugin's own account: with
// the probe zone under the agent domain, ServeDNS could not tell a probe name
// from a report name, and the more permissive parser would win silently.
func (p *Probe) validateAgentDomain(c *caddy.Controller) error {
	if p.AgentDomain == "" {
		if p.AgentTTL != 0 {
			//nolint:wrapcheck // caddyfile Dispenser errors are already user-facing config errors
			return c.Err("agent_ttl set without agent_domain")
		}
		return nil
	}
	if p.AgentDomain == "." {
		// RFC 9567 §6.1 forbids advertising the null label, and serving it here
		// would claim the entire namespace.
		//nolint:wrapcheck // caddyfile Dispenser errors are already user-facing config errors
		return c.Err("agent_domain must not be the root")
	}
	if dns.IsSubDomain(p.Zone, p.AgentDomain) {
		//nolint:wrapcheck // caddyfile Dispenser errors are already user-facing config errors
		return c.Errf("agent_domain %s is inside the zone %s it reports on; RFC 9567 §6.3 forbids it, "+
			"because a resolver that cannot resolve the zone cannot deliver the report either",
			p.AgentDomain, p.Zone)
	}
	if dns.IsSubDomain(p.AgentDomain, p.Zone) {
		//nolint:wrapcheck // caddyfile Dispenser errors are already user-facing config errors
		return c.Errf("zone %s is inside agent_domain %s; probe names and report names would be indistinguishable",
			p.Zone, p.AgentDomain)
	}
	if p.AgentTTL == 0 {
		p.AgentTTL = defaultAgentTTL
	}
	return nil
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
			//nolint:wrapcheck // caddyfile Dispenser errors are already user-facing config errors
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
		//nolint:wrapcheck // caddyfile Dispenser errors are already user-facing config errors
		return nil, c.Err("valkey requires valkey_ca so the server certificate can be verified")
	}
	vc.TTL, vc.MaxPerToken = ttl, maxPerToken
	return NewValkeyStore(vc)
}

func parseIntArg(c *caddy.Controller) (int, error) {
	if !c.NextArg() {
		//nolint:wrapcheck // caddyfile Dispenser errors are already user-facing config errors
		return 0, c.ArgErr()
	}
	var v int
	if _, err := fmt.Sscanf(c.Val(), "%d", &v); err != nil {
		//nolint:wrapcheck // caddyfile Dispenser errors are already user-facing config errors
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
		//nolint:wrapcheck // caddyfile Dispenser errors are already user-facing config errors
		return 0, c.Errf("value %d out of range", v)
	}
	return uint32(v), nil
}

func parseDurationArg(c *caddy.Controller) (time.Duration, error) {
	if !c.NextArg() {
		//nolint:wrapcheck // caddyfile Dispenser errors are already user-facing config errors
		return 0, c.ArgErr()
	}
	d, err := time.ParseDuration(c.Val())
	if err != nil {
		//nolint:wrapcheck // caddyfile Dispenser errors are already user-facing config errors
		return 0, c.Errf("%q is not a duration", c.Val())
	}
	if d <= 0 {
		//nolint:wrapcheck // caddyfile Dispenser errors are already user-facing config errors
		return 0, c.Errf("duration %q must be positive", c.Val())
	}
	return d, nil
}

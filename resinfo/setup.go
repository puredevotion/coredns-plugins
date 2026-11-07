package resinfo

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/miekg/dns"
)

const (
	// The record's TTL when the Corefile sets none.
	defaultTTL = 3600
	// RFC 2181 §8's largest TTL, 2^31 - 1.
	maxTTL = 1<<31 - 1
	// RFC 6763 §6.2's ceiling for the RDATA: "Using TXT records larger than
	// 1300 bytes is NOT RECOMMENDED".
	warnRDATA = 1300
)

func init() { plugin.Register(pluginName, setup) }

func setup(c *caddy.Controller) error {
	cfg, err := parse(c)
	if err != nil {
		return plugin.Error(pluginName, err) //nolint:wrapcheck // plugin.Error is CoreDNS's setup-error convention
	}
	r := newResInfo(cfg.names, cfg.info, cfg.ttl)
	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		r.Next = next
		return r
	})
	return nil
}

// config is one parsed `resinfo` block.
type config struct {
	names []string
	info  Info
	ttl   uint32
}

// parse reads `resinfo NAME... { ... }`. Every malformed input is an error:
// a resolver that publishes capabilities it was not configured with is worse
// than one that does not start.
func parse(c *caddy.Controller) (config, error) {
	cfg := config{ttl: defaultTTL}
	if !c.Next() {
		return cfg, fmt.Errorf("resinfo: %w", c.ArgErr())
	}
	names, err := parseNames(c.RemainingArgs(), c.ServerBlockKeys)
	if err != nil {
		return cfg, err
	}
	cfg.names = names

	var pairs []Pair
	seen := map[string]bool{}
	for c.NextBlock() {
		name, args := c.Val(), c.RemainingArgs()
		if seen[name] {
			return cfg, fmt.Errorf("duplicate %s", name)
		}
		seen[name] = true
		if name == "ttl" {
			if cfg.ttl, err = parseTTL(args); err != nil {
				return cfg, err
			}
			continue
		}
		p, perr := directivePair(name, args)
		if perr != nil {
			return cfg, perr
		}
		pairs = append(pairs, p)
	}
	if c.Next() {
		return cfg, errors.New("resinfo may be given once per server block; list every name on the one line")
	}
	if cfg.info, err = New(pairs...); err != nil {
		return cfg, err
	}
	if err := replyFits(cfg.names, cfg.info); err != nil {
		return cfg, err
	}
	if n := cfg.info.WireLen(); n > warnRDATA {
		log.Warningf("RESINFO RDATA is %d octets; RFC 6763 §6.2 does not recommend more than %d", n, warnRDATA)
	}
	return cfg, nil
}

// replyFits checks that the answer for every name fits in one DNS message
// (65535 octets, RFC 1035 §4.2.2), compressed and with an OPT RR, as it
// would go out over TCP. RDATA up to 65535 octets is valid on its own, but
// with the header, question and owner around it a record near that limit
// can never be sent: CoreDNS would truncate it to an empty TC reply even
// over TCP, so the plugin would answer every RESINFO query with nothing.
func replyFits(names []string, info Info) error {
	r := newResInfo(names, info, 0)
	for _, n := range names {
		req := new(dns.Msg)
		req.SetQuestion(n, dns.TypeRESINFO)
		m := r.reply(req)
		m.SetEdns0(dns.MaxMsgSize, false)
		m.Compress = true
		if l := m.Len(); l > dns.MaxMsgSize {
			return fmt.Errorf("the RESINFO reply for %s is %d octets, over the %d of a DNS message (RFC 1035 §4.2.2)", n, l, dns.MaxMsgSize)
		}
	}
	return nil
}

// directivePair turns one block line into the pair it publishes.
func directivePair(name string, args []string) (Pair, error) {
	switch name {
	case KeyQNameMin, KeyDeleg:
		if len(args) != 0 {
			return Pair{}, fmt.Errorf("%s takes no arguments", name)
		}
		return Pair{Key: name}, nil
	case KeyExtErr:
		if len(args) == 0 {
			return Pair{}, errors.New("exterr needs at least one INFO-CODE or LO-HI range")
		}
		rs := make([]Range, 0, len(args))
		for _, a := range args {
			r, err := ParseExtErrItem(a)
			if err != nil {
				return Pair{}, err
			}
			rs = append(rs, r)
		}
		return Pair{Key: name, Value: FormatExtErr(CanonicalRanges(rs)), HasValue: true}, nil
	case KeyInfoURL:
		if len(args) != 1 {
			return Pair{}, errors.New("infourl takes exactly one https URL")
		}
		return Pair{Key: name, Value: args[0], HasValue: true}, nil
	}
	if strings.HasPrefix(name, TempPrefix) {
		switch len(args) {
		case 0:
			return Pair{Key: name}, nil
		case 1:
			return Pair{Key: name, Value: args[0], HasValue: true}, nil
		}
		return Pair{}, fmt.Errorf("%s takes at most one value", name)
	}
	return Pair{}, fmt.Errorf("unknown property %q", name)
}

// parseTTL reads `ttl SECONDS`, 0 to 2^31-1 (RFC 2181 §8).
func parseTTL(args []string) (uint32, error) {
	if len(args) != 1 {
		return 0, errors.New("ttl takes exactly one value")
	}
	n, err := strconv.ParseUint(args[0], 10, 32)
	if err != nil || n > maxTTL {
		return 0, fmt.Errorf("ttl %q: want 0 to %d seconds", args[0], maxTTL)
	}
	return uint32(n), nil
}

// parseNames canonicalises the resolver names and checks each one is inside
// a zone of this server block, so that queries for it reach the plugin at
// all.
func parseNames(args, serverBlock []string) ([]string, error) {
	if len(args) == 0 {
		return nil, errors.New("resinfo needs at least one resolver name: its authentication domain name (RFC 9463), or resolver.arpa (RFC 9462)")
	}
	zones := plugin.Zones(plugin.OriginsFromArgsOrServerBlock(nil, serverBlock))
	out := make([]string, 0, len(args))
	for _, a := range args {
		n, err := parseName(a)
		if err != nil {
			return nil, err
		}
		if slices.Contains(out, n) {
			return nil, fmt.Errorf("name %q listed twice", a)
		}
		if len(zones) > 0 && zones.Matches(n) == "" {
			return nil, fmt.Errorf("name %q is outside every zone of this server block %v", n, []string(zones))
		}
		out = append(out, n)
	}
	return out, nil
}

// parseName returns name lowercased (ASCII only, RFC 4343) and fully
// qualified. The root is refused: it is no resolver's name.
func parseName(name string) (string, error) {
	b := []byte(name)
	for i := range b {
		b[i] = lowerASCII(b[i])
	}
	n := dns.Fqdn(string(b))
	if _, ok := dns.IsDomainName(n); !ok || n == "." {
		return "", fmt.Errorf("%q is not a resolver name", name)
	}
	return n, nil
}

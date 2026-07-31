package probe

import (
	"errors"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// What this file is for
//
// The point of the probe zone is not the answer — it is what we learn about the
// resolver that asked. Because the query name is unique per visitor, every
// property below is attributable to one browser session, which is what lets the
// web tier say "your resolver did X" truthfully instead of guessing from the
// browser's own IP (which is usually not the resolver's at all).
//
// Everything here is derived from a single query. Nothing is inferred across
// queries except Seen, the per-token counter, which is itself a signal:
// resolvers that duplicate queries, or that use several egress addresses, show
// up as several observations sharing one token.

// Transport is how the query reached us. Worth recording per-query rather than
// per-listener because a resolver that falls back from one to another (UDP to
// TCP after truncation, or DoT to Do53) reveals its behaviour in the change.
type Transport string

const (
	TransportUDP  Transport = "udp"
	TransportTCP  Transport = "tcp"
	TransportTLS  Transport = "tls"
	TransportQUIC Transport = "quic"
	TransportHTTP Transport = "https"
)

// Observation is one query, as seen from the authoritative side.
type Observation struct {
	Token string    `json:"token"`
	At    time.Time `json:"at"`

	// ResolverAddr is the source address of the query: the resolver's egress
	// address, NOT the visitor's. The difference is the single most common
	// misconception these pages exist to correct.
	ResolverAddr netip.Addr `json:"resolver_addr"`
	// ResolverPrefix groups egress addresses that belong to one network, so a
	// resolver pool spread across many addresses still reads as one operator.
	// Same widths as response rate limiting uses (/24, /56) and for the same
	// reason: an individual address is too fine a unit to mean anything.
	ResolverPrefix netip.Prefix `json:"resolver_prefix"`

	Transport Transport `json:"transport"`
	// IPv6 records which protocol carried the query. A resolver reaching us
	// over IPv6 for a visitor on IPv4 (and the reverse) is common and worth
	// showing.
	IPv6 bool `json:"ipv6"`

	Qtype string `json:"qtype"`
	// Mods is the deviation set the query asked for, so a validation failure
	// can be attributed to the variant that provoked it.
	Mods string `json:"mods"`

	// DO set means the resolver asked for DNSSEC records. Necessary but not
	// sufficient for validation — plenty of resolvers set DO and then ignore
	// what comes back, which is exactly what the badsig/unsigned variants
	// expose.
	DO bool `json:"do"`
	// EDNS records whether an OPT record was present at all. Its absence dates
	// a resolver severely.
	EDNS bool `json:"edns"`
	// UDPSize is the advertised EDNS buffer. Values above ~1232 invite
	// fragmentation; the DNS-flag-day-2020 consensus is to advertise no more.
	UDPSize uint16 `json:"udp_size"`
	// Cookie means the resolver supports DNS cookies (RFC 7873), which is what
	// lets an authoritative server distinguish a return-path-validated client
	// from a spoofed source.
	Cookie bool `json:"cookie"`
	// ECS means the resolver forwarded a client-subnet prefix — a privacy leak
	// the visitor probably did not opt into, and worth surfacing as such.
	//
	// Read ECS together with ECSScope, never alone. There are THREE states, and
	// collapsing them to two gets the interesting one backwards:
	//
	//	ECS=false                 no option sent — resolver says nothing
	//	ECS=true, ECSScope=0      option sent with SOURCE PREFIX-LENGTH 0, i.e.
	//	                          the resolver deliberately DECLINED to disclose
	//	ECS=true, ECSScope>0      resolver disclosed ECSScope bits of the client
	//
	// The middle case is the *best* outcome (RFC 7871 §7.1.2's explicit opt-out)
	// and must never render as "leaked".
	ECS bool `json:"ecs"`
	// ECSScope is SOURCE PREFIX-LENGTH from the query — how many bits of the
	// client address the resolver disclosed. 0 when absent OR when explicitly
	// declined; see ECS.
	//
	// Named "Scope" for the field's history, not for accuracy: RFC 7871 calls
	// the response-side field SCOPE PREFIX-LENGTH, and this is the query-side
	// SOURCE PREFIX-LENGTH. Kept as-is because the web tier's
	// internal/probereport mirrors this JSON tag and renaming would break the
	// seam for no measurement benefit.
	ECSScope uint8 `json:"ecs_scope"`
	// ECSFamily is the RFC 7871 address family of the disclosed prefix (1=IPv4,
	// 2=IPv6), 0 when absent. Worth its own field because a resolver disclosing
	// an IPv6 prefix for an IPv4 client (or the reverse) is itself a finding.
	ECSFamily uint16 `json:"ecs_family"`
	// ECSPrefix is the prefix the resolver actually disclosed, zero when absent
	// or declined.
	//
	// This is the most identifying thing this plugin stores — it is a truncated
	// form of the visitor's own address, which nothing else here records. It is
	// kept only because showing someone what leaked is the entire point of the
	// measurement, it is reachable only via the random token the visitor holds,
	// and it expires with the rest of the observation on the store's TTL. Do not
	// add a second index over it.
	ECSPrefix netip.Prefix `json:"ecs_prefix"`

	// DELEGAware means the resolver set the EDNS DE bit, signalling that it
	// understands extensible delegation (draft-ietf-deleg). DELEG-unaware
	// servers ignore the bit, so a resolver setting it is opting in to being
	// measured for it — which is why this costs nothing and risks nothing.
	//
	// See degFlag's comment for why this specific bit, and what would make it
	// silently wrong.
	DELEGAware bool `json:"deleg_aware"`
	// KeyTags are the DNSSEC key tags the resolver signalled it would validate
	// this response with (RFC 8145 edns-key-tag, EDNS option 14). Empty when the
	// resolver said nothing, which is the overwhelmingly common case.
	KeyTags []uint16 `json:"key_tags,omitempty"`
	// KnowsZoneKey means this zone's own key tag was among KeyTags — i.e. the
	// resolver is holding the key it would need to validate us. Meaningful only
	// when KeyTags is non-empty; false otherwise means "did not say", not "does
	// not have it".
	KnowsZoneKey bool `json:"knows_zone_key,omitempty"`

	// ZoneVersionAsked means the resolver sent an RFC 9660 ZONEVERSION option,
	// i.e. asked which version of the zone answered. Vanishingly rare, which is
	// what makes it worth counting: it is a direct measure of how much
	// diagnostic protocol a resolver actually implements.
	ZoneVersionAsked bool `json:"zoneversion_asked"`

	// CompactAware means the resolver set the EDNS CO bit (RFC 9824),
	// signalling it understands compact denial of existence. This zone already
	// SERVES compact denial via the `_nxname` variant, so pairing the two tells
	// us something neither does alone: whether the resolvers that receive our
	// compact denials actually asked for them.
	CompactAware bool `json:"compact_aware"`

	// CaseRandomized means the query arrived with mixed-case labels, i.e. the
	// resolver implements DNS-0x20 (draft-vixie-dnsext-dns0x20) as an
	// anti-spoofing measure. Detectable only because we compare against the
	// name we would have generated ourselves.
	CaseRandomized bool `json:"case_randomized"`

	// Seen is this observation's ordinal for the token, starting at 1. Set by
	// the store, not the observer.
	Seen int `json:"seen"`
}

// v4PrefixBits and v6PrefixBits mirror response-rate-limiting's defaults.
const (
	v4PrefixBits = 24
	v6PrefixBits = 56
)

// EDNS header flag bits, as they sit in the OPT record's 16-bit flags field
// (the low half of OPT.Hdr.Ttl). miekg/dns exposes only DO, via Do()/SetDo, so
// the other two are masked by hand.
//
// Bit numbering is MSB-first per RFC 6891, hence bit 0 == 1<<15:
//
//	bit 0  DO  DNSSEC OK                (RFC 4035)     -> 1<<15  0x8000
//	bit 1  CO  Compact denial understood (RFC 9824)     -> 1<<14  0x4000
//	bit 2  DE  DELEG enabled             (draft-ietf-deleg) -> 1<<13  0x2000
//
// CAVEAT, and the reason both constants are declared here with this comment
// rather than inlined: DE is **not yet permanently assigned**.
// draft-ietf-deleg-08 says the bit is "expected to be assigned by IANA as Bit 2
// in the EDNS Header Flags registry" and separately gives 2 as a *temporary
// testing* assignment, with the permanent request written as "Bit TBA2". If IANA
// lands it elsewhere, this code keeps compiling and keeps returning a plausible
// answer that is simply wrong — the worst failure mode for a measurement. Re-check
// the registry against the current draft before trusting DELEGAware, and treat a
// sudden collapse to all-false (or all-true) as suspicion of a moved bit rather
// than a finding about resolvers.
const (
	coFlag = 1 << 14 // RFC 9824, assigned
	deFlag = 1 << 13 // draft-ietf-deleg, PROVISIONAL — see above
)

// Observe builds an Observation from a query. `raw` is the qname exactly as it
// arrived, before any normalisation, because case is itself a measurement.
func Observe(q Query, raw string, addr netip.Addr, transport Transport, qtype uint16, msg *dns.Msg) Observation {
	addr = addr.Unmap()
	bits := v4PrefixBits
	if addr.Is6() {
		bits = v6PrefixBits
	}
	prefix, err := addr.Prefix(bits)
	if err != nil {
		// Only possible if bits exceeds the address width, which the branch
		// above prevents; fall back to a host route rather than dropping the
		// observation.
		prefix = netip.PrefixFrom(addr, addr.BitLen())
	}

	obs := Observation{
		Token:          q.Token,
		At:             time.Now().UTC(),
		ResolverAddr:   addr,
		ResolverPrefix: prefix,
		Transport:      transport,
		IPv6:           addr.Is6(),
		Qtype:          dns.TypeToString[qtype],
		Mods:           q.Mods.String(),
		CaseRandomized: isCaseRandomized(raw),
	}
	if obs.Qtype == "" {
		obs.Qtype = "TYPE" + strconv.Itoa(int(qtype))
	}

	if opt := msg.IsEdns0(); opt != nil {
		obs.EDNS = true
		obs.DO = opt.Do()
		obs.UDPSize = opt.UDPSize()

		// Flags miekg/dns has no accessor for. Masked off the same 16-bit field
		// Do() reads; see coFlag/deFlag for the bit numbering and the caveat on
		// DE not being permanently assigned.
		obs.CompactAware = opt.Hdr.Ttl&coFlag != 0
		obs.DELEGAware = opt.Hdr.Ttl&deFlag != 0

		for _, o := range opt.Option {
			switch v := o.(type) {
			case *dns.EDNS0_COOKIE:
				obs.Cookie = true
			case *dns.EDNS0_ZONEVERSION:
				obs.ZoneVersionAsked = true
			case *dns.EDNS0_LOCAL:
				// RFC 8145 option 14 has no type in miekg/dns, so it lands here.
				// Decoded rather than ignored; a malformed payload records
				// nothing rather than a truncated tag list.
				if v.Code == ednsKeyTagOption {
					if tags, ok := parseEDNSKeyTags(v.Data); ok {
						obs.KeyTags = tags
					}
				}
			case *dns.EDNS0_SUBNET:
				obs.ECS = true
				obs.ECSScope = v.SourceNetmask
				obs.ECSFamily = v.Family
				// SourceNetmask 0 is a deliberate "I am telling you nothing"
				// (RFC 7871 §7.1.2), not a missing value, so it must not become
				// a 0-bit prefix over 0.0.0.0 — that would render as a leak of
				// everything. Leave ECSPrefix zero and let ECS+ECSScope carry
				// the distinction.
				if v.SourceNetmask > 0 {
					if a, ok := netip.AddrFromSlice(v.Address); ok {
						if p, err := a.Unmap().Prefix(int(v.SourceNetmask)); err == nil {
							obs.ECSPrefix = p
						}
						// A SourceNetmask wider than the address family allows is
						// malformed input from the resolver. Dropped silently on
						// purpose: ECS/ECSScope still record that it happened, and
						// a malformed option must not cost the visitor their answer.
					}
				}
			}
		}
	}
	return obs
}

// isCaseRandomized reports whether the name mixes upper and lower case, which
// only a resolver deliberately randomizing it would produce: the names this
// zone hands out are lowercase hex and underscore keywords.
//
// A name that is entirely uppercase is NOT randomization — that is just a
// client shouting — so both cases must be present to count.
func isCaseRandomized(name string) bool {
	var hasUpper, hasLower bool
	for i := 0; i < len(name); i++ {
		switch c := name[i]; {
		case c >= 'A' && c <= 'Z':
			hasUpper = true
		case c >= 'a' && c <= 'z':
			hasLower = true
		}
		if hasUpper && hasLower {
			return true
		}
	}
	return false
}

// Summary renders the observation as the in-band TXT payload, so a bare `dig`
// user gets the same readout as the web page without any correlation store
// being involved at all. Deliberately a flat key=value list: it has to survive
// being read in a terminal, split across 255-byte TXT strings.
func (o Observation) Summary() string {
	var b strings.Builder
	b.WriteString("resolver=")
	b.WriteString(o.ResolverAddr.String())
	b.WriteString(" prefix=")
	b.WriteString(o.ResolverPrefix.String())
	b.WriteString(" proto=")
	b.WriteString(string(o.Transport))
	b.WriteString(" ipv6=")
	b.WriteString(boolStr(o.IPv6))
	b.WriteString(" edns=")
	b.WriteString(boolStr(o.EDNS))
	b.WriteString(" do=")
	b.WriteString(boolStr(o.DO))
	b.WriteString(" bufsize=")
	b.WriteString(strconv.Itoa(int(o.UDPSize)))
	b.WriteString(" cookie=")
	b.WriteString(boolStr(o.Cookie))
	b.WriteString(" ecs=")
	b.WriteString(boolStr(o.ECS))
	// ecs_src is what separates "declined" from "leaked", and a bare ecs= flag
	// cannot: `ecs=1 ecs_src=0` is a resolver explicitly refusing to disclose,
	// which is the opposite finding from `ecs=1 ecs_src=24`. Emitted always, so
	// the terminal readout carries all three states the JSON does.
	b.WriteString(" ecs_src=")
	b.WriteString(strconv.Itoa(int(o.ECSScope)))
	if o.ECSPrefix.IsValid() {
		b.WriteString(" ecs_prefix=")
		b.WriteString(o.ECSPrefix.String())
	}
	b.WriteString(" co=")
	b.WriteString(boolStr(o.CompactAware))
	b.WriteString(" deleg=")
	b.WriteString(boolStr(o.DELEGAware))
	b.WriteString(" zoneversion=")
	b.WriteString(boolStr(o.ZoneVersionAsked))
	b.WriteString(" case0x20=")
	b.WriteString(boolStr(o.CaseRandomized))
	b.WriteString(" seen=")
	b.WriteString(strconv.Itoa(o.Seen))
	return b.String()
}

func boolStr(v bool) string {
	if v {
		return "1"
	}
	return "0"
}

// Store holds observations long enough for the web tier to read them back
// against a token, and no longer.
//
// This is the seam between the two programs in this design: this plugin writes,
// the (separately licensed, separately deployed) web tier reads. Keeping it an
// interface means the DNS path has no compile-time dependency on whichever
// backing store is in use, and tests need no external service.
type Store interface {
	// Record stores one observation and returns it with Seen populated. It must
	// not block the DNS response path for long — an unavailable store is a
	// degraded probe, not a failed query.
	Record(obs Observation) (Observation, error)
	// Lookup returns everything recorded for a token, oldest first.
	Lookup(token string) ([]Observation, error)
}

// MemStore is an in-process Store with time-based expiry. It is the default so
// that the plugin is useful (and testable) with no external dependency; a
// multi-replica deployment needs a shared store instead, since a visitor's
// queries and their report request can land on different pods.
type MemStore struct {
	// TTL bounds how long a token remains readable. Short by design: this is
	// transient diagnostic state about someone's network, not a record to keep.
	TTL time.Duration
	// MaxTokens bounds memory. A public zone invites someone to walk the token
	// space purely to grow this map, so it needs a ceiling independent of TTL.
	MaxTokens int
	// MaxPerToken bounds observations per token, so a resolver hammering one
	// name cannot grow a single entry without limit.
	MaxPerToken int

	mu      sync.Mutex
	entries map[string]*memEntry
}

type memEntry struct {
	first time.Time
	obs   []Observation
}

// ErrStoreFull means the token ceiling was reached, so this observation was not
// retained. The query is still answered: a probe that fails to record is
// degraded, not broken, and refusing to answer would turn a memory limit into
// an outage.
var ErrStoreFull = errors.New("probe: observation store full")

// Defaults chosen to be safe rather than generous: this store exists to bridge
// a page load, not to accumulate history.
const (
	defaultStoreTTL    = 10 * time.Minute
	defaultMaxTokens   = 10000
	defaultMaxPerToken = 64
)

// NewMemStore returns a MemStore with defaults applied for any zero field.
func NewMemStore(ttl time.Duration, maxTokens, maxPerToken int) *MemStore {
	if ttl <= 0 {
		ttl = defaultStoreTTL
	}
	if maxTokens <= 0 {
		maxTokens = defaultMaxTokens
	}
	if maxPerToken <= 0 {
		maxPerToken = defaultMaxPerToken
	}
	return &MemStore{
		TTL:         ttl,
		MaxTokens:   maxTokens,
		MaxPerToken: maxPerToken,
		entries:     make(map[string]*memEntry),
	}
}

// Record implements Store.
func (s *MemStore) Record(obs Observation) (Observation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := obs.At
	if now.IsZero() {
		now = time.Now().UTC()
		obs.At = now
	}
	s.expireLocked(now)

	e, ok := s.entries[obs.Token]
	if !ok {
		// Refuse new tokens rather than evicting existing ones: dropping a
		// token mid-session would corrupt a real visitor's results to make room
		// for whoever is flooding us.
		if len(s.entries) >= s.MaxTokens {
			obs.Seen = 1
			return obs, ErrStoreFull
		}
		e = &memEntry{first: now}
		s.entries[obs.Token] = e
	}

	obs.Seen = len(e.obs) + 1
	if len(e.obs) >= s.MaxPerToken {
		// Keep the count truthful even once we stop retaining detail — "seen
		// 200 times" is itself the interesting finding.
		return obs, nil
	}
	e.obs = append(e.obs, obs)
	return obs, nil
}

// Lookup implements Store.
func (s *MemStore) Lookup(token string) ([]Observation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked(time.Now().UTC())

	e, ok := s.entries[token]
	if !ok {
		return nil, nil
	}
	out := make([]Observation, len(e.obs))
	copy(out, e.obs)
	return out, nil
}

// expireLocked drops entries whose first observation is older than TTL. Expiry
// is keyed on first-seen, not last-seen, so a token cannot be kept alive
// indefinitely by continuing to query it.
func (s *MemStore) expireLocked(now time.Time) {
	for token, e := range s.entries {
		if now.Sub(e.first) > s.TTL {
			delete(s.entries, token)
		}
	}
}

// Len reports the number of live tokens. For tests and metrics.
func (s *MemStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked(time.Now().UTC())
	return len(s.entries)
}

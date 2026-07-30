package probe

import (
	"strings"
)

// Query grammar
//
// A probe query name, relative to the plugin's zone, is:
//
//	[_option[._option...].]<token>
//
// so a full qname looks like:
//
//	a1b2c3d4.check.example.com.                        baseline
//	_unsigned.a1b2c3d4.check.example.com.              one modifier
//	_badsig._truncate.a1b2c3d4.check.example.com.      several
//
// The <token> label sits closest to the zone because it is the stable
// per-visitor identity: everything to its left modifies how this one query is
// answered, and the token is what correlates a browser session with the queries
// its resolver actually made. Modifiers are underscore-prefixed, following the
// RFC 8552 "attrleaf" convention for labels that are not hostnames — so a
// modifier can never be mistaken for, or collide with, a real name someone
// might want to look up in the zone.
//
// Why the token has to be unique per visit: a random label defeats every cache
// between the visitor and this server, which is the whole mechanism. Without
// it, a resolver that already answered someone else's identical query serves
// from cache and we observe nothing.
//
// Modifiers are order-insensitive and each may appear at most once. Anything
// that does not parse is REFUSED rather than guessed at — a probe zone that
// silently reinterprets a malformed request produces measurements nobody can
// trust.

// Modifier is one deliberate deviation from a normal, correctly signed answer.
type Modifier uint16

const (
	// ModUnsigned omits RRSIGs entirely. Against a signed zone a validating
	// resolver must treat the answer as bogus, so this is the "does your
	// resolver actually validate?" probe.
	ModUnsigned Modifier = 1 << iota
	// ModBadSig returns an RRSIG whose signature bytes are corrupt. Distinct
	// from ModUnsigned: it tests signature verification rather than the
	// presence check, and some resolvers get exactly one of the two right.
	ModBadSig
	// ModExpiredSig returns a structurally valid signature whose validity
	// window closed in the past — tests clock/validity enforcement.
	ModExpiredSig
	// ModFutureSig returns a signature not yet valid. The mirror of
	// ModExpiredSig, and the case implementations more often forget.
	ModFutureSig
	// ModTruncate sets TC=1 and drops the answer section, forcing a
	// well-behaved client to retry over TCP.
	ModTruncate
	// ModNXDOMAIN answers NXDOMAIN for a name that would otherwise exist.
	ModNXDOMAIN
	// ModServfail answers SERVFAIL, the failure mode most often confused with
	// a DNSSEC validation failure.
	ModServfail
	// ModBig returns a deliberately large answer. This is the amplification
	// demonstration, so it is also the one modifier that is dangerous to leave
	// reachable without rate limiting in front of it.
	ModBig
)

// modifierNames maps the wire label (without its leading underscore) to the
// modifier. Keep this the single source of truth: String() and the parser both
// derive from it, so adding a modifier means touching one place.
var modifierNames = map[string]Modifier{
	"unsigned":   ModUnsigned,
	"badsig":     ModBadSig,
	"expiredsig": ModExpiredSig,
	"futuresig":  ModFutureSig,
	"truncate":   ModTruncate,
	"nxdomain":   ModNXDOMAIN,
	"servfail":   ModServfail,
	"big":        ModBig,
}

// Has reports whether m includes every modifier in want.
func (m Modifier) Has(want Modifier) bool { return m&want == want }

// String renders the set in a stable order for logging and tests.
func (m Modifier) String() string {
	if m == 0 {
		return "none"
	}
	// Iterate the ordered slice rather than the map so output is deterministic.
	var set []string
	for _, name := range modifierOrder {
		if m.Has(modifierNames[name]) {
			set = append(set, name)
		}
	}
	return strings.Join(set, ",")
}

// modifierOrder fixes String()'s output order (map iteration is randomized).
var modifierOrder = []string{
	"unsigned", "badsig", "expiredsig", "futuresig",
	"truncate", "nxdomain", "servfail", "big",
}

// conflicts lists modifier pairs that cannot both apply to one answer, so a
// query asking for both is a client error rather than something to resolve by
// precedence. Signature variants are mutually exclusive because there is only
// one signature to spoil, and rcode variants because there is only one rcode.
var conflicts = []Modifier{
	ModUnsigned | ModBadSig | ModExpiredSig | ModFutureSig,
	ModNXDOMAIN | ModServfail,
}

// Query is a parsed probe request.
type Query struct {
	// Token is the per-visitor correlation label, lowercased.
	Token string
	// Mods is the set of requested deviations.
	Mods Modifier
}

const (
	minTokenLen = 8
	maxTokenLen = 32
)

// ParseQuery parses the part of a qname that sits below the zone. `sub` must
// already have the zone stripped and must not be fully qualified.
//
// It returns ok=false for anything malformed: no token, a token of the wrong
// shape, an unknown modifier, a repeated modifier, or a conflicting pair. The
// caller answers REFUSED in that case.
//
// The empty string means the zone apex, which is not a probe query — apex
// records are handled separately, so this reports ok=false for it too.
func ParseQuery(sub string) (Query, bool) {
	sub = strings.TrimSuffix(sub, ".")
	if sub == "" {
		return Query{}, false
	}

	labels := strings.Split(sub, ".")
	// The token is the rightmost label (closest to the zone).
	tokenLabel := labels[len(labels)-1]
	modLabels := labels[:len(labels)-1]

	token, ok := parseToken(tokenLabel)
	if !ok {
		return Query{}, false
	}

	var mods Modifier
	for _, l := range modLabels {
		name, isMod := strings.CutPrefix(l, "_")
		if !isMod {
			// A bare extra label is not part of this grammar. Refusing beats
			// ignoring it: silently treating `foo.<token>` as the baseline
			// query would report a measurement the caller did not ask for.
			return Query{}, false
		}
		m, known := modifierNames[toLowerASCII(name)]
		if !known {
			return Query{}, false
		}
		if mods.Has(m) {
			return Query{}, false // repeated
		}
		mods |= m
	}

	for _, group := range conflicts {
		if bits := mods & group; bits != 0 && bits != bits&-bits {
			return Query{}, false // more than one bit from a mutually exclusive group
		}
	}

	return Query{Token: token, Mods: mods}, true
}

// parseToken validates the correlation label: hex only, bounded length. Hex
// keeps it case-insensitive in a zone where queries arrive with randomized case
// (0x20 encoding), and bounded length keeps an attacker from using this zone's
// correlation store as free memory.
func parseToken(l string) (string, bool) {
	if len(l) < minTokenLen || len(l) > maxTokenLen {
		return "", false
	}
	lower := toLowerASCII(l)
	for i := 0; i < len(lower); i++ {
		c := lower[i]
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		default:
			return "", false
		}
	}
	return lower, true
}

// toLowerASCII lowercases ASCII only. DNS case-insensitivity is defined over
// ASCII (RFC 4343), and unicode.ToLower would additionally fold non-ASCII bytes
// that have no business appearing in these labels.
func toLowerASCII(s string) string {
	var b []byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			if b == nil {
				b = []byte(s)
			}
			b[i] = c + ('a' - 'A')
		}
	}
	if b == nil {
		return s
	}
	return string(b)
}

package probe

import (
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// RFC 8145 — Signalling Trust Anchor Knowledge in DNSSEC.
//
// A validating resolver can tell a server which DNSSEC key(s) it would use to
// validate that server's answers. This is the mechanism that measured the root
// KSK rollover, and essentially only root operators have ever run the receiving
// side of it.
//
// Two independent mechanisms, and they are NOT equally useful here — worth
// saying plainly rather than implying both are live measurements:
//
//	EDNS option 14 (edns-key-tag). RFC 8145 §4.2: "A DNS client MUST NOT
//	include the edns-key-tag option for non-DNSKEY queries", so a conforming
//	resolver attaches it only to DNSKEY queries, which go to the apex. This
//	zone parses it on probe-token queries, so what it records there comes from
//	senders that break that rule.
//
//	Key Tag queries (`_ta-<hex>...`). RFC 8145 §5.2 has a resolver send one
//	"whenever it also originates a DNSKEY query for a trust anchor zone", to
//	the apex of each CONFIGURED TRUST ANCHOR. This zone is not a
//	configured trust anchor for anybody — it chains from root through a DS — so
//	expect approximately zero of these in practice. Implemented anyway because it
//	is cheap and because the case where one DOES arrive is the interesting one: it
//	means someone pinned this zone as a trust anchor, which is exactly the kind of
//	thing a measurement zone should be able to notice rather than answer REFUSED
//	to.
//
// Key tag values are the RFC 4034 Appendix B tag of a DNSKEY, which is what lets
// "which keys do you hold" be asked without transferring keys.

// keyTagPrefix is the label prefix RFC 8145 §5.1 defines for Key Tag queries.
const keyTagPrefix = "_ta-"

// keyTagHexDigits is RFC 8145 §5.1's mandatory zero-padded width for one key
// tag: a uint16 rendered as exactly four hex digits.
const keyTagHexDigits = 4

// maxKeyTagsPerQuery bounds how many tags will be parsed out of one name or
// option. RFC 8145 §4.2.2.1 only says "It is RECOMMENDED that implementations
// place reasonable limits on the number of Key Tags"; in a query name, RFC 1035's
// 63-octet label caps it at 12 anyway. Sixteen
// is far above any real resolver's trust-anchor set (root has had at most three
// tags in flight during a rollover) and low enough that a name crafted to make us
// allocate is refused rather than walked.
const maxKeyTagsPerQuery = 16

// ErrNotKeyTagQuery means the name is not an RFC 8145 Key Tag query.
var ErrNotKeyTagQuery = errors.New("probe: not a key tag query")

// ErrBadKeyTagQuery means the name had the `_ta-` shape but its contents did not
// parse.
var ErrBadKeyTagQuery = errors.New("probe: malformed key tag query")

// ParseKeyTagQuery decodes the key tags out of an RFC 8145 Key Tag query name.
//
// Per RFC 8145 §5.1 the first label is `_ta-` followed by a sorted,
// hyphen-separated list of key tags, each **zero-padded to exactly four
// hexadecimal digits**, sorted smallest to largest by NUMERIC value. `sub` is the
// query name with the zone already stripped.
//
//	_ta-4444                     -> [0x4444]
//	_ta-0635-7aae-aa1b           -> [0x0635, 0x7aae, 0xaa1b]
//
// Returns the tags in the order they appeared, so a caller can tell whether the
// sender honoured the sort requirement — a detail worth keeping, since this zone
// exists to observe what implementations actually do rather than what they should.
func ParseKeyTagQuery(sub string) ([]uint16, error) {
	label := sub
	if strings.Contains(label, ".") {
		// Key Tag queries are sent to the zone apex, so the prefix must be the
		// only label. Anything deeper is not one.
		return nil, ErrNotKeyTagQuery
	}
	if !strings.HasPrefix(strings.ToLower(label), keyTagPrefix) {
		return nil, ErrNotKeyTagQuery
	}

	rest := label[len(keyTagPrefix):]
	if rest == "" {
		return nil, ErrBadKeyTagQuery
	}

	parts := strings.Split(rest, "-")
	if len(parts) > maxKeyTagsPerQuery {
		return nil, ErrBadKeyTagQuery
	}

	tags := make([]uint16, 0, len(parts))
	for _, p := range parts {
		// Exactly four hex digits. RFC 8145 says MUST zero-pad, so "635" is
		// malformed rather than 0x0635 — accepting it would silently normalise
		// away a real implementation bug this zone exists to see.
		if len(p) != keyTagHexDigits {
			return nil, ErrBadKeyTagQuery
		}
		n, err := strconv.ParseUint(p, 16, 16)
		if err != nil {
			return nil, ErrBadKeyTagQuery
		}
		tags = append(tags, uint16(n))
	}
	return tags, nil
}

// KeyTagsSorted reports whether tags are in the smallest-to-largest order RFC
// 8145 §5.1 requires. Recorded rather than corrected.
func KeyTagsSorted(tags []uint16) bool {
	return sort.SliceIsSorted(tags, func(i, j int) bool { return tags[i] < tags[j] })
}

// FormatKeyTagQuery renders tags as the label RFC 8145 defines, for tests and
// for documentation examples. Sorts a copy, since the wire format requires it.
func FormatKeyTagQuery(tags []uint16) string {
	cp := make([]uint16, len(tags))
	copy(cp, tags)
	slices.Sort(cp)

	var b strings.Builder
	b.WriteString(keyTagPrefix)
	for i, t := range cp {
		if i > 0 {
			b.WriteByte('-')
		}
		fmt.Fprintf(&b, "%04x", t)
	}
	return b.String()
}

// ednsKeyTagOption is RFC 8145 §4.1's OPTION-CODE 14. Miekg/dns has no type for
// it, so it arrives as an EDNS0_LOCAL and is decoded by hand — the same situation
// as the DELEG DE bit.
const ednsKeyTagOption = 14

// parseEDNSKeyTags decodes the edns-key-tag option payload: OPTION-LENGTH is
// 2 x the number of tags, each a 16-bit value in network byte order.
//
// An odd length is malformed. Returning nothing rather than a truncated list is
// deliberate: a half-read tag is a plausible-looking wrong answer, and this is a
// measurement.
func parseEDNSKeyTags(data []byte) ([]uint16, bool) {
	if len(data) == 0 || len(data)%2 != 0 {
		return nil, false
	}
	n := len(data) / uint16Len
	if n > maxKeyTagsPerQuery {
		return nil, false
	}
	tags := make([]uint16, 0, n)
	for i := 0; i < len(data); i += 2 {
		tags = append(tags, binary.BigEndian.Uint16(data[i:i+2]))
	}
	return tags, true
}

// hasKeyTag reports whether want appears in tags.
func hasKeyTag(tags []uint16, want uint16) bool {
	return slices.Contains(tags, want)
}

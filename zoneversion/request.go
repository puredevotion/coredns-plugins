package zoneversion

import "github.com/miekg/dns"

// ask is what a query's ZONEVERSION options amount to.
type ask uint8

const (
	// AskNone means no OPT, or no ZONEVERSION option. The response must not carry
	// one (RFC 9660 §3.2.2: "A name server MUST NOT send a ZONEVERSION option
	// back to a client that did not request it").
	askNone ask = iota
	// AskVersion means exactly one ZONEVERSION option, empty (§3.1).
	askVersion
	// AskMalformed means a ZONEVERSION option that is not empty, or more
	// than one. RFC 9660 §3.2.1: the server "MUST return a FORMERR
	// response".
	askMalformed
)

// optionLength is the OPTION-LENGTH an option had on the wire, as far as the
// in-memory form records it, and whether the option is a ZONEVERSION at all.
//
// The miekg/dns v1.1.73 library unpacks option 19 as *dns.EDNS0_ZONEVERSION, whose
// unpack refuses fewer than two octets (ErrBuf), so a ZONEVERSION it hands us
// always had 2 + len(Version) octets: never the empty query form. The empty
// form can only reach a handler as *dns.EDNS0_LOCAL with Code 19 (built in
// process). TestMiekgRejectsEmptyOption pins that behaviour so an upgrade
// that changes it fails loudly instead of turning every conformant query
// into a FORMERR here. See docs/zoneversion-plugin.md, "The blocker".
func optionLength(o dns.EDNS0) (int, bool) {
	switch v := o.(type) {
	case *dns.EDNS0_ZONEVERSION:
		return headerLen + len(v.Version), true
	case *dns.EDNS0_LOCAL:
		if v.Code == optionCode {
			return len(v.Data), true
		}
	}
	return 0, false
}

// classify decides askNone / askVersion / askMalformed from a query's OPT RR.
// It is the Go side of ZoneVersion.lean's `classify`: askVersion iff exactly
// one ZONEVERSION option and its length is 0. It allocates nothing, because
// every query to the zone goes through it.
func classify(opt *dns.OPT) ask {
	if opt == nil {
		return askNone
	}
	seen := 0
	empty := false
	for _, o := range opt.Option {
		n, ok := optionLength(o)
		if !ok {
			continue
		}
		seen++
		empty = n == 0
	}
	switch {
	case seen == 0:
		return askNone
	case seen == 1 && empty:
		return askVersion
	default:
		return askMalformed
	}
}

// isZoneVersion reports whether o is a ZONEVERSION option in either
// in-memory form.
func isZoneVersion(o dns.EDNS0) bool {
	_, ok := optionLength(o)
	return ok
}

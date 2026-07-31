package probe

import (
	"github.com/miekg/dns"
)

// RFC 8914 — Extended DNS Errors, emitted from the authoritative side.
//
// EDE is overwhelmingly a resolver-side mechanism: the party that DETECTED a
// problem explains it. An authoritative server emitting EDE is unusual, and an
// authoritative emitting EDE about a failure it caused on purpose is, as far as I
// can tell, unique to this zone.
//
// # Why this is worth more than a nicety
//
// It turns the zone into GROUND TRUTH. We know exactly what we broke, because we
// broke it deliberately. Saying so in the response means a resolver's own
// diagnosis can be compared against what actually happened:
//
//   - We serve `_expiredsig` and say EDE 7 (Signature Expired).
//   - The resolver validates, fails, and — if it implements RFC 9567 — reports
//     back the code IT concluded.
//   - Agreement means the resolver diagnosed correctly. DISAGREEMENT is the
//     finding: a resolver that reports "DNSSEC Bogus" for an expired signature is
//     technically right and diagnostically worse, and one that reports nothing at
//     all is worse again.
//
// That comparison is what closes the loop with the RFC 9567 receiver in
// errorreport.go, which until now waited for reports about conditions this zone
// never labelled.
//
// # What is deliberately NOT claimed
//
// EDE is attached only where this zone actually knows the answer. A modifier that
// produces a well-formed response (`_truncate`, `_big`) gets no EDE, because
// nothing is wrong. `_servfail` gets EDE 0 with text rather than a DNSSEC code,
// because a synthetic SERVFAIL is not a validation failure and labelling it as one
// would put a false code into someone else's telemetry.

// edeText is kept short on purpose. EXTRA-TEXT is bytes on every failing response,
// and this zone has a modifier whose entire job is measuring response size — a
// chatty explanation here would quietly move that measurement.
const edeText = "deliberate: dns measurement zone"

// edeFor returns the Extended DNS Error to attach for a given modifier set, or
// nil when this zone has nothing truthful to say.
//
// Order matters where modifiers can combine: the most specific cause wins, so
// `_expiredsig` is reported as expired rather than as generic bogus. A resolver
// receiving "bogus" when we could have said "expired" learns less, which is the
// opposite of the point.
func edeFor(mods Modifier) *dns.EDNS0_EDE {
	switch {
	case mods.Has(ModExpiredSig):
		// Specific beats general: this is bogus, but it is bogus for a knowable
		// reason and RFC 8914 has a code for exactly it.
		return ede(dns.ExtendedErrorCodeSignatureExpired)

	case mods.Has(ModFutureSig):
		return ede(dns.ExtendedErrorCodeSignatureNotYetValid)

	case mods.Has(ModUnsigned):
		// The signature is absent rather than wrong, which is a different
		// diagnosis and a different resolver code path — it depends on having the
		// DS/DNSKEY chain, not on any crypto.
		return ede(dns.ExtendedErrorCodeRRSIGsMissing)

	case mods.Has(ModBadSig):
		// Present, well-formed, and does not verify. "Bogus" is the honest code:
		// there is no RFC 8914 code for "the bytes were tampered with", and
		// inventing a more specific one would be a lie.
		return ede(dns.ExtendedErrorCodeDNSBogus)

	case mods.Has(ModServfail):
		// NOT a DNSSEC code. A synthetic SERVFAIL is not a validation failure, and
		// labelling it as one would inject a false code into whatever telemetry
		// the resolver keeps.
		return ede(dns.ExtendedErrorCodeOther)
	}

	// ModTruncate and ModBig produce correct, well-formed responses. Nothing is
	// wrong, so nothing is claimed. ModNXDOMAIN and ModNXNAME are deliberately
	// left alone too: whether an unprovable denial is "bogus" is the resolver's
	// judgement to make and the experiment being run, so pre-empting it with our
	// own code would contaminate the measurement.
	return nil
}

func ede(code uint16) *dns.EDNS0_EDE {
	return &dns.EDNS0_EDE{InfoCode: code, ExtraText: edeText}
}

// attachEDE adds the option to a response's OPT record.
//
// Requires an OPT to already be present, which is correct rather than defensive:
// RFC 8914 §3 only permits EDE in response to a query that itself carried an OPT
// pseudo-RR. A querier with no EDNS has not opted in to extended errors and must
// not be sent one.
func attachEDE(m *dns.Msg, e *dns.EDNS0_EDE) {
	if e == nil {
		return
	}
	opt := m.IsEdns0()
	if opt == nil {
		return
	}
	// One EDE per response. Repeated codes are permitted by RFC 8914 §2 but say
	// nothing extra here, and every duplicate costs bytes on a response whose size
	// this zone also measures.
	for _, existing := range opt.Option {
		if _, ok := existing.(*dns.EDNS0_EDE); ok {
			return
		}
	}
	opt.Option = append(opt.Option, e)
}

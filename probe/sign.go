package probe

import (
	"crypto"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Why this plugin signs its own answers
//
// CoreDNS already has two signing plugins, and neither fits:
//
//   - `sign` signs a zone FILE offline. This zone has no file — every name is
//     synthesized per query from a token that did not exist a moment ago.
//   - `dnssec` signs on the fly, which is the right shape, but it only ever
//     produces CORRECT signatures. The entire point here is to produce
//     specific, deliberate DNSSEC failures on demand, so that a page can ask
//     "did your resolver actually notice?" and get a truthful answer.
//
// So signing happens here, where the modifier set is known. Everything the
// crypto touches is standard miekg/dns; the only unusual part is the
// deliberate spoiling, which is confined to signRRset below.

// Signer holds the zone's signing key.
type Signer struct {
	key  *dns.DNSKEY
	priv crypto.Signer
	// validity is how long a correct signature stays valid. Short is fine (and
	// preferable) because signatures are minted per query and nothing caches
	// them for long; it also bounds the damage if the key ever leaks.
	validity time.Duration
}

// defaultSigValidity is deliberately short. These signatures cover synthesized
// records with small TTLs, so nothing needs a week-long window, and a narrow
// window makes the expiredsig variant behave sensibly relative to it.
const defaultSigValidity = time.Hour

// LoadSigner reads a keypair in the conventional BIND file layout that
// CoreDNS's own `sign`/`dnssec` plugins use: `basename` names a pair of files,
// `<basename>.key` (the DNSKEY record) and `<basename>.private`.
//
// Using the same layout as those plugins is deliberate — key material for this
// zone can then be generated, rotated, and inspected with the same tooling and
// the same operator habits as every other signed zone in the fleet, instead of
// this plugin inventing a private encoding.
func LoadSigner(basename string, validity time.Duration) (*Signer, error) {
	if validity <= 0 {
		validity = defaultSigValidity
	}

	pubPath := basename + ".key"
	privPath := basename + ".private"

	pubData, err := os.ReadFile(pubPath)
	if err != nil {
		return nil, fmt.Errorf("reading public key %s: %w", pubPath, err)
	}
	rr, err := dns.NewRR(string(pubData))
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", pubPath, err)
	}
	key, ok := rr.(*dns.DNSKEY)
	if !ok {
		return nil, fmt.Errorf("%s contains a %T, want a DNSKEY", pubPath, rr)
	}

	privFile, err := os.Open(privPath)
	if err != nil {
		return nil, fmt.Errorf("reading private key %s: %w", privPath, err)
	}
	defer privFile.Close()

	priv, err := key.ReadPrivateKey(privFile, privPath)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", privPath, err)
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("%s holds a %T, which cannot sign", privPath, priv)
	}

	// A zone-signing key with the wrong owner name produces signatures no
	// validator will accept, and the symptom (everything bogus, no error
	// anywhere) is miserable to debug. Catch it at load time instead.
	if key.Hdr.Rrtype != dns.TypeDNSKEY {
		return nil, fmt.Errorf("%s is not a DNSKEY record", pubPath)
	}

	return &Signer{key: key, priv: signer, validity: validity}, nil
}

// DNSKEY returns the zone's public key record, for answering DNSKEY queries.
func (s *Signer) DNSKEY() *dns.DNSKEY { return s.key }

// Owner returns the zone the key signs, normalised.
func (s *Signer) Owner() string { return dns.CanonicalName(s.key.Hdr.Name) }

// DS returns the delegation signer record to publish at the registrar. Exposed
// so the operator can print it rather than deriving it by hand — a signed zone
// with no DS published validates as insecure, which silently makes every
// validation probe report the boring answer.
func (s *Signer) DS(digest uint8) *dns.DS {
	if digest == 0 {
		digest = dns.SHA256
	}
	return s.key.ToDS(digest)
}

// signRRset signs one RRset, applying whichever signature deviation the query
// asked for. It returns nil (no RRSIG at all) for ModUnsigned.
//
// Each deviation is produced differently on purpose:
//
//   - unsigned:   no RRSIG is emitted. Tests the resolver's "this zone is
//     signed, where is the signature?" check, which depends on it
//     having the DS/DNSKEY chain, not on any crypto.
//   - badsig:     a real signature is computed and then corrupted. Computing
//     first matters — a random byte string in the signature field
//     can be rejected on a length or structure check before any
//     verification happens, which would test something weaker than
//     intended.
//   - expiredsig: correct signature, validity window entirely in the past.
//   - futuresig:  correct signature, validity window entirely in the future.
//
// The last two are genuinely valid signatures, so a resolver that verifies the
// crypto but ignores the timestamps accepts them — which is exactly the bug
// worth surfacing.
func (s *Signer) signRRset(rrs []dns.RR, mods Modifier) (*dns.RRSIG, error) {
	if len(rrs) == 0 {
		return nil, nil
	}
	if mods.Has(ModUnsigned) {
		return nil, nil
	}

	now := time.Now().UTC()
	inception, expiration := now.Add(-s.validity), now.Add(s.validity)
	switch {
	case mods.Has(ModExpiredSig):
		// Window closed well before now, and wide enough that clock skew
		// cannot accidentally make it current.
		expiration = now.Add(-s.validity)
		inception = expiration.Add(-s.validity)
	case mods.Has(ModFutureSig):
		inception = now.Add(s.validity)
		expiration = inception.Add(s.validity)
	}

	hdr := rrs[0].Header()
	sig := &dns.RRSIG{
		Hdr: dns.RR_Header{
			Name:   hdr.Name,
			Rrtype: dns.TypeRRSIG,
			Class:  dns.ClassINET,
			Ttl:    hdr.Ttl,
		},
		TypeCovered: hdr.Rrtype,
		Algorithm:   s.key.Algorithm,
		Labels:      uint8(dns.CountLabel(hdr.Name)),
		OrigTtl:     hdr.Ttl,
		Expiration:  uint32(expiration.Unix()),
		Inception:   uint32(inception.Unix()),
		KeyTag:      s.key.KeyTag(),
		SignerName:  s.Owner(),
	}
	if err := sig.Sign(s.priv, rrs); err != nil {
		return nil, fmt.Errorf("signing %s %s: %w",
			hdr.Name, dns.TypeToString[hdr.Rrtype], err)
	}

	if mods.Has(ModBadSig) {
		sig.Signature = corruptSignature(sig.Signature)
	}
	return sig, nil
}

// corruptSignature invalidates a base64 signature while keeping it the same
// length and still valid base64, so it fails verification rather than failing
// to parse. Flipping a character in the middle avoids the trailing padding,
// where an edit can change the decoded length instead of the decoded value.
func corruptSignature(sig string) string {
	if sig == "" {
		return sig
	}
	trimmed := strings.TrimRight(sig, "=")
	if trimmed == "" {
		return sig
	}
	b := []byte(sig)
	i := len(trimmed) / 2
	// Swap between two characters that are both in the base64 alphabet, so the
	// result decodes cleanly to different bytes.
	if b[i] == 'A' {
		b[i] = 'B'
	} else {
		b[i] = 'A'
	}
	return string(b)
}

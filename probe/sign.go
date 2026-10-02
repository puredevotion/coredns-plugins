package probe

import (
	"crypto"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Why this plugin signs its own answers
//
// CoreDNS already has two signing plugins, and neither fits:
//
//   - `sign` signs a zone FILE offline. This zone has no file — every name is
//     synthesised per query from a token that did not exist a moment ago.
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
	// Owner is the key's owner name, canonicalised once. RRSIG's SignerName
	// field carries it on every signature.
	owner string
	// Validity is how long a correct signature stays valid. Short is fine (and
	// preferable) because signatures are minted per query and nothing caches
	// them for long; it also bounds the damage if the key ever leaks.
	validity time.Duration
	// KeyTag is the RFC 4034 Appendix B tag of key, computed once. The library
	// recomputes it from the base64 public key on every call, and it is needed
	// on every signature and every RFC 8145 comparison.
	keyTag uint16
}

// defaultSigValidity is deliberately short. These signatures cover synthesised
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

	// Both halves of the keypair are opened relative to a *rooted* directory
	// rather than by absolute path. Os.Root confines every lookup beneath that
	// directory: a symlink inside it that points elsewhere, or a name that tries
	// to climb out with "..", fails instead of resolving. The key directory is
	// operator-supplied and usually a mounted Secret, so this costs nothing and
	// removes a whole class of "how did it read THAT file" question.
	root, dir, base, err := openKeyRoot(basename)
	if err != nil {
		return nil, err
	}
	defer func() {
		// Closing a directory handle can only fail in ways the caller cannot act
		// on, and the keys are already loaded by this point.
		if closeErr := root.Close(); closeErr != nil {
			log.Warningf("closing key directory %s: %v", dir, closeErr)
		}
	}()

	pubName, privName := base+".key", base+".private"

	key, err := readDNSKEYFile(root, dir, pubName)
	if err != nil {
		return nil, err
	}

	privFile, err := root.Open(privName)
	if err != nil {
		return nil, fmt.Errorf("reading private key %s in %s: %w", privName, dir, err)
	}
	// Read-only handle: a close error carries no information the caller could
	// act on, and the key material is already parsed by then.
	defer func() {
		if closeErr := privFile.Close(); closeErr != nil {
			log.Warningf("closing private key %s in %s: %v", privName, dir, closeErr)
		}
	}()

	priv, err := key.ReadPrivateKey(privFile, privName)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", privName, err)
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("%s holds a %T, which cannot sign", privName, priv)
	}

	return &Signer{
		key:      key,
		priv:     signer,
		owner:    dns.CanonicalName(key.Hdr.Name),
		validity: validity,
		keyTag:   key.KeyTag(),
	}, nil
}

// openKeyRoot splits basename into its containing directory and file base,
// then opens the directory with os.Root so every subsequent lookup beneath it
// is confined there — see LoadSigner's comment on why that matters.
//
// Split out of LoadSigner purely to keep that function's length down.
func openKeyRoot(basename string) (root *os.Root, dir, base string, err error) {
	dir, base = filepath.Split(basename)
	if dir == "" {
		dir = "."
	}
	if base == "" {
		return nil, "", "", fmt.Errorf("key basename %q names a directory, not a keypair", basename)
	}

	root, err = os.OpenRoot(dir)
	if err != nil {
		return nil, "", "", fmt.Errorf("opening key directory %s: %w", dir, err)
	}
	return root, dir, base, nil
}

// readDNSKEYFile reads and parses the public half of the keypair, confirming
// it decodes to a DNSKEY record.
//
// Split out of LoadSigner purely to keep that function's length down; every
// check and error is unchanged, including the RRTYPE check that used to run
// later — it depends only on the parsed key, not on the private half.
func readDNSKEYFile(root *os.Root, dir, pubName string) (*dns.DNSKEY, error) {
	pubFile, err := root.Open(pubName)
	if err != nil {
		return nil, fmt.Errorf("reading public key %s in %s: %w", pubName, dir, err)
	}
	pubData, err := io.ReadAll(pubFile)
	if closeErr := pubFile.Close(); closeErr != nil {
		log.Warningf("closing public key %s in %s: %v", pubName, dir, closeErr)
	}
	if err != nil {
		return nil, fmt.Errorf("reading public key %s in %s: %w", pubName, dir, err)
	}

	rr, err := dns.NewRR(string(pubData))
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", pubName, err)
	}
	key, ok := rr.(*dns.DNSKEY)
	if !ok {
		return nil, fmt.Errorf("%s contains a %T, want a DNSKEY", pubName, rr)
	}

	// A zone-signing key with the wrong owner name produces signatures no
	// validator will accept, and the symptom (everything bogus, no error
	// anywhere) is miserable to debug. Catch it at load time instead.
	if key.Hdr.Rrtype != dns.TypeDNSKEY {
		return nil, fmt.Errorf("%s is not a DNSKEY record", pubName)
	}

	return key, nil
}

// DNSKEY returns the zone's public key record, for answering DNSKEY queries.
func (s *Signer) DNSKEY() *dns.DNSKEY { return s.key }

// Owner returns the zone the key signs, normalised.
func (s *Signer) Owner() string { return s.owner }

// KeyTag returns the key's RFC 4034 Appendix B tag.
func (s *Signer) KeyTag() uint16 { return s.keyTag }

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
// asked for. It returns ok=false (no RRSIG at all) for ModUnsigned or an empty
// RRset, which is a normal outcome and distinct from err != nil.
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
func (s *Signer) signRRset(rrs []dns.RR, mods Modifier) (sig *dns.RRSIG, ok bool, err error) {
	if len(rrs) == 0 {
		return nil, false, nil
	}
	if mods.Has(ModUnsigned) {
		return nil, false, nil
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

	labels, err := rrsigLabelCount(hdr.Name)
	if err != nil {
		return nil, false, fmt.Errorf("signing %s: %w", hdr.Name, err)
	}
	incept, err := rrsigTime(inception)
	if err != nil {
		return nil, false, fmt.Errorf("signing %s: inception: %w", hdr.Name, err)
	}
	expire, err := rrsigTime(expiration)
	if err != nil {
		return nil, false, fmt.Errorf("signing %s: expiration: %w", hdr.Name, err)
	}

	sig = &dns.RRSIG{
		Hdr: dns.RR_Header{
			Name:   hdr.Name,
			Rrtype: dns.TypeRRSIG,
			Class:  dns.ClassINET,
			Ttl:    hdr.Ttl,
		},
		TypeCovered: hdr.Rrtype,
		Algorithm:   s.key.Algorithm,
		Labels:      labels,
		OrigTtl:     hdr.Ttl,
		Expiration:  expire,
		Inception:   incept,
		KeyTag:      s.keyTag,
		SignerName:  s.owner,
	}
	if err := sig.Sign(s.priv, rrs); err != nil {
		return nil, false, fmt.Errorf("signing %s %s: %w",
			hdr.Name, dns.TypeToString[hdr.Rrtype], err)
	}

	if mods.Has(ModBadSig) {
		sig.Signature = corruptSignature(sig.Signature)
	}
	return sig, true, nil
}

// rrsigLabelCount counts the labels in a name into the single octet RRSIG
// reserves for it (RFC 4034 §3.1.3).
//
// The library's CountLabel walks the name in place; SplitDomainName, which
// this used to range over, allocated a slice of the labels only to count
// them. The bound check keeps the conversion to RRSIG's width explicit: a name
// deep enough to overflow is rejected rather than wrapped.
func rrsigLabelCount(name string) (uint8, error) {
	n := dns.CountLabel(name)
	if n > math.MaxUint8 {
		return 0, fmt.Errorf("more than %d labels, which RRSIG cannot express", math.MaxUint8)
	}
	return uint8(n), nil //nolint:gosec // G115: bounds-checked immediately above; this is the checked conversion itself, not a suppressed truncation.
}

// rrsigYear68 is dns.StringToTime's wrap period: 2^31 seconds, "approximately
// 68 years" in RFC 4034 §3.1.5's words.
const rrsigYear68 = 1 << 31

// rrsigTime renders a time as RRSIG's 32-bit inception/expiration value, with
// the RFC 1982 serial arithmetic RFC 4034 §3.1.5 prescribes: the value is the
// Unix time modulo 2^32, which is what makes the field meaningful past 2106.
//
// This is dns.StringToTime's arithmetic on the time directly. That helper takes
// a YYYYMMDDHHmmSS string, so using it meant formatting the time and parsing
// it straight back — four allocations and a date parse per signature, which
// at two signatures per denial was a measurable share of the non-crypto cost.
// TestRRSIGTimeMatchesLibraryRoundTrip pins this to the library's result, so
// the wrap behaviour cannot drift from what a resolver expects.
func rrsigTime(t time.Time) (uint32, error) {
	unix := t.Unix()
	if unix < 0 {
		return 0, fmt.Errorf("render RRSIG time: %s predates the epoch", t.UTC().Format(time.RFC3339))
	}
	mod := max(unix/rrsigYear68-1, 0)
	return uint32(unix - mod*rrsigYear68), nil //nolint:gosec // G115: unix-mod*2^31 lies in [0, 2^32) once mod is clamped above; this is the RFC 1982 reduction itself.
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
	const midpoint = 2 // Flip the middle byte, away from the trailing padding.
	i := len(trimmed) / midpoint
	// Swap between two characters that are both in the base64 alphabet, so the
	// result decodes cleanly to different bytes.
	if b[i] == 'A' {
		b[i] = 'B'
	} else {
		b[i] = 'A'
	}
	return string(b)
}

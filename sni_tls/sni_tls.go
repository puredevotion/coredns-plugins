package snitls

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"strings"
)

// certStore holds the loaded cert/key pairs keyed by SAN hostname (lowercased),
// plus the fallback (first-loaded) cert for unmatched/absent SNI. See
// ../docs/sni-tls-plugin.md for the verified-DDR caveat on this fallback: with
// more than one cert loaded, an unmatched-SNI client could get served a cert
// without the required IP-SAN, silently defeating RFC 9462 §4.2 verified
// discovery. Set strict to refuse the fallback entirely on such an instance —
// see the `strict` Corefile option in setup.go.
type certStore struct {
	byName   map[string]*tls.Certificate
	fallback *tls.Certificate
	strict   bool
}

// GetCertificate implements the tls.Config.GetCertificate callback: look up the
// client's requested SNI, then its RFC 9525 §6.3 single-label wildcard form
// (dns.sevenwoods.nl -> *.sevenwoods.nl) so a wildcard cert's SAN actually
// gets selected for concrete hostnames under it -- caught live: a real LE
// wildcard cert (*.sevenwoods.nl) loaded alongside a per-host cert silently
// never matched any real SNI at all (the map key was the literal string
// "*.sevenwoods.nl", which no real ClientHello ever sends), falling through
// to the fallback cert on every connection instead. Falls back to the
// first-loaded cert if neither matches, unless strict is set, in which case
// an unmatched or absent SNI fails the handshake instead of guessing.
//
// The strict refusal is (nil, nil), not an error. Since setup() leaves
// tls.Config.Certificates empty, crypto/tls then aborts with a fatal
// unrecognized_name(112) alert, which RFC 6066 §3 says a server that "does
// not recognize the server name" SHOULD send. Any error would go out as
// internal_error(80) instead, telling the client the server is broken
// rather than that it asked for a name this listener does not serve.
//
//nolint:misspell,nilnil // RFC 6066 §3's alert name and wording are quoted verbatim, in US spelling; (nil, nil) is the strict refusal described above.
func (s *certStore) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if hello.ServerName != "" {
		name := asciiLower(hello.ServerName)
		if cert, ok := s.byName[name]; ok {
			return cert, nil
		}
		if wildcard, ok := wildcardOf(name); ok {
			if cert, ok := s.byName[wildcard]; ok {
				return cert, nil
			}
		}
	}
	if s.strict {
		return nil, nil
	}
	return s.fallback, nil
}

// asciiLower folds A-Z to a-z and leaves every other byte alone. DNS names
// compare case-insensitively in ASCII only (RFC 4343 §3; RFC 9525 §6.3,
// "case-insensitive ASCII comparison"). The strings.ToLower this replaces
// folds Unicode too, so an SNI of "\u212a.example.com" (KELVIN SIGN) used to become
// "k.example.com" and select that name's certificate, strict mode included.
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

// validPresentedName reports whether a certificate's DNS SAN is one RFC
// 9525 §6.3 lets a client match. A wildcard is valid only as "the complete
// content of the left-most label", and only one of it; otherwise "the
// presented identifier is invalid and MUST be ignored". Keying such a SAN
// would let an SNI that spells it out literally ("f*.example.com") select
// its certificate.
func validPresentedName(name string) bool {
	switch strings.Count(name, "*") {
	case 0:
		return true
	case 1:
		return strings.HasPrefix(name, "*.") && len(name) > len("*.")
	default:
		return false
	}
}

// wildcardOf returns name's RFC 9525 §6.3 single-label wildcard form (its
// leftmost label replaced with "*"), and whether name has enough labels for
// that to be meaningful. A bare single-label name has no wildcard form --
// *.example.com must not match example.com itself, matching how every TLS
// client actually verifies wildcard certs. Multi-label names only get the
// wildcard's own domain's protection: *.sevenwoods.nl matches
// dns.sevenwoods.nl but not a.b.sevenwoods.nl (single wildcard level, not
// suffix matching). An empty leftmost label (".example.com") has no
// wildcard form either: "*" stands for one whole label, and an empty string
// is not one, so strict mode must refuse that SNI rather than serve the
// wildcard cert for it.
func wildcardOf(name string) (string, bool) {
	i := strings.IndexByte(name, '.')
	if i <= 0 {
		return "", false
	}
	return "*" + name[i:], true
}

// loadCert loads a cert/key pair via tls.LoadX509KeyPair and returns it
// alongside its SAN DNS names (ASCII-lowercased, as GetCertificate folds the
// SNI; invalid wildcards dropped); tls.Certificate.Leaf is NOT populated by
// LoadX509KeyPair (see design doc step 1), so the leaf must be parsed
// explicitly via x509.ParseCertificate to read its DNSNames.
func loadCert(certFile, keyFile string) (*tls.Certificate, []string, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("sni_tls: could not load cert/key pair (%s, %s): %w", certFile, keyFile, err)
	}
	if len(cert.Certificate) == 0 {
		return nil, nil, fmt.Errorf("sni_tls: %s contains no certificate", certFile)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, nil, fmt.Errorf("sni_tls: could not parse leaf certificate %s: %w", certFile, err)
	}
	names := make([]string, 0, len(leaf.DNSNames))
	for _, n := range leaf.DNSNames {
		if validPresentedName(n) {
			names = append(names, asciiLower(n))
		}
	}
	if len(names) == 0 {
		return nil, nil, fmt.Errorf("sni_tls: %s has no usable SAN DNS names to key SNI lookup on", certFile)
	}
	return &cert, names, nil
}

// buildCertStore loads each (cert, key) pair in order and returns a certStore
// keyed by every loaded cert's SAN DNS names. The first SUCCESSFULLY LOADED
// pair's cert becomes the fallback for absent/unmatched SNI, matching the
// stock tls plugin's SNI-agnostic single-cert behaviour for those cases (see
// design doc step 2) — unless strict is set, in which case no fallback is
// installed at all and unmatched/absent SNI hard-fails in GetCertificate.
//
// A pair whose cert or key FILE IS ABSENT is skipped, not fatal — this is the
// "partial cert set is fine, whatever loaded loads" tolerance design doc step
// 5 requires (a secondary cert renewal failure must not take down the
// primary listener, and vice versa; the two Secrets/volumes roll
// independently). Any other load failure (corrupt PEM, cert/key mismatch, no
// SAN DNS names) is still fatal: those indicate a present-but-broken cert,
// not an expected rollout gap, and silently skipping a broken cert would mask
// a real misconfiguration. If ALL configured pairs are missing (and at least
// one was configured), that's fatal too — a Corefile listing certs that never
// materialise is worth failing loudly on, unlike a genuinely empty
// configuration (setup() already rejects zero pairs before calling this; an
// empty slice here is a valid input with no fallback, not an error).
func buildCertStore(pairs [][2]string, strict bool) (*certStore, error) {
	store := &certStore{byName: make(map[string]*tls.Certificate), strict: strict}
	var loadErrs []error
	for _, p := range pairs {
		cert, names, err := loadCert(p[0], p[1])
		if err != nil {
			if isMissingFile(err) {
				loadErrs = append(loadErrs, err)
				continue
			}
			return nil, err
		}
		if store.fallback == nil {
			store.fallback = cert
		}
		for _, name := range names {
			store.byName[name] = cert
		}
	}
	if store.fallback == nil && len(pairs) > 0 && len(loadErrs) == len(pairs) {
		return nil, fmt.Errorf("sni_tls: no cert/key pairs could be loaded (all %d missing): %w", len(loadErrs), loadErrs[0])
	}
	return store, nil
}

// isMissingFile reports whether err (as returned by loadCert, which wraps
// with fmt.Errorf("...: %w", err)) is caused by a missing cert or key file
// specifically, as opposed to some other load failure (corrupt PEM,
// mismatched key, parse error, no SAN names).
func isMissingFile(err error) bool {
	return errors.Is(err, os.ErrNotExist)
}

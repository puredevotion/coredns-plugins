package sni_tls

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

// errNoMatchingCert is returned by GetCertificate in strict mode when no exact
// or wildcard SNI match is found. Returning an error here (rather than a cert)
// makes the Go TLS server abort the handshake instead of completing one with
// an unintended cert — a closed failure, not a silent one.
var errNoMatchingCert = errors.New("sni_tls: no certificate configured for this SNI (strict mode, no fallback)")

// GetCertificate implements the tls.Config.GetCertificate callback: look up the
// client's requested SNI, then its RFC 6125 §6.4.3 single-level wildcard form
// (dns.sevenwoods.nl -> *.sevenwoods.nl) so a wildcard cert's SAN actually
// gets selected for concrete hostnames under it -- caught live: a real LE
// wildcard cert (*.sevenwoods.nl) loaded alongside a per-host cert silently
// never matched any real SNI at all (the map key was the literal string
// "*.sevenwoods.nl", which no real ClientHello ever sends), falling through
// to the fallback cert on every connection instead. Falls back to the
// first-loaded cert if neither matches, unless strict is set, in which case
// an unmatched or absent SNI fails the handshake instead of guessing.
func (s *certStore) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if hello.ServerName != "" {
		name := strings.ToLower(hello.ServerName)
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
		return nil, errNoMatchingCert
	}
	return s.fallback, nil
}

// wildcardOf returns name's RFC 6125 §6.4.3 single-level wildcard form (its
// leftmost label replaced with "*"), and whether name has enough labels for
// that to be meaningful. A bare single-label name has no wildcard form --
// *.example.com must not match example.com itself, matching how every TLS
// client actually verifies wildcard certs. Multi-label names only get the
// wildcard's own domain's protection: *.sevenwoods.nl matches
// dns.sevenwoods.nl but not a.b.sevenwoods.nl (single wildcard level, not
// suffix matching).
func wildcardOf(name string) (string, bool) {
	i := strings.IndexByte(name, '.')
	if i < 0 {
		return "", false
	}
	return "*" + name[i:], true
}

// loadCert loads a cert/key pair via tls.LoadX509KeyPair and returns it
// alongside its SAN DNS names (lowercased, matching TLS SNI's case-insensitive
// comparison per RFC 6066 §3). tls.Certificate.Leaf is NOT populated by
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
	if len(leaf.DNSNames) == 0 {
		return nil, nil, fmt.Errorf("sni_tls: %s has no SAN DNS names to key SNI lookup on", certFile)
	}
	names := make([]string, len(leaf.DNSNames))
	for i, n := range leaf.DNSNames {
		names[i] = strings.ToLower(n)
	}
	return &cert, names, nil
}

// buildCertStore loads each (cert, key) pair in order and returns a certStore
// keyed by every loaded cert's SAN DNS names. The first SUCCESSFULLY LOADED
// pair's cert becomes the fallback for absent/unmatched SNI, matching the
// stock tls plugin's SNI-agnostic single-cert behavior for those cases (see
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
// materialize is worth failing loudly on, unlike a genuinely empty
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

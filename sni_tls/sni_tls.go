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
// ../docs/sni-tls-plugin.md for the verified-DDR caveat on this fallback: it must
// never be used on the coredns-lan-ddr (.244) instance with more than one cert
// loaded, since an unmatched-SNI client could get served a cert without the
// required IP-SAN, silently defeating RFC 9462 §4.2 verified discovery.
type certStore struct {
	byName   map[string]*tls.Certificate
	fallback *tls.Certificate
}

// GetCertificate implements the tls.Config.GetCertificate callback: look up the
// client's requested SNI, fall back to the first-loaded cert if unmatched.
func (s *certStore) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if hello.ServerName != "" {
		if cert, ok := s.byName[strings.ToLower(hello.ServerName)]; ok {
			return cert, nil
		}
	}
	return s.fallback, nil
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
// design doc step 2).
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
func buildCertStore(pairs [][2]string) (*certStore, error) {
	store := &certStore{byName: make(map[string]*tls.Certificate)}
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

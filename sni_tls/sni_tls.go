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
// see the `strict` Corefile option in setup.go. A ClientHello with no SNI is
// handled by noSNI, the `no_sni` option.
type certStore struct {
	byName map[string]*tls.Certificate
	// BySuffix holds the wildcard certs again, keyed by the part of the SAN
	// after the "*": "*.example.net" sits under ".example.net". GetCertificate
	// can then look a name's wildcard form up by slicing the name, where
	// building the "*.example.net" key allocated on every wildcard match. Nil
	// in a store built by hand (tests), which falls back to byName.
	bySuffix  map[string]*tls.Certificate
	fallback  *tls.Certificate
	noSNICert *tls.Certificate // The cert noSNICertificate serves; nil until it loads.
	noSNI     noSNIPolicy
	strict    bool
}

// noSNIPolicy is what a ClientHello without SNI gets: the `no_sni` option.
// RFC 9462 §6.3: "resolvers that support discovery using IP addresses will
// need to be configured to present the appropriate TLS certificate when no
// SNI is present for DoT, DoQ, and DoH." Strict mode alone refuses those
// clients, so a strict instance that clients discover by IP sets one of the
// other policies.
type noSNIPolicy int

const (
	// The default treats an absent SNI like an unmatched one: refused in
	// strict mode, the fallback cert otherwise.
	noSNIAsUnmatched noSNIPolicy = iota
	// The `no_sni refuse` policy always refuses the handshake.
	noSNIRefuse
	// The `no_sni fallback` policy always serves the fallback (first
	// loaded) cert, strict mode included.
	noSNIFallback
	// The `no_sni cert <cert> <key>` policy serves a cert configured for
	// no-SNI clients alone, strict mode included.
	noSNICertificate
)

// storeConfig is everything buildCertStore needs: the parsed Corefile
// options, kept by liveStore so every reload rebuilds the same way.
type storeConfig struct {
	noSNIPair [2]string // The no_sni cert and key, for noSNICertificate.
	pairs     [][2]string
	noSNI     noSNIPolicy
	strict    bool
}

// files lists every cert/key pair the store reads, the no_sni one included,
// so a rotation of any of them triggers a reload.
func (c storeConfig) files() [][2]string {
	if c.noSNI != noSNICertificate {
		return c.pairs
	}
	return append(append(make([][2]string, 0, len(c.pairs)+1), c.pairs...), c.noSNIPair)
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
// an unmatched SNI fails the handshake instead of guessing. An absent SNI
// gets whatever the no_sni policy says, by default the same as an unmatched
// one.
//
// The strict refusal is (nil, nil), not an error. Since setup() leaves
// tls.Config.Certificates empty, crypto/tls then aborts with a fatal
// unrecognized_name(112) alert, which RFC 6066 §3 says a server that "does
// not recognize the server name" SHOULD send. Any error would go out as
// internal_error(80) instead, telling the client the server is broken
// rather than that it asked for a name this listener does not serve. A
// client that sent no SNI at all is refused by refuseNoSNI, which over QUIC
// can do better.
//
//nolint:misspell,nilnil // RFC 6066 §3's alert name and wording are quoted verbatim, in US spelling; (nil, nil) is the strict refusal described above.
func (s *certStore) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if hello.ServerName == "" {
		switch s.noSNI {
		case noSNIRefuse:
			return refuseNoSNI(hello)
		case noSNIFallback:
			return s.fallback, nil
		case noSNICertificate:
			if s.noSNICert == nil { // Its files are missing.
				return refuseNoSNI(hello)
			}
			return s.noSNICert, nil
		case noSNIAsUnmatched:
			if s.strict {
				return refuseNoSNI(hello)
			}
		}
	} else {
		name := asciiLower(hello.ServerName)
		if cert, ok := s.byName[name]; ok {
			return cert, nil
		}
		if cert, ok := s.wildcardFor(name); ok {
			return cert, nil
		}
	}
	if s.strict {
		return nil, nil
	}
	return s.fallback, nil
}

// wildcardFor looks up the certificate for name's RFC 9525 §6.3 wildcard form
// (see wildcardOf). The suffix index answers it without building the wildcard
// string; a store without one is searched by name.
func (s *certStore) wildcardFor(name string) (*tls.Certificate, bool) {
	if s.bySuffix != nil {
		i := strings.IndexByte(name, '.')
		if i <= 0 {
			return nil, false
		}
		cert, ok := s.bySuffix[name[i:]]
		return cert, ok
	}
	wildcard, ok := wildcardOf(name)
	if !ok {
		return nil, false
	}
	cert, ok := s.byName[wildcard]
	return cert, ok
}

// alertMissingExtension is TLS alert 109, missing_extension (RFC 8446 §6). Over
// QUIC it travels as CRYPTO_ERROR 0x0100+109 (RFC 9001 §4.8).
const alertMissingExtension = tls.AlertError(109)

// refuseNoSNI refuses a ClientHello that carried no server_name extension.
// RFC 8446 §9.2: "Servers requiring this extension SHOULD respond to a
// ClientHello lacking a "server_name" extension by terminating the
// connection with a "missing_extension" alert".
//
// That is only possible over QUIC (DoQ, DoH3). There crypto/tls hands the
// error GetCertificate returns to the QUIC stack, and quic-go sends the
// first tls.AlertError it finds in it as the CRYPTO_ERROR. Over TCP (DoT,
// DoH) every GetCertificate error goes out as internal_error(80), so the
// refusal stays (nil, nil) and the client gets unrecognized_name(112), the
// only other alert a GetCertificate refusal can produce there.
//
//nolint:misspell,nilnil // The TLS alert name is quoted verbatim, in US spelling; (nil, nil) is the TCP refusal described above.
func refuseNoSNI(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if overQUIC(hello) {
		return nil, fmt.Errorf("sni_tls: refusing a QUIC handshake without SNI: %w", alertMissingExtension)
	}
	return nil, nil
}

// overQUIC reports whether hello arrived over QUIC. The quic-go stack sets
// ClientHelloInfo.Conn to a stand-in whose LocalAddr is the UDP socket's (via
// tls.QUICConfig.ClientHelloInfoConn on Go 1.27); over TCP it is the real
// TCP connection. With no Conn there is no evidence, and the TCP-safe answer
// is kept.
func overQUIC(hello *tls.ClientHelloInfo) bool {
	if hello.Conn == nil {
		return false
	}
	addr := hello.Conn.LocalAddr()
	return addr != nil && addr.Network() == "udp"
}

// asciiLower folds A-Z to a-z and leaves every other byte alone. DNS names
// compare case-insensitively in ASCII only (RFC 4343 §3; RFC 9525 §6.3,
// "case-insensitive ASCII comparison"). The strings.ToLower this replaces
// folds Unicode too, so an SNI of "\u212a.example.com" (KELVIN SIGN) used to become
// "k.example.com" and select that name's certificate, strict mode included.
//
// Nothing is copied unless there is something to fold: the common ClientHello
// already carries a lowercase name, and this runs on every handshake.
func asciiLower(s string) string {
	i := 0
	for i < len(s) && (s[i] < 'A' || s[i] > 'Z') {
		i++
	}
	if i == len(s) {
		return s
	}
	b := []byte(s)
	for ; i < len(b); i++ {
		if c := b[i]; 'A' <= c && c <= 'Z' {
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
	cert.Leaf = leaf
	return &cert, names, nil
}

// buildCertStore loads each (cert, key) pair in order and returns a certStore
// keyed by every loaded cert's SAN DNS names. The first SUCCESSFULLY LOADED
// pair's cert becomes the fallback for absent/unmatched SNI, matching the
// stock tls plugin's SNI-agnostic single-cert behaviour for those cases (see
// design doc step 2). In strict mode GetCertificate never serves it for an
// unmatched SNI, and serves it for an absent one only under `no_sni
// fallback`.
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
func buildCertStore(cfg storeConfig) (*certStore, error) {
	pairs := cfg.pairs
	store := &certStore{
		byName:   make(map[string]*tls.Certificate),
		bySuffix: make(map[string]*tls.Certificate),
		strict:   cfg.strict,
		noSNI:    cfg.noSNI,
	}
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
			if suffix, ok := strings.CutPrefix(name, "*"); ok {
				store.bySuffix[suffix] = cert
			}
		}
	}
	if store.fallback == nil && len(pairs) > 0 && len(loadErrs) == len(pairs) {
		return nil, fmt.Errorf("sni_tls: no cert/key pairs could be loaded (all %d missing): %w", len(loadErrs), loadErrs[0])
	}
	if err := store.loadNoSNI(cfg); err != nil {
		return nil, err
	}
	return store, nil
}

// loadNoSNI loads the no_sni cert, and warns when the cert no-SNI clients
// will get carries no IP-address SAN: such a client connected by IP, and
// RFC 9462 §4.2 has it "verify that the certificate contains the IP address
// of the designating Unencrypted DNS Resolver in an iPAddress entry of the
// subjectAltName extension". A missing no_sni file is tolerated like any
// other (design doc step 5): no-SNI clients are refused until it appears.
func (s *certStore) loadNoSNI(cfg storeConfig) error {
	var served *tls.Certificate
	switch cfg.noSNI {
	case noSNICertificate:
		cert, err := loadAnyCert(cfg.noSNIPair[0], cfg.noSNIPair[1])
		if err != nil {
			if !isMissingFile(err) {
				return err
			}
			log.Warningf("no_sni cert not loaded, refusing clients without SNI until it is: %v", err)
			return nil
		}
		s.noSNICert, served = cert, cert
	case noSNIFallback:
		served = s.fallback
	case noSNIAsUnmatched, noSNIRefuse:
		return nil
	}
	if served != nil && served.Leaf != nil && len(served.Leaf.IPAddresses) == 0 {
		log.Warningf("the cert served without SNI has no IP-address SAN, so clients that discovered this resolver by IP (RFC 9462 §4.2) cannot verify it")
	}
	return nil
}

// loadAnyCert loads a cert/key pair without requiring DNS SANs. The no_sni
// cert is not looked up by name, and the cert RFC 9462 §4.2 asks for there
// may well carry only IP addresses. Leaf is set so loadNoSNI can read them.
func loadAnyCert(certFile, keyFile string) (*tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("sni_tls: could not load no_sni cert/key pair (%s, %s): %w", certFile, keyFile, err)
	}
	if len(cert.Certificate) == 0 {
		return nil, fmt.Errorf("sni_tls: %s contains no certificate", certFile)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("sni_tls: could not parse leaf certificate %s: %w", certFile, err)
	}
	cert.Leaf = leaf
	return &cert, nil
}

// isMissingFile reports whether err (as returned by loadCert, which wraps
// with fmt.Errorf("...: %w", err)) is caused by a missing cert or key file
// specifically, as opposed to some other load failure (corrupt PEM,
// mismatched key, parse error, no SAN names).
func isMissingFile(err error) bool {
	return errors.Is(err, os.ErrNotExist)
}

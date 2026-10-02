package snitls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	ctls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Shared SNI hostnames reused across this package's tests, extracted to
// named constants (goconst) rather than repeating the same string literals
// at every call site.
const (
	testSNIPrimary   = "dns.example.com"
	testSNISecondary = "dns.internal.example"
	testSNIUnknown   = "unknown.example.org"
)

// generateSeedCertPEM builds a self-signed ECDSA cert/key pair with the given
// SAN DNS names and returns their PEM-encoded bytes (not written to disk).
// Factored out of writeTestCert so fuzz_test.go's seed corpus (which needs
// PEM bytes, not files, and runs against *testing.F not *testing.T) can reuse
// the same well-formed generation logic instead of duplicating it.
func generateSeedCertPEM(sans ...string) (certPEM, keyPEM []byte) {
	return generateCertPEM(sans, nil)
}

// generateCertPEM is generateSeedCertPEM with IP-address SANs as well.
func generateCertPEM(sans []string, ips []net.IP) (certPEM, keyPEM []byte) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic("generateSeedCertPEM: GenerateKey: " + err.Error())
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "seed"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     sans,
		IPAddresses:  ips,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		panic("generateSeedCertPEM: CreateCertificate: " + err.Error())
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		panic("generateSeedCertPEM: MarshalECPrivateKey: " + err.Error())
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

// writeTestCert generates a self-signed ECDSA cert/key pair with the given SAN
// DNS names, writes them as PEM files under t.TempDir(), and returns their
// paths. Used to exercise the real tls.LoadX509KeyPair + x509.ParseCertificate
// path end-to-end, rather than empty dummy *tls.Certificate{} structs.
func writeTestCert(t *testing.T, cn string, sans ...string) (certPath, keyPath string) {
	t.Helper()

	return writeCertFiles(t, cn, sans, nil)
}

// writeIPCert is writeTestCert for a cert whose only SANs are IP addresses,
// the kind RFC 9462 §4.2 verified discovery wants served without SNI.
func writeIPCert(t *testing.T, cn string, ips ...net.IP) (certPath, keyPath string) {
	t.Helper()
	return writeCertFiles(t, cn, nil, ips)
}

func writeCertFiles(t *testing.T, cn string, sans []string, ips []net.IP) (certPath, keyPath string) {
	t.Helper()

	certPEM, keyPEM := generateCertPEM(sans, ips)

	dir := t.TempDir()
	certPath = filepath.Join(dir, cn+"-cert.pem")
	keyPath = filepath.Join(dir, cn+"-key.pem")

	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("write cert file: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}

	return certPath, keyPath
}

// writeNoSANCert generates a self-signed cert with no SAN DNS names at all
// (CN only) — RFC 9525 Appendix A: "it is no longer valid to use the
// commonName RDN" as an identifier, so validators (and this plugin) key
// strictly off SANs and such a cert must be rejected by loadCert.
func writeNoSANCert(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	return writeTestCert(t, "no-san-cn") // DNSNames left empty.
}

// acceptAndHandshakeOnce accepts a single connection on ln and completes the
// server-side TLS handshake, discarding the outcome. Shared by the real-TLS
// end-to-end tests' background accept goroutines, where the accept/handshake
// error genuinely doesn't affect the test's assertions (the client side is
// what's being checked) and logging from a background goroutine after the
// test may have already completed would be unsafe.
func acceptAndHandshakeOnce(ln net.Listener) {
	conn, acceptErr := ln.Accept()
	if acceptErr != nil {
		return
	}
	defer func() {
		_ = conn.Close() //nolint:errcheck // best-effort close of a test-only connection in a background goroutine; logging after the test may complete is unsafe
	}()
	tlsConn, ok := conn.(*ctls.Conn)
	if !ok {
		return
	}
	_ = tlsConn.HandshakeContext(context.Background()) //nolint:errcheck // handshake error from a background goroutine is expected on early conn close; can't safely log after the test completes
}

// acceptAndHandshakeReporting accepts a single connection on ln, completes
// the server-side TLS handshake, and reports the outcome — including an
// accept failure or a non-*tls.Conn accepted conn, which should never happen
// against a *tls.Config-armed listener — on acceptErr. Shared by the
// strict-mode end-to-end tests' background accept goroutines, which (unlike
// acceptAndHandshakeOnce) need the real handshake error to assert on.
func acceptAndHandshakeReporting(ln net.Listener, acceptErr chan<- error) {
	conn, connErr := ln.Accept()
	if connErr != nil {
		acceptErr <- connErr
		return
	}
	defer func() {
		_ = conn.Close() //nolint:errcheck // best-effort close of a test-only connection in a background goroutine; logging after the test may complete is unsafe
	}()
	tlsConn, ok := conn.(*ctls.Conn)
	if !ok {
		acceptErr <- fmt.Errorf("accepted conn is not *tls.Conn: %T", conn)
		return
	}
	acceptErr <- tlsConn.HandshakeContext(context.Background())
}

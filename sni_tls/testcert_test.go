package sni_tls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// generateSeedCertPEM builds a self-signed ECDSA cert/key pair with the given
// SAN DNS names and returns their PEM-encoded bytes (not written to disk).
// Factored out of writeTestCert so fuzz_test.go's seed corpus (which needs
// PEM bytes, not files, and runs against *testing.F not *testing.T) can reuse
// the same well-formed generation logic instead of duplicating it.
func generateSeedCertPEM(sans ...string) (certPEM, keyPEM []byte) {
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

	certPEM, keyPEM := generateSeedCertPEM(sans...)

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
// (CN only) — covers the RFC 6125 §6.4.4 rule that CN-only matching is
// deprecated and modern validators (and this plugin) must key strictly off
// SANs, so such a cert should be rejected by loadCert.
func writeNoSANCert(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	return writeTestCert(t, "no-san-cn") // DNSNames left empty
}

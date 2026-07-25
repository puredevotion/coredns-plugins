package sni_tls

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"testing"
)

// FuzzLoadCert feeds arbitrary bytes as cert/key file contents into loadCert
// — the plugin's actual parser attack surface (tls.LoadX509KeyPair +
// x509.ParseCertificate on attacker-influenced input, since these files come
// from a mounted secret/volume; a malformed/rotated cert file must degrade to an
// error, never a panic). Seeds start from a real valid cert/key pair so the
// mutator has a well-formed structure to corrupt, not just noise.
func FuzzLoadCert(f *testing.F) {
	dir := f.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	// Seed corpus: a real valid pair (from writeTestCert's logic, inlined
	// here since testing.F seeds must be added before any subtest forking,
	// and f.TempDir()-based *_test.go helpers taking *testing.T don't apply
	// to *testing.F directly).
	seedCert, seedKey := generateSeedCertPEM("dns.example.com")
	f.Add(seedCert, seedKey)
	f.Add([]byte(""), []byte(""))
	f.Add([]byte("not a cert"), []byte("not a key"))
	f.Add(seedCert, []byte("")) // valid cert, empty key
	f.Add([]byte(""), seedKey)  // empty cert, valid key
	f.Add(seedCert, seedCert)   // cert reused as "key"

	f.Fuzz(func(t *testing.T, certBytes, keyBytes []byte) {
		if err := os.WriteFile(certPath, certBytes, 0o600); err != nil {
			t.Fatalf("write cert fixture: %v", err)
		}
		if err := os.WriteFile(keyPath, keyBytes, 0o600); err != nil {
			t.Fatalf("write key fixture: %v", err)
		}

		// The only property under test: loadCert must never panic on
		// attacker-controlled file contents, and must return a non-nil error
		// whenever it returns a nil cert or empty names (no silent
		// inconsistent partial result).
		cert, names, err := loadCert(certPath, keyPath)
		if err != nil {
			if cert != nil || names != nil {
				t.Fatalf("loadCert returned an error AND non-nil results: cert=%v names=%v err=%v", cert, names, err)
			}
			return
		}
		if cert == nil {
			t.Fatal("loadCert returned nil error and nil cert")
		}
		if len(names) == 0 {
			t.Fatal("loadCert returned nil error but no SAN names (should have errored per the no-SAN check)")
		}
		for _, n := range names {
			if n == "" {
				t.Fatal("loadCert returned an empty SAN name")
			}
		}
	})
}

// FuzzGetCertificate fuzzes the SNI ServerName string against a fixed
// two-cert store — the runtime-facing attack surface, since ServerName comes
// directly from a TLS ClientHello sent by an untrusted network peer, before
// any authentication. Property: GetCertificate never panics and always
// returns either a known cert or the fallback, never nil+nil.
func FuzzGetCertificate(f *testing.F) {
	primary := &tls.Certificate{Certificate: [][]byte{{1}}}
	secondary := &tls.Certificate{Certificate: [][]byte{{2}}}
	store := &certStore{
		byName: map[string]*tls.Certificate{
			"dns.example.com":      primary,
			"dns.internal.example": secondary,
		},
		fallback: primary,
	}

	for _, s := range []string{
		"", "dns.example.com", "DNS.EXAMPLE.COM", "dns.internal.example",
		"unknown.example.org", "dns.example.com\x00evil", strRepeat("a", 300),
		"..", "*.example.com", "dns.example.com.", "\xff\xfe\xfd",
	} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, serverName string) {
		got, err := store.GetCertificate(&tls.ClientHelloInfo{ServerName: serverName})
		if err != nil {
			t.Fatalf("GetCertificate must never error, got: %v", err)
		}
		if got == nil {
			t.Fatalf("GetCertificate(%q) returned nil cert with nil error", serverName)
		}
		if got != primary && got != secondary {
			t.Fatalf("GetCertificate(%q) returned a cert not in the store", serverName)
		}
	})
}

func strRepeat(s string, n int) string {
	out := make([]byte, 0, len(s)*n)
	for i := 0; i < n; i++ {
		out = append(out, s...)
	}
	return string(out)
}

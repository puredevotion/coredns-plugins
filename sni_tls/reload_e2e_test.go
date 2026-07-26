package sni_tls

import (
	"crypto/tls"
	"crypto/x509"
	"testing"
)

// TestReload_EndToEnd_RealTLSHandshake proves the whole path — certStore,
// atomic swap, crypto/tls's own GetCertificate invocation — via a real
// tls.Dial/SNI handshake before and after rotating the cert file, not just
// the plugin's internal call sequence like TestLiveStore_ReloadOnce_SwapsOnRotation.
func TestReload_EndToEnd_RealTLSHandshake(t *testing.T) {
	const sni = "dns.example.com"

	certPath, keyPath := writeTestCert(t, "primary", sni)
	store, err := buildCertStore([][2]string{{certPath, keyPath}})
	if err != nil {
		t.Fatalf("buildCertStore: %v", err)
	}
	pairs := [][2]string{{certPath, keyPath}}
	live := newLiveStore(pairs, store, digestPairs(pairs))

	serverConf := &tls.Config{GetCertificate: live.GetCertificate}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverConf)
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	defer ln.Close()

	acceptOnce := func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.(*tls.Conn).Handshake()
	}

	dial := func() *x509.Certificate {
		t.Helper()
		go acceptOnce()

		conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: true, // self-signed test certs; only the served leaf identity is asserted
		})
		if err != nil {
			t.Fatalf("tls.Dial: %v", err)
		}
		defer conn.Close()

		state := conn.ConnectionState()
		if len(state.PeerCertificates) == 0 {
			t.Fatal("handshake produced no peer certificates")
		}
		return state.PeerCertificates[0]
	}

	before := dial()

	rotatedCertPath, rotatedKeyPath := writeTestCert(t, "rotated", sni)
	overwrite(t, certPath, rotatedCertPath)
	overwrite(t, keyPath, rotatedKeyPath)

	live.reloadOnce()

	after := dial()

	if before.SerialNumber.Cmp(after.SerialNumber) == 0 && before.Raw != nil && string(before.Raw) == string(after.Raw) {
		t.Fatal("real TLS handshake served the same cert before and after rotation — reload did not take effect")
	}
	if !contains(after.DNSNames, sni) {
		t.Fatalf("post-rotation cert missing expected SAN %q: %v", sni, after.DNSNames)
	}
}

func contains(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}

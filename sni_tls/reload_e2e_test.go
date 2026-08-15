package snitls

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"slices"
	"testing"
)

// TestReload_EndToEnd_RealTLSHandshake proves the whole path — certStore,
// atomic swap, crypto/tls's own GetCertificate invocation — via a real
// tls.Dial/SNI handshake before and after rotating the cert file, not just
// the plugin's internal call sequence like TestLiveStore_ReloadOnce_SwapsOnRotation.
func TestReload_EndToEnd_RealTLSHandshake(t *testing.T) {
	sni := testSNIPrimary

	certPath, keyPath := writeTestCert(t, "primary", sni)
	store, err := buildCertStore([][2]string{{certPath, keyPath}}, false)
	if err != nil {
		t.Fatalf("buildCertStore: %v", err)
	}
	pairs := [][2]string{{certPath, keyPath}}
	live := newLiveStore(pairs, false, store, digestPairs(pairs))

	serverConf := &tls.Config{GetCertificate: live.GetCertificate}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverConf)
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	defer func() {
		if closeErr := ln.Close(); closeErr != nil {
			t.Logf("close listener: %v", closeErr)
		}
	}()

	before := dialAndGetLeaf(t, ln, sni)

	rotatedCertPath, rotatedKeyPath := writeTestCert(t, "rotated", sni)
	overwrite(t, certPath, rotatedCertPath)
	overwrite(t, keyPath, rotatedKeyPath)

	live.reloadOnce()

	after := dialAndGetLeaf(t, ln, sni)

	if before.SerialNumber.Cmp(after.SerialNumber) == 0 && before.Raw != nil && bytes.Equal(before.Raw, after.Raw) {
		t.Fatal("real TLS handshake served the same cert before and after rotation — reload did not take effect")
	}
	if !slices.Contains(after.DNSNames, sni) {
		t.Fatalf("post-rotation cert missing expected SAN %q: %v", sni, after.DNSNames)
	}
}

// dialAndGetLeaf dials ln with the given SNI over a real TLS handshake and
// returns the server's leaf certificate. Extracted from
// TestReload_EndToEnd_RealTLSHandshake to keep it within the funlen
// statement budget.
func dialAndGetLeaf(t *testing.T, ln net.Listener, sni string) *x509.Certificate {
	t.Helper()
	go acceptAndHandshakeOnce(ln)

	dialer := &tls.Dialer{Config: &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true, //nolint:gosec // self-signed test certs; only the served leaf identity is asserted
	}}
	rawConn, dialErr := dialer.DialContext(context.Background(), "tcp", ln.Addr().String())
	if dialErr != nil {
		t.Fatalf("tls.Dial: %v", dialErr)
	}
	conn, ok := rawConn.(*tls.Conn)
	if !ok {
		t.Fatalf("dialled conn is not *tls.Conn: %T", rawConn)
	}
	defer func() {
		if closeErr := conn.Close(); closeErr != nil {
			t.Logf("close client conn: %v", closeErr)
		}
	}()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		t.Fatal("handshake produced no peer certificates")
	}
	return state.PeerCertificates[0]
}

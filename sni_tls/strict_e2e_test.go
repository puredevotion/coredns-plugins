package snitls

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"slices"
	"testing"
)

// TestStrict_EndToEnd_RealTLSHandshake proves strict mode's rejection at the
// actual wire level, not just via direct GetCertificate calls: two real
// certs loaded (mirroring dns.sevenwoods.nl's IP-SAN cert and dns.example.com's
// hostname-only cert on the same listener), then real tls.Dial handshakes
// with matching, mismatched, and absent SNI. This is the scenario the
// verified-DDR caveat in docs/sni-tls-plugin.md is about: an unmatched or
// absent SNI must fail the handshake outright, never silently complete with
// the wrong cert.
func TestStrict_EndToEnd_RealTLSHandshake(t *testing.T) {
	const sniA = "dns.sevenwoods.nl"
	sniB := testSNIPrimary

	certA, keyA := writeTestCert(t, "sevenwoods", sniA)
	certB, keyB := writeTestCert(t, "homearpa", sniB)

	store, err := buildCertStore(storeConfig{pairs: [][2]string{{certA, keyA}, {certB, keyB}}, strict: true})
	if err != nil {
		t.Fatalf("buildCertStore: %v", err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{GetCertificate: store.GetCertificate})
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	defer func() {
		if closeErr := ln.Close(); closeErr != nil {
			t.Logf("close listener: %v", closeErr)
		}
	}()

	if err := dialSNIStrict(t, ln, sniA); err != nil {
		t.Errorf("SNI=%q: expected successful handshake (exact match), got error: %v", sniA, err)
	}
	if err := dialSNIStrict(t, ln, sniB); err != nil {
		t.Errorf("SNI=%q: expected successful handshake (exact match), got error: %v", sniB, err)
	}
	if err := dialSNIStrict(t, ln, "unmatched.example.org"); err == nil {
		t.Error("SNI=unmatched: expected handshake to fail in strict mode, it succeeded")
	}
	if err := dialNoSNIStrict(t, ln); err == nil {
		t.Error("SNI=<absent>: expected handshake to fail in strict mode, it succeeded")
	}
}

// dialSNIStrict dials ln with the given SNI over a real TLS handshake and
// reports the client-side handshake error, if any. Extracted from
// TestStrict_EndToEnd_RealTLSHandshake to keep it within the gocognit
// complexity budget.
func dialSNIStrict(t *testing.T, ln net.Listener, sni string) error {
	t.Helper()
	acceptErr := make(chan error, 1)
	go acceptAndHandshakeReporting(ln, acceptErr)

	dialer := &tls.Dialer{Config: &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true, //nolint:gosec // self-signed test certs; only the served identity/success is asserted
	}}
	rawConn, dialErr := dialer.DialContext(context.Background(), "tcp", ln.Addr().String())
	if dialErr == nil {
		if closeErr := rawConn.Close(); closeErr != nil {
			t.Logf("close client conn: %v", closeErr)
		}
	}
	<-acceptErr // Ensure server-side handshake goroutine finished before the next dial.
	if dialErr != nil {
		return fmt.Errorf("dial sni %q: %w", sni, dialErr)
	}
	return nil
}

// dialNoSNIStrict bypasses tls.Dial's own convenience behaviour (it fills
// config.ServerName from the dial address's host when empty, so a ""
// ServerName never actually reaches the wire via tls.Dial) by using
// net.Dial + tls.Client directly, which sends genuinely no SNI extension
// when ServerName is empty. Extracted from TestStrict_EndToEnd_RealTLSHandshake
// to keep it within the gocognit complexity budget.
func dialNoSNIStrict(t *testing.T, ln net.Listener) error {
	t.Helper()
	acceptErr := make(chan error, 1)
	go acceptAndHandshakeReporting(ln, acceptErr)

	raw, dialErr := (&net.Dialer{}).DialContext(context.Background(), "tcp", ln.Addr().String())
	if dialErr != nil {
		t.Fatalf("net.Dial: %v", dialErr)
	}
	client := tls.Client(raw, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // self-signed test certs; only handshake success/failure is asserted
	hsErr := client.HandshakeContext(context.Background())
	if closeErr := client.Close(); closeErr != nil {
		t.Logf("close client: %v", closeErr)
	}
	<-acceptErr
	if hsErr != nil {
		return fmt.Errorf("handshake with no sni: %w", hsErr)
	}
	return nil
}

// TestStrict_EndToEnd_WildcardSNI proves the wildcard-matching path (real
// LE-style *.sevenwoods.nl cert) also works through a real TLS handshake in
// strict mode, not just via direct GetCertificate calls (TestGetCertificate_
// Wildcard exercises that already, but only against the internal struct, and
// never combined with strict). A concrete subdomain must still resolve via
// the wildcard SAN; the bare domain itself must NOT match its own wildcard
// (RFC 9525 §6.3) and, in strict mode, must hard-fail rather than fall
// back.
func TestStrict_EndToEnd_WildcardSNI(t *testing.T) {
	const wildcardSAN = "*.sevenwoods.nl"
	const bareDomain = "sevenwoods.nl"
	const concreteHost = "dns.sevenwoods.nl"
	otherSNI := testSNIPrimary

	wildcardCert, wildcardKey := writeTestCert(t, "wildcard", wildcardSAN)
	otherCert, otherKey := writeTestCert(t, "homearpa", otherSNI)

	store, err := buildCertStore(storeConfig{pairs: [][2]string{{wildcardCert, wildcardKey}, {otherCert, otherKey}}, strict: true})
	if err != nil {
		t.Fatalf("buildCertStore: %v", err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{GetCertificate: store.GetCertificate})
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	defer func() {
		if closeErr := ln.Close(); closeErr != nil {
			t.Logf("close listener: %v", closeErr)
		}
	}()

	dial := func(sni string) (*tls.Conn, error) {
		t.Helper()
		acceptErr := make(chan error, 1)
		go acceptAndHandshakeReporting(ln, acceptErr)

		dialer := &tls.Dialer{Config: &tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: true, //nolint:gosec // self-signed test certs; only the served identity/success is asserted
		}}
		rawConn, dialErr := dialer.DialContext(context.Background(), "tcp", ln.Addr().String())
		<-acceptErr
		if dialErr != nil {
			return nil, fmt.Errorf("dial sni %q: %w", sni, dialErr)
		}
		conn, ok := rawConn.(*tls.Conn)
		if !ok {
			return nil, fmt.Errorf("dialled conn is not *tls.Conn: %T", rawConn)
		}
		return conn, nil
	}

	conn, err := dial(concreteHost)
	if err != nil {
		t.Fatalf("SNI=%q: expected wildcard cert to match via a real handshake, got error: %v", concreteHost, err)
	}
	got := conn.ConnectionState().PeerCertificates[0]
	if !slices.Contains(got.DNSNames, wildcardSAN) {
		t.Errorf("SNI=%q: served cert SANs = %v, expected the wildcard cert (%s)", concreteHost, got.DNSNames, wildcardSAN)
	}
	if closeErr := conn.Close(); closeErr != nil {
		t.Logf("close client conn: %v", closeErr)
	}

	if _, err := dial(bareDomain); err == nil {
		t.Errorf("SNI=%q: bare domain must NOT match its own wildcard cert, and strict mode must reject it -- handshake unexpectedly succeeded", bareDomain)
	}
}

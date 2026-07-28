package sni_tls

import (
	"crypto/tls"
	"net"
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
	const sniB = "dns.example.com"

	certA, keyA := writeTestCert(t, "sevenwoods", sniA)
	certB, keyB := writeTestCert(t, "homearpa", sniB)

	store, err := buildCertStore([][2]string{{certA, keyA}, {certB, keyB}}, true)
	if err != nil {
		t.Fatalf("buildCertStore: %v", err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{GetCertificate: store.GetCertificate})
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	defer ln.Close()

	dial := func(sni string) error {
		t.Helper()
		acceptErr := make(chan error, 1)
		go func() {
			conn, err := ln.Accept()
			if err != nil {
				acceptErr <- err
				return
			}
			defer conn.Close()
			acceptErr <- conn.(*tls.Conn).Handshake()
		}()

		conn, dialErr := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: true, // self-signed test certs; only the served identity/success is asserted
		})
		if dialErr == nil {
			conn.Close()
		}
		<-acceptErr // ensure server-side handshake goroutine finished before the next dial
		return dialErr
	}

	// dialNoSNI bypasses tls.Dial's own convenience behavior (it fills
	// config.ServerName from the dial address's host when empty, so a
	// "" ServerName never actually reaches the wire via tls.Dial) by using
	// net.Dial + tls.Client directly, which sends genuinely no SNI
	// extension when ServerName is empty.
	dialNoSNI := func() error {
		t.Helper()
		acceptErr := make(chan error, 1)
		go func() {
			conn, err := ln.Accept()
			if err != nil {
				acceptErr <- err
				return
			}
			defer conn.Close()
			acceptErr <- conn.(*tls.Conn).Handshake()
		}()

		raw, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatalf("net.Dial: %v", err)
		}
		client := tls.Client(raw, &tls.Config{InsecureSkipVerify: true})
		dialErr := client.Handshake()
		client.Close()
		<-acceptErr
		return dialErr
	}

	if err := dial(sniA); err != nil {
		t.Errorf("SNI=%q: expected successful handshake (exact match), got error: %v", sniA, err)
	}
	if err := dial(sniB); err != nil {
		t.Errorf("SNI=%q: expected successful handshake (exact match), got error: %v", sniB, err)
	}
	if err := dial("unmatched.example.org"); err == nil {
		t.Error("SNI=unmatched: expected handshake to fail in strict mode, it succeeded")
	}
	if err := dialNoSNI(); err == nil {
		t.Error("SNI=<absent>: expected handshake to fail in strict mode, it succeeded")
	}
}

// TestStrict_EndToEnd_WildcardSNI proves the wildcard-matching path (real
// LE-style *.sevenwoods.nl cert) also works through a real TLS handshake in
// strict mode, not just via direct GetCertificate calls (TestGetCertificate_
// Wildcard exercises that already, but only against the internal struct, and
// never combined with strict). A concrete subdomain must still resolve via
// the wildcard SAN; the bare domain itself must NOT match its own wildcard
// (RFC 6125 §6.4.3) and, in strict mode, must hard-fail rather than fall
// back.
func TestStrict_EndToEnd_WildcardSNI(t *testing.T) {
	const wildcardSAN = "*.sevenwoods.nl"
	const bareDomain = "sevenwoods.nl"
	const concreteHost = "dns.sevenwoods.nl"
	const otherSNI = "dns.example.com"

	wildcardCert, wildcardKey := writeTestCert(t, "wildcard", wildcardSAN)
	otherCert, otherKey := writeTestCert(t, "homearpa", otherSNI)

	store, err := buildCertStore([][2]string{{wildcardCert, wildcardKey}, {otherCert, otherKey}}, true)
	if err != nil {
		t.Fatalf("buildCertStore: %v", err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{GetCertificate: store.GetCertificate})
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	defer ln.Close()

	dial := func(sni string) (*tls.Conn, error) {
		t.Helper()
		acceptErr := make(chan error, 1)
		go func() {
			conn, err := ln.Accept()
			if err != nil {
				acceptErr <- err
				return
			}
			defer conn.Close()
			acceptErr <- conn.(*tls.Conn).Handshake()
		}()

		conn, dialErr := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: true, // self-signed test certs; only the served identity/success is asserted
		})
		<-acceptErr
		return conn, dialErr
	}

	conn, err := dial(concreteHost)
	if err != nil {
		t.Fatalf("SNI=%q: expected wildcard cert to match via a real handshake, got error: %v", concreteHost, err)
	}
	got := conn.ConnectionState().PeerCertificates[0]
	if !contains(got.DNSNames, wildcardSAN) {
		t.Errorf("SNI=%q: served cert SANs = %v, expected the wildcard cert (%s)", concreteHost, got.DNSNames, wildcardSAN)
	}
	conn.Close()

	if _, err := dial(bareDomain); err == nil {
		t.Errorf("SNI=%q: bare domain must NOT match its own wildcard cert, and strict mode must reject it -- handshake unexpectedly succeeded", bareDomain)
	}
}

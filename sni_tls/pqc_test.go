package snitls

import (
	"context"
	ctls "crypto/tls"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
)

// mlkemGroups are the hybrid post-quantum key-exchange groups Go's
// crypto/tls includes by default: X25519MLKEM768 since Go 1.24, plus
// SecP256r1MLKEM768/SecP384r1MLKEM1024 since Go 1.26. See crypto/tls's
// CurveID doc comment (checked against this toolchain: go1.26.3).
var mlkemGroups = map[ctls.CurveID]string{
	ctls.X25519MLKEM768:     "X25519MLKEM768",
	ctls.SecP256r1MLKEM768:  "SecP256r1MLKEM768",
	ctls.SecP384r1MLKEM1024: "SecP384r1MLKEM1024",
}

// TestSetup_HandshakeNegotiatesMLKEM drives a real loopback TLS 1.3 handshake
// through the *tls.Config that setup() wires onto dnsserver.Config.TLSConfig
// (certStore.GetCertificate serving the leaf), using default CurvePreferences
// on both ends. It asserts the negotiated ConnectionState.CurveID is one of
// Go's hybrid post-quantum key-exchange groups — proving the plugin's cert
// selection works correctly under a real PQC-negotiated handshake, not merely
// that ML-KEM is enabled somewhere in the process. This is an environment
// fact (Go 1.24+ defaults), not something the plugin's code opts into; the
// test exists to catch a future change that sets an explicit
// CurvePreferences on the wired config and accidentally excludes ML-KEM.
func TestSetup_HandshakeNegotiatesMLKEM(t *testing.T) {
	certPath, keyPath := writeTestCert(t, "primary", testSNIPrimary)

	c := caddy.NewTestController("dns", fmt.Sprintf("sni_tls %s %s", certPath, keyPath))
	if err := setup(c); err != nil {
		t.Fatalf("setup: %v", err)
	}
	serverConfig := dnsserver.GetConfig(c).TLSConfig

	ln, err := ctls.Listen("tcp", "127.0.0.1:0", serverConfig)
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	defer func() {
		if closeErr := ln.Close(); closeErr != nil {
			t.Logf("close listener: %v", closeErr)
		}
	}()

	serverDone := make(chan *ctls.ConnectionState, 1)
	serverErr := make(chan error, 1)
	go acceptAndHandshakeMLKEM(ln, serverDone, serverErr)

	clientConfig := &ctls.Config{
		ServerName: testSNIPrimary,
		RootCAs:    nil, // Set via InsecureSkipVerify below; test cert is self-signed.
		MinVersion: ctls.VersionTLS13,
		// InsecureSkipVerify is fine here: this test's subject is the negotiated
		// key-exchange group, not certificate trust chain validation (that's
		// covered by TestSetup_WiresTLSConfig and the loadCert tests).
		InsecureSkipVerify: true, //nolint:gosec // self-signed test cert; this test's subject is the negotiated key-exchange group, not trust chain validation
	}

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	rawConn, err := dialer.DialContext(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	clientConn := ctls.Client(rawConn, clientConfig)
	defer func() {
		if closeErr := clientConn.Close(); closeErr != nil {
			t.Logf("close client conn: %v", closeErr)
		}
	}()

	if err := clientConn.HandshakeContext(context.Background()); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	clientState := clientConn.ConnectionState()

	assertMLKEMNegotiated(t, serverDone, serverErr, &clientState)

	// The cert served through certStore.GetCertificate must be the one loaded
	// for this SNI — confirms the plugin's own cert-selection logic is what
	// served the leaf in this PQC-negotiated handshake, not a coincidence of
	// there being only one cert loaded.
	if len(clientState.PeerCertificates) == 0 {
		t.Fatal("client saw no peer certificates")
	}
	if got := clientState.PeerCertificates[0].DNSNames; len(got) != 1 || got[0] != testSNIPrimary {
		t.Fatalf("served cert SANs = %v, want [%s]", got, testSNIPrimary)
	}
}

// assertMLKEMNegotiated waits for the server-side handshake outcome and
// asserts both ends negotiated TLS 1.3 with an ML-KEM hybrid group. Extracted
// from TestSetup_HandshakeNegotiatesMLKEM to keep that test within the
// funlen line budget.
func assertMLKEMNegotiated(t *testing.T, serverDone <-chan *ctls.ConnectionState, serverErr <-chan error, clientState *ctls.ConnectionState) {
	t.Helper()
	select {
	case srvState := <-serverDone:
		if srvState.Version != ctls.VersionTLS13 {
			t.Fatalf("server negotiated TLS version %x, want TLS 1.3", srvState.Version)
		}
		if _, ok := mlkemGroups[srvState.CurveID]; !ok {
			t.Fatalf("server CurveID = %v (%s), want one of the ML-KEM hybrid groups %v",
				srvState.CurveID, srvState.CurveID, mlkemGroups)
		}
	case err := <-serverErr:
		t.Fatalf("server handshake: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for server handshake to complete")
	}

	if clientState.Version != ctls.VersionTLS13 {
		t.Fatalf("client negotiated TLS version %x, want TLS 1.3", clientState.Version)
	}
	if _, ok := mlkemGroups[clientState.CurveID]; !ok {
		t.Fatalf("client CurveID = %v (%s), want one of the ML-KEM hybrid groups %v",
			clientState.CurveID, clientState.CurveID, mlkemGroups)
	}
}

// acceptAndHandshakeMLKEM accepts a single connection on ln, completes the
// server-side TLS handshake, and reports the outcome on serverDone/serverErr.
// Extracted from TestSetup_HandshakeNegotiatesMLKEM to keep that test's
// cognitive complexity within bounds.
func acceptAndHandshakeMLKEM(ln net.Listener, serverDone chan<- *ctls.ConnectionState, serverErr chan<- error) {
	conn, acceptErr := ln.Accept()
	if acceptErr != nil {
		serverErr <- acceptErr
		return
	}
	defer func() {
		_ = conn.Close() //nolint:errcheck // best-effort close of a test-only connection in a background goroutine; logging after the test may complete is unsafe
	}()
	tlsConn, ok := conn.(*ctls.Conn)
	if !ok {
		serverErr <- fmt.Errorf("accepted conn is not *tls.Conn: %T", conn)
		return
	}
	if hsErr := tlsConn.HandshakeContext(context.Background()); hsErr != nil {
		serverErr <- hsErr
		return
	}
	state := tlsConn.ConnectionState()
	serverDone <- &state
}

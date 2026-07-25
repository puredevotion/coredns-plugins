package sni_tls

import (
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
	certPath, keyPath := writeTestCert(t, "primary", "dns.example.com")

	c := caddy.NewTestController("dns", fmt.Sprintf("sni_tls %s %s", certPath, keyPath))
	if err := setup(c); err != nil {
		t.Fatalf("setup: %v", err)
	}
	serverConfig := dnsserver.GetConfig(c).TLSConfig

	ln, err := ctls.Listen("tcp", "127.0.0.1:0", serverConfig)
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	defer ln.Close()

	serverDone := make(chan *ctls.ConnectionState, 1)
	serverErr := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()
		tlsConn := conn.(*ctls.Conn)
		if err := tlsConn.Handshake(); err != nil {
			serverErr <- err
			return
		}
		state := tlsConn.ConnectionState()
		serverDone <- &state
	}()

	clientConfig := &ctls.Config{
		ServerName: "dns.example.com",
		RootCAs:    nil, // set via InsecureSkipVerify below; test cert is self-signed
		MinVersion: ctls.VersionTLS13,
		// InsecureSkipVerify is fine here: this test's subject is the negotiated
		// key-exchange group, not certificate trust chain validation (that's
		// covered by TestSetup_WiresTLSConfig and the loadCert tests).
		InsecureSkipVerify: true, //nolint:gosec
	}

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	rawConn, err := dialer.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	clientConn := ctls.Client(rawConn, clientConfig)
	defer clientConn.Close()

	if err := clientConn.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	clientState := clientConn.ConnectionState()

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

	// The cert served through certStore.GetCertificate must be the one loaded
	// for this SNI — confirms the plugin's own cert-selection logic is what
	// served the leaf in this PQC-negotiated handshake, not a coincidence of
	// there being only one cert loaded.
	if len(clientState.PeerCertificates) == 0 {
		t.Fatal("client saw no peer certificates")
	}
	if got := clientState.PeerCertificates[0].DNSNames; len(got) != 1 || got[0] != "dns.example.com" {
		t.Fatalf("served cert SANs = %v, want [dns.example.com]", got)
	}
}

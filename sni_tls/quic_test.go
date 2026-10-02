package snitls

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/quic-go/quic-go"
)

// addrConn is a net.Conn that only reports addresses, the shape of what
// quic-go puts in ClientHelloInfo.Conn.
type addrConn struct {
	net.Conn
	local net.Addr
}

func (c addrConn) LocalAddr() net.Addr { return c.local }

var (
	udpConn = addrConn{local: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 53), Port: 853}}
	tcpConn = addrConn{local: &net.TCPAddr{IP: net.IPv4(192, 0, 2, 53), Port: 853}}
)

func TestOverQUIC(t *testing.T) {
	for name, tc := range map[string]struct {
		conn net.Conn
		want bool
	}{
		"UDP local address": {udpConn, true},
		"TCP local address": {tcpConn, false},
		"no Conn":           {nil, false},
		"no local address":  {addrConn{}, false},
	} {
		if got := overQUIC(&tls.ClientHelloInfo{Conn: tc.conn}); got != tc.want {
			t.Errorf("%s: overQUIC = %v, want %v", name, got, tc.want)
		}
	}
}

// RFC 8446 §9.2: a server requiring SNI "SHOULD respond to a ClientHello
// lacking a "server_name" extension by terminating the connection with a
// "missing_extension" alert". Every policy that refuses a no-SNI client does
// so over QUIC; over TCP, and for a present but unmatched SNI, the refusal
// stays (nil, nil), which crypto/tls sends as the RFC 6066 alert (112).
func TestGetCertificate_NoSNIRefusalOverQUICIsMissingExtension(t *testing.T) {
	primary := &tls.Certificate{}
	refusing := map[string]*certStore{
		"strict, no_sni unset":             {noSNI: noSNIAsUnmatched, strict: true},
		"no_sni refuse":                    {noSNI: noSNIRefuse},
		"no_sni cert, files still missing": {noSNI: noSNICertificate, strict: true},
	}
	for name, s := range refusing {
		s.byName = map[string]*tls.Certificate{testSNIPrimary: primary}
		s.fallback = primary

		got, err := s.GetCertificate(&tls.ClientHelloInfo{Conn: udpConn})
		if a, ok := errors.AsType[tls.AlertError](err); got != nil || !ok || a != alertMissingExtension {
			t.Errorf("%s, QUIC, no SNI: got (%v, %v), want a missing_extension refusal", name, got, err)
		}
		if got, err := s.GetCertificate(&tls.ClientHelloInfo{Conn: tcpConn}); got != nil || err != nil {
			t.Errorf("%s, TCP, no SNI: got (%v, %v), want (nil, nil)", name, got, err)
		}
	}

	strict := &certStore{byName: map[string]*tls.Certificate{testSNIPrimary: primary}, fallback: primary, strict: true}
	if got, err := strict.GetCertificate(&tls.ClientHelloInfo{Conn: udpConn, ServerName: testSNIUnknown}); got != nil || err != nil {
		t.Errorf("QUIC, unmatched SNI: got (%v, %v), want (nil, nil), sent as alert 112", got, err)
	}
	served := &certStore{byName: map[string]*tls.Certificate{testSNIPrimary: primary}, fallback: primary, noSNI: noSNIFallback, strict: true}
	if got, err := served.GetCertificate(&tls.ClientHelloInfo{Conn: udpConn}); got != primary || err != nil {
		t.Errorf("QUIC, no SNI, no_sni fallback: got (%v, %v), want the fallback cert", got, err)
	}
}

// End to end through quic-go, the stack CoreDNS's DoQ server uses, with the
// tls.Config setup() installs. A client dialling an IP address sends no SNI,
// which is exactly the DDR-by-IP case. The alert arrives as CRYPTO_ERROR
// 0x0100 + alert (RFC 9001 §4.8).
func TestSetup_QUICHandshakeAlerts(t *testing.T) {
	certPath, keyPath := writeTestCert(t, "primary", testSNIPrimary)
	ipCert, ipKey := writeIPCert(t, "vip", net.IPv4(127, 0, 0, 1))
	const (
		cryptoError = 0x0100
		strict      = "strict"
	)

	tests := []struct {
		name      string
		opts      string
		sni       string
		wantAlert uint8 // 0: the handshake succeeds.
	}{
		{"strict, no SNI", strict, "", uint8(alertMissingExtension)},
		{"no_sni refuse, no SNI", "no_sni refuse", "", uint8(alertMissingExtension)},
		{"strict, unmatched SNI", strict, testSNIUnknown, 112},
		{"strict, matched SNI", strict, testSNIPrimary, 0},
		{"strict + no_sni cert, no SNI", fmt.Sprintf("strict\nno_sni cert %s %s", ipCert, ipKey), "", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := caddy.NewTestController("dns", fmt.Sprintf("sni_tls %s %s\nsni_tls {\n%s\n}", certPath, keyPath, tt.opts))
			if err := setup(c); err != nil {
				t.Fatalf("setup: %v", err)
			}
			serverConfig := dnsserver.GetConfig(c).TLSConfig
			serverConfig.NextProtos = []string{"doq"} // As core/dnsserver/server_quic.go does.

			err := quicHandshake(t, serverConfig, tt.sni)
			if tt.wantAlert == 0 {
				if err != nil {
					t.Fatalf("handshake failed: %v", err)
				}
				return
			}
			var te *quic.TransportError
			if !errors.As(err, &te) || !te.Remote || te.ErrorCode != quic.TransportErrorCode(cryptoError+uint16(tt.wantAlert)) {
				t.Fatalf("handshake error = %v, want the server's CRYPTO_ERROR for alert %d", err, tt.wantAlert)
			}
		})
	}
}

// quicHandshake dials a quic-go listener serving serverConfig on loopback and
// returns the client's handshake error.
func quicHandshake(t *testing.T, serverConfig *tls.Config, sni string) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ln, err := quic.ListenAddr("127.0.0.1:0", serverConfig, nil)
	if err != nil {
		t.Fatalf("quic listen: %v", err)
	}
	defer func() {
		if closeErr := ln.Close(); closeErr != nil {
			t.Logf("close listener: %v", closeErr)
		}
	}()
	go func() {
		for {
			conn, acceptErr := ln.Accept(ctx)
			if acceptErr != nil {
				return
			}
			<-conn.HandshakeComplete()
		}
	}()

	conn, err := quic.DialAddr(ctx, ln.Addr().String(), &tls.Config{
		ServerName:         sni,
		NextProtos:         []string{"doq"},
		InsecureSkipVerify: true, //nolint:gosec // Self-signed test certs; the subject is the alert.
	}, nil)
	if err != nil {
		return fmt.Errorf("quic dial: %w", err)
	}
	if err := conn.CloseWithError(0, ""); err != nil {
		t.Logf("close conn: %v", err)
	}
	return nil
}

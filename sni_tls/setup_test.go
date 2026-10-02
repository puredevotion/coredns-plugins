package snitls

import (
	"context"
	ctls "crypto/tls"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
)

func TestSetup(t *testing.T) {
	certPath, keyPath := writeTestCert(t, "primary", testSNIPrimary)
	cert2Path, key2Path := writeTestCert(t, "secondary", testSNISecondary)

	tests := []struct {
		input     string
		shouldErr bool
	}{
		{fmt.Sprintf("sni_tls %s %s", certPath, keyPath), false},
		{fmt.Sprintf("sni_tls %s %s\nsni_tls %s %s", certPath, keyPath, cert2Path, key2Path), false},
		{fmt.Sprintf("sni_tls %s", certPath), true}, // Missing key arg.
		{"sni_tls", true}, // Missing both args.
		{fmt.Sprintf("sni_tls %s %s c", certPath, keyPath), true}, // Too many args.
	}

	for i, tc := range tests {
		c := caddy.NewTestController("dns", tc.input)
		err := setup(c)
		if tc.shouldErr && err == nil {
			t.Errorf("test %d: expected error, got none", i)
		}
		if !tc.shouldErr && err != nil {
			t.Errorf("test %d: expected no error, got %v", i, err)
		}
	}
}

// TestSetup_MissingCertFile covers the load-failure path end-to-end through
// setup(), not just buildCertStore directly, ensuring the plugin.Error wrap
// happens and no partial TLSConfig is left behind on failure.
func TestSetup_MissingCertFile(t *testing.T) {
	c := caddy.NewTestController("dns", "sni_tls /nonexistent/cert.pem /nonexistent/key.pem")
	if err := setup(c); err == nil {
		t.Fatal("expected error for missing cert file")
	}
}

// TestSetup_WiresTLSConfig confirms setup() actually installs a *tls.Config
// on the server's dnsserver.Config (the part the original stub never did —
// it stopped after parsing args) and that its GetCertificate resolves SNI
// through the plugin's own certStore logic, end-to-end from Corefile text to
// a working TLS callback.
func TestSetup_WiresTLSConfig(t *testing.T) {
	primaryCert, primaryKey := writeTestCert(t, "primary", testSNIPrimary)
	secondaryCert, secondaryKey := writeTestCert(t, "secondary", testSNISecondary)

	input := fmt.Sprintf("sni_tls %s %s\nsni_tls %s %s", primaryCert, primaryKey, secondaryCert, secondaryKey)
	c := caddy.NewTestController("dns", input)
	if err := setup(c); err != nil {
		t.Fatalf("setup: %v", err)
	}

	tlsConfig := dnsserver.GetConfig(c).TLSConfig
	if tlsConfig == nil {
		t.Fatal("setup did not install a TLSConfig on the server config")
	}
	if tlsConfig.GetCertificate == nil {
		t.Fatal("installed TLSConfig has no GetCertificate callback wired")
	}
	if tlsConfig.MinVersion != ctls.VersionTLS12 {
		t.Fatalf("MinVersion = %v, want TLS 1.2 (matches plugin/pkg/tls's default)", tlsConfig.MinVersion)
	}
	// Static Certificates must be unset: GetCertificate takes priority when
	// both are set, but the design doc (step 2) says omit Certificates for
	// clarity — also guards against a future edit accidentally setting both.
	if len(tlsConfig.Certificates) != 0 {
		t.Fatalf("TLSConfig.Certificates must be empty when GetCertificate is used, got %d entries", len(tlsConfig.Certificates))
	}

	primary, err := tlsConfig.GetCertificate(&ctls.ClientHelloInfo{ServerName: testSNIPrimary})
	if err != nil {
		t.Fatalf("GetCertificate(dns.example.com): %v", err)
	}
	secondary, err := tlsConfig.GetCertificate(&ctls.ClientHelloInfo{ServerName: testSNISecondary})
	if err != nil {
		t.Fatalf("GetCertificate(dns.internal.example): %v", err)
	}
	if primary == nil || secondary == nil || primary == secondary {
		t.Fatalf("expected two distinct certs, got primary=%v secondary=%v", primary, secondary)
	}

	fallback, err := tlsConfig.GetCertificate(&ctls.ClientHelloInfo{ServerName: "unmatched.example.org"})
	if err != nil {
		t.Fatalf("GetCertificate(unmatched): %v", err)
	}
	if fallback != primary {
		t.Fatal("unmatched SNI must fall back to the first-loaded (primary) cert")
	}
}

// TestSetup_StrictBlock covers the `sni_tls { strict }` option line: it must
// parse alongside ordinary `sni_tls <cert> <key>` lines (in either order),
// reject unknown option tokens, and reject a bare block with nothing in it
// the same way a bare `sni_tls` with no args already does.
func TestSetup_StrictBlock(t *testing.T) {
	certPath, keyPath := writeTestCert(t, "primary", testSNIPrimary)

	tests := []struct {
		name      string
		input     string
		shouldErr bool
	}{
		{
			"strict after cert lines",
			fmt.Sprintf("sni_tls %s %s\nsni_tls {\n  strict\n}", certPath, keyPath),
			false,
		},
		{
			"strict before cert lines",
			fmt.Sprintf("sni_tls {\n  strict\n}\nsni_tls %s %s", certPath, keyPath),
			false,
		},
		{
			"unknown option",
			fmt.Sprintf("sni_tls %s %s\nsni_tls {\n  bogus\n}", certPath, keyPath),
			true,
		},
		{
			"strict takes no args",
			fmt.Sprintf("sni_tls %s %s\nsni_tls {\n  strict extra\n}", certPath, keyPath),
			true,
		},
	}

	for _, tc := range tests {
		c := caddy.NewTestController("dns", tc.input)
		err := setup(c)
		if tc.shouldErr && err == nil {
			t.Errorf("%s: expected error, got none", tc.name)
		}
		if !tc.shouldErr && err != nil {
			t.Errorf("%s: expected no error, got %v", tc.name, err)
		}
	}
}

// TestSetup_StrictBlock_RejectsUnmatchedSNI confirms the parsed `strict`
// option actually reaches the installed TLSConfig's GetCertificate, end to
// end from Corefile text -- not just that setup() accepts the syntax.
func TestSetup_StrictBlock_RejectsUnmatchedSNI(t *testing.T) {
	certPath, keyPath := writeTestCert(t, "primary", testSNIPrimary)
	input := fmt.Sprintf("sni_tls %s %s\nsni_tls {\n  strict\n}", certPath, keyPath)
	c := caddy.NewTestController("dns", input)
	if err := setup(c); err != nil {
		t.Fatalf("setup: %v", err)
	}

	tlsConfig := dnsserver.GetConfig(c).TLSConfig
	if refused, err := tlsConfig.GetCertificate(&ctls.ClientHelloInfo{ServerName: "unmatched.example.org"}); refused != nil || err != nil {
		t.Fatalf("strict mode: expected unmatched SNI to be refused with (nil, nil), got (%v, %v)", refused, err)
	}
	got, err := tlsConfig.GetCertificate(&ctls.ClientHelloInfo{ServerName: testSNIPrimary})
	if err != nil || got == nil {
		t.Fatalf("strict mode: configured SNI must still resolve: got=%v err=%v", got, err)
	}
}

// TestSetup_RejectsDoubleTLSConfig mirrors the stock tls plugin's guard
// (plugin/tls's parseTLS: "TLS already configured for this server instance")
// — sni_tls must refuse to silently overwrite an existing TLSConfig set by an
// earlier tls/sni_tls directive in the same server block.
func TestSetup_RejectsDoubleTLSConfig(t *testing.T) {
	certPath, keyPath := writeTestCert(t, "primary", testSNIPrimary)
	c := caddy.NewTestController("dns", fmt.Sprintf("sni_tls %s %s", certPath, keyPath))
	dnsserver.GetConfig(c).TLSConfig = &ctls.Config{}

	if err := setup(c); err == nil {
		t.Fatal("expected error when TLSConfig is already set, got nil")
	}
}

// RFC 6066 §3: a server that "does not recognize the server name" SHOULD
// abort with a fatal unrecognized_name(112) alert. Strict mode's refusal
// used to be an error, which crypto/tls sends as internal_error(80).
//
//nolint:misspell // RFC 6066 §3 and crypto/tls's alert text are quoted verbatim, in US spelling.
func TestSetup_StrictRefusalSendsUnrecognizedName(t *testing.T) {
	certPath, keyPath := writeTestCert(t, "primary", testSNIPrimary)
	c := caddy.NewTestController("dns", fmt.Sprintf("sni_tls %s %s\nsni_tls {\n  strict\n}", certPath, keyPath))
	if err := setup(c); err != nil {
		t.Fatalf("setup: %v", err)
	}
	serverConfig := dnsserver.GetConfig(c).TLSConfig

	for _, tc := range []struct {
		name    string
		sni     string
		version uint16
	}{
		{"TLS 1.2 unmatched SNI", testSNIUnknown, ctls.VersionTLS12},
		{"TLS 1.3 unmatched SNI", testSNIUnknown, ctls.VersionTLS13},
		{"TLS 1.3 absent SNI", "", ctls.VersionTLS13},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clientSide, serverSide := net.Pipe()
			server := ctls.Server(serverSide, serverConfig)
			serverDone := make(chan struct{})
			go func() {
				defer close(serverDone)
				_ = server.HandshakeContext(context.Background()) //nolint:errcheck // The refusal is observed from the client side.
				_ = server.Close()                                //nolint:errcheck // net.Pipe close cannot fail meaningfully here.
			}()

			client := ctls.Client(clientSide, &ctls.Config{
				ServerName:         tc.sni,
				MinVersion:         tc.version,
				MaxVersion:         tc.version,
				InsecureSkipVerify: true, //nolint:gosec // The handshake must be refused before any certificate is sent.
			})
			err := client.HandshakeContext(context.Background())
			_ = client.Close() //nolint:errcheck // net.Pipe close cannot fail meaningfully here.
			<-serverDone
			if err == nil || !strings.Contains(err.Error(), "unrecognized name") {
				t.Errorf("client handshake error = %v, want the unrecognized_name alert", err)
			}
		})
	}
}

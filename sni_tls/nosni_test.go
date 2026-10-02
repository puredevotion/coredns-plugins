package snitls

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
)

// testVIP is the address a DDR-by-IP client connects to, which RFC 9462 §4.2
// wants in the no-SNI cert's iPAddress SANs.
var testVIP = net.ParseIP("192.0.2.53")

// TestGetCertificate_NoSNIPolicies pins every policy against every kind of
// ClientHello, in both modes. The policy changes only the absent-SNI row;
// a present SNI, matched or not, is answered as before.
func TestGetCertificate_NoSNIPolicies(t *testing.T) {
	primary, own := &tls.Certificate{}, &tls.Certificate{}
	type want struct{ absent, unmatched, matched *tls.Certificate }
	tests := []struct {
		noSNICert *tls.Certificate
		want      want
		name      string
		policy    noSNIPolicy
		strict    bool
	}{
		{name: "default", policy: noSNIAsUnmatched, want: want{primary, primary, primary}},
		{name: "default strict", policy: noSNIAsUnmatched, strict: true, want: want{nil, nil, primary}},
		{name: "refuse", policy: noSNIRefuse, want: want{nil, primary, primary}},
		{name: "refuse strict", policy: noSNIRefuse, strict: true, want: want{nil, nil, primary}},
		{name: "fallback", policy: noSNIFallback, want: want{primary, primary, primary}},
		{name: "fallback strict", policy: noSNIFallback, strict: true, want: want{primary, nil, primary}},
		{name: "cert", policy: noSNICertificate, noSNICert: own, want: want{own, primary, primary}},
		{name: "cert strict", policy: noSNICertificate, noSNICert: own, strict: true, want: want{own, nil, primary}},
		{name: "cert strict, cert not loaded yet", policy: noSNICertificate, strict: true, want: want{nil, nil, primary}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &certStore{
				byName:    map[string]*tls.Certificate{testSNIPrimary: primary},
				fallback:  primary,
				noSNICert: tt.noSNICert,
				noSNI:     tt.policy,
				strict:    tt.strict,
			}
			for sni, w := range map[string]*tls.Certificate{"": tt.want.absent, testSNIUnknown: tt.want.unmatched, testSNIPrimary: tt.want.matched} {
				got, err := s.GetCertificate(&tls.ClientHelloInfo{ServerName: sni})
				if err != nil {
					t.Errorf("SNI %q: error %v; a refusal must be (nil, nil)", sni, err)
				}
				if got != w {
					t.Errorf("SNI %q: got %p, want %p", sni, got, w)
				}
			}
		})
	}
}

func TestParseConfig_NoSNIOption(t *testing.T) {
	block := func(opts string) string { return "sni_tls c.pem k.pem\nsni_tls {\n" + opts + "\n}" }
	tests := []struct {
		input   string
		pair    [2]string
		want    noSNIPolicy
		wantErr bool
	}{
		{input: block("strict"), want: noSNIAsUnmatched},
		{input: block("no_sni refuse"), want: noSNIRefuse},
		{input: block("strict\nno_sni fallback"), want: noSNIFallback},
		{input: block("no_sni cert ip.pem ip.key\nstrict"), want: noSNICertificate, pair: [2]string{"ip.pem", "ip.key"}},
		{input: block("no_sni"), wantErr: true},
		{input: block("no_sni sometimes"), wantErr: true},
		{input: block("no_sni refuse extra"), wantErr: true},
		{input: block("no_sni cert ip.pem"), wantErr: true},
		{input: block("no_sni refuse\nno_sni fallback"), wantErr: true},
	}
	for _, tt := range tests {
		cfg, err := parseConfig(caddy.NewTestController("dns", tt.input))
		if tt.wantErr {
			if err == nil {
				t.Errorf("%q: expected a parse error", tt.input)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: %v", tt.input, err)
			continue
		}
		if cfg.noSNI != tt.want || cfg.noSNIPair != tt.pair {
			t.Errorf("%q: policy %d with %v, want %d with %v", tt.input, cfg.noSNI, cfg.noSNIPair, tt.want, tt.pair)
		}
	}
}

// A missing no_sni cert is tolerated like any other missing file (design doc
// step 5); a broken one is a misconfiguration and fails setup.
func TestSetup_NoSNICertMissingVersusBroken(t *testing.T) {
	certPath, keyPath := writeTestCert(t, "primary", testSNIPrimary)
	_, otherKey := writeTestCert(t, "other", testSNISecondary)
	ipCert, _ := writeIPCert(t, "vip", testVIP)
	input := func(c, k string) string {
		return fmt.Sprintf("sni_tls %s %s\nsni_tls {\nno_sni cert %s %s\n}", certPath, keyPath, c, k)
	}
	if err := setup(caddy.NewTestController("dns", input("/nonexistent/c.pem", "/nonexistent/k.pem"))); err != nil {
		t.Errorf("missing no_sni cert: setup failed: %v", err)
	}
	if err := setup(caddy.NewTestController("dns", input(ipCert, otherKey))); err == nil {
		t.Error("a no_sni cert with the wrong key was accepted")
	}
}

// RFC 9462 §6.3 asks a DDR-by-IP resolver to "present the appropriate TLS
// certificate when no SNI is present". With strict and `no_sni cert`, a
// client without SNI gets the IP cert over a real handshake, while one
// sending an unknown SNI is still refused with the RFC 6066 alert.
func TestSetup_StrictWithNoSNICert_Handshakes(t *testing.T) {
	certPath, keyPath := writeTestCert(t, "primary", testSNIPrimary)
	ipCert, ipKey := writeIPCert(t, "vip", testVIP)
	input := fmt.Sprintf("sni_tls %s %s\nsni_tls {\n  strict\n  no_sni cert %s %s\n}", certPath, keyPath, ipCert, ipKey)
	c := caddy.NewTestController("dns", input)
	if err := setup(c); err != nil {
		t.Fatalf("setup: %v", err)
	}
	serverConfig := dnsserver.GetConfig(c).TLSConfig

	state, err := handshake(serverConfig, "")
	if err != nil {
		t.Fatalf("no-SNI handshake: %v", err)
	}
	if ips := state.PeerCertificates[0].IPAddresses; len(ips) != 1 || !ips[0].Equal(testVIP) {
		t.Errorf("no-SNI client got a cert for %v, want the %v cert", ips, testVIP)
	}

	if _, err = handshake(serverConfig, testSNIUnknown); err == nil || !strings.Contains(err.Error(), "unrecognized name") { //nolint:misspell // crypto/tls's alert text, verbatim.
		t.Errorf("unmatched SNI: handshake error = %v, want the RFC 6066 alert", err)
	}

	state, err = handshake(serverConfig, testSNIPrimary)
	if err != nil {
		t.Fatalf("matched SNI handshake: %v", err)
	}
	if got := state.PeerCertificates[0].DNSNames; len(got) != 1 || got[0] != testSNIPrimary {
		t.Errorf("matched SNI got cert for %v", got)
	}
}

// `no_sni fallback` with strict: a no-SNI client gets the first cert, an
// unmatched SNI is still refused.
func TestSetup_StrictWithNoSNIFallback_Handshakes(t *testing.T) {
	certPath, keyPath := writeTestCert(t, "primary", testSNIPrimary)
	cert2, key2 := writeTestCert(t, "secondary", testSNISecondary)
	input := fmt.Sprintf("sni_tls %s %s\nsni_tls %s %s\nsni_tls {\n  strict\n  no_sni fallback\n}", certPath, keyPath, cert2, key2)
	c := caddy.NewTestController("dns", input)
	if err := setup(c); err != nil {
		t.Fatalf("setup: %v", err)
	}
	serverConfig := dnsserver.GetConfig(c).TLSConfig

	state, err := handshake(serverConfig, "")
	if err != nil {
		t.Fatalf("no-SNI handshake: %v", err)
	}
	if got := state.PeerCertificates[0].DNSNames; len(got) != 1 || got[0] != testSNIPrimary {
		t.Errorf("no-SNI client got cert for %v, want the first-loaded %s", got, testSNIPrimary)
	}
	if _, err := handshake(serverConfig, testSNIUnknown); err == nil {
		t.Error("unmatched SNI was served under strict + no_sni fallback")
	}
}

// handshake runs one client handshake against serverConfig over a pipe.
func handshake(serverConfig *tls.Config, sni string) (tls.ConnectionState, error) {
	clientSide, serverSide := net.Pipe()
	server := tls.Server(serverSide, serverConfig)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = server.HandshakeContext(context.Background()) //nolint:errcheck // The outcome is observed from the client side.
		// The raw pipe, not the tls.Conn: after a completed handshake its
		// Close writes close_notify, which nobody reads on a net.Pipe.
		_ = serverSide.Close() //nolint:errcheck // net.Pipe close cannot fail meaningfully here.
	}()
	client := tls.Client(clientSide, &tls.Config{
		ServerName:         sni,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, //nolint:gosec // Self-signed test certs; the subject is which cert is served.
	})
	err := client.HandshakeContext(context.Background())
	state := client.ConnectionState()
	_ = clientSide.Close() //nolint:errcheck // net.Pipe close cannot fail meaningfully here.
	<-done
	if err != nil {
		return state, fmt.Errorf("client handshake: %w", err)
	}
	return state, nil
}

// The no_sni cert is polled and hot-reloaded like the SNI certs: a missing
// one is tolerated (no-SNI clients refused) and picked up once it appears,
// and a rotation of it is picked up too.
func TestLiveStore_NoSNICertHotReload(t *testing.T) {
	certPath, keyPath := writeTestCert(t, "primary", testSNIPrimary)
	ipCert, ipKey := writeIPCert(t, "vip", testVIP)
	dir := t.TempDir()
	noSNICert, noSNIKey := dir+"/nosni.crt", dir+"/nosni.key"

	cfg := storeConfig{
		pairs:     [][2]string{{certPath, keyPath}},
		strict:    true,
		noSNI:     noSNICertificate,
		noSNIPair: [2]string{noSNICert, noSNIKey},
	}
	store, err := buildCertStore(cfg)
	if err != nil {
		t.Fatalf("buildCertStore with the no_sni files missing: %v", err)
	}
	live := newLiveStore(cfg, store, digestPairs(cfg.files()))
	if got, _ := live.GetCertificate(&tls.ClientHelloInfo{}); got != nil { //nolint:errcheck // A refusal is (nil, nil).
		t.Fatal("served a cert without SNI before the no_sni cert existed")
	}

	overwrite(t, noSNICert, ipCert)
	overwrite(t, noSNIKey, ipKey)
	live.reloadOnce()
	first, _ := live.GetCertificate(&tls.ClientHelloInfo{}) //nolint:errcheck // A refusal is (nil, nil).
	if first == nil || len(first.Leaf.IPAddresses) != 1 {
		t.Fatalf("no_sni cert not picked up once it appeared: %v", first)
	}

	rotatedCert, rotatedKey := writeIPCert(t, "vip2", testVIP)
	overwrite(t, noSNICert, rotatedCert)
	overwrite(t, noSNIKey, rotatedKey)
	live.reloadOnce()
	if second, _ := live.GetCertificate(&tls.ClientHelloInfo{}); second == first { //nolint:errcheck // A refusal is (nil, nil).
		t.Error("a rotated no_sni cert was not reloaded")
	}
}

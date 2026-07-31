package probe

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"testing"
)

func testECHKey() []byte {
	k := make([]byte, x25519PubKeyLen)
	for i := range k {
		k[i] = byte(i + 1)
	}
	return k
}

// TestECHConfigListRoundTrip checks our own encoder against our own parser. Weak
// on its own — a symmetric bug passes — which is why TestECHConfigListAcceptedByCryptoTLS
// below exists.
func TestECHConfigListRoundTrip(t *testing.T) {
	key := testECHKey()
	list, err := BuildECHConfigList(0x2a, key, "check.example.com")
	if err != nil {
		t.Fatalf("BuildECHConfigList: %v", err)
	}

	id, gotKey, name, err := ParseECHConfigList(list)
	if err != nil {
		t.Fatalf("ParseECHConfigList: %v", err)
	}
	if id != 0x2a {
		t.Errorf("configID = %#x, want 0x2a", id)
	}
	if !bytes.Equal(gotKey, key) {
		t.Errorf("public key round trip mismatch")
	}
	if name != "check.example.com" {
		t.Errorf("publicName = %q", name)
	}
}

// TestECHConfigListAcceptedByCryptoTLS is the assertion that actually matters.
// Every length prefix in this encoding is hand-written, and a wrong one produces
// bytes a resolver may forward happily while no client can parse them — the
// failure would look like a successful measurement.
//
// crypto/tls is the real consumer: it parses ECHConfigList when a client is
// configured with one. A malformed list fails at parse time with a distinctive
// error, before any network activity, which is what this detects.
func TestECHConfigListAcceptedByCryptoTLS(t *testing.T) {
	list, err := BuildECHConfigList(0x01, testECHKey(), "public.example.com")
	if err != nil {
		t.Fatalf("BuildECHConfigList: %v", err)
	}

	// The pipe must stay OPEN and be drained, so the ClientHello is actually
	// CONSTRUCTED and written. That is the step which parses the config list and
	// encrypts the inner hello with it. Closing the pipe first (the obvious way to
	// write this test) makes the write fail before ECH is ever touched, so the test
	// passes while validating nothing — worth stating, because that was the first
	// version of this test.
	c1, c2 := net.Pipe()
	defer func() { _ = c1.Close() }()
	defer func() { _ = c2.Close() }()

	var hello []byte
	read := make(chan struct{})
	go func() {
		defer close(read)
		buf := make([]byte, 16384)
		n, _ := c2.Read(buf)
		hello = buf[:n]
		// Drop the connection rather than answering: we only need the ClientHello.
		_ = c2.Close()
	}()

	conn := tls.Client(c1, &tls.Config{
		ServerName:                     "inner.example.com",
		EncryptedClientHelloConfigList: list,
		MinVersion:                     tls.VersionTLS13,
	})
	err = conn.Handshake()
	<-read

	if err == nil {
		t.Fatal("handshake unexpectedly succeeded")
	}

	// crypto/tls reports a bad list as an ECH/config parse failure rather than an
	// I/O error. Anything naming the config is a real finding about our encoding.
	msg := strings.ToLower(err.Error())
	for _, bad := range []string{"ech", "encryptedclienthello", "config list", "invalid"} {
		if strings.Contains(msg, bad) {
			t.Fatalf("crypto/tls rejected our ECHConfigList: %v", err)
		}
	}

	// Proof the config was actually consumed: a ClientHello was built and sent. If
	// crypto/tls had refused the list it would have errored before writing a byte.
	if len(hello) == 0 {
		t.Fatal("no ClientHello was written, so the ECH config was never exercised")
	}
	if hello[0] != 0x16 {
		t.Errorf("first byte %#x is not a TLS handshake record", hello[0])
	}
	t.Logf("crypto/tls accepted the config and wrote a %d-byte ClientHello; handshake then failed on transport: %v", len(hello), err)
}

// TestECHConfigListRejectsBadInput — refusing to encode is better than encoding
// something unusable, because the unusable version would be published and measured
// as if it were fine.
func TestECHConfigListRejectsBadInput(t *testing.T) {
	for _, tc := range []struct {
		name string
		key  []byte
		pub  string
	}{
		{"short key", make([]byte, 31), "example.com"},
		{"long key", make([]byte, 33), "example.com"},
		{"nil key", nil, "example.com"},
		{"public_name too long", testECHKey(), strings.Repeat("a", 256)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := BuildECHConfigList(1, tc.key, tc.pub); err == nil {
				t.Error("encoded invalid input")
			}
		})
	}

	if _, err := BuildECHConfigList(1, make([]byte, 31), "x"); !errors.Is(err, ErrECHPublicKeyLen) {
		t.Errorf("err = %v, want ErrECHPublicKeyLen", err)
	}
}

// TestParseECHConfigListDetectsTampering is the measurement's whole point: a config
// that arrives altered must be detectable as altered, not silently accepted.
func TestParseECHConfigListDetectsTampering(t *testing.T) {
	good, err := BuildECHConfigList(0x05, testECHKey(), "check.example.com")
	if err != nil {
		t.Fatalf("BuildECHConfigList: %v", err)
	}

	t.Run("truncated", func(t *testing.T) {
		// The most likely real-world mangling: something on the path shortened it.
		// The outer length prefix no longer matches, which is reported distinctly.
		if _, _, _, err := ParseECHConfigList(good[:len(good)-4]); err == nil {
			t.Error("truncated list parsed as valid")
		} else if !strings.Contains(err.Error(), "bytes follow") {
			t.Errorf("truncation not reported as a length mismatch: %v", err)
		}
	})

	t.Run("version rewritten", func(t *testing.T) {
		bad := bytes.Clone(good)
		binary.BigEndian.PutUint16(bad[2:4], 0xfe0a) // an older draft codepoint
		if _, _, _, err := ParseECHConfigList(bad); err == nil {
			t.Error("rewritten version parsed as valid")
		}
	})

	t.Run("KEM rewritten", func(t *testing.T) {
		bad := bytes.Clone(good)
		// version(2) + len(2) + configID(1) -> KEM at offset 2+2+2+1 = 7
		binary.BigEndian.PutUint16(bad[7:9], 0x0010)
		if _, _, _, err := ParseECHConfigList(bad); err == nil {
			t.Error("rewritten KEM parsed as valid")
		}
	})

	t.Run("empty and stub inputs", func(t *testing.T) {
		for _, in := range [][]byte{nil, {}, {0x00}, {0x00, 0x05}} {
			if _, _, _, err := ParseECHConfigList(in); err == nil {
				t.Errorf("%v parsed as valid", in)
			}
		}
	})
}

// TestECHConfigListIsDeterministic — the measurement compares bytes we serve against
// bytes that arrived. That comparison is only possible if the same inputs always
// produce the same output, so this pins it rather than leaving it to luck.
func TestECHConfigListIsDeterministic(t *testing.T) {
	a, err := BuildECHConfigList(9, testECHKey(), "check.example.com")
	if err != nil {
		t.Fatal(err)
	}
	b, err := BuildECHConfigList(9, testECHKey(), "check.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Error("BuildECHConfigList is not deterministic; the transport comparison depends on it")
	}
}

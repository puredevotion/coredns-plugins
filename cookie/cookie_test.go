package cookie

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"net/netip"
	"testing"
)

func mustHex(tb testing.TB, s string) []byte {
	tb.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		tb.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func key16(tb testing.TB, s string) [16]byte {
	tb.Helper()
	var k [16]byte
	if b := mustHex(tb, s); len(b) != len(k) {
		tb.Fatalf("secret %q is %d bytes, want 16", s, len(b))
	} else {
		copy(k[:], b)
	}
	return k
}

func client8(tb testing.TB, s string) [8]byte {
	tb.Helper()
	var c [8]byte
	if b := mustHex(tb, s); len(b) != len(c) {
		tb.Fatalf("client cookie %q is %d bytes, want 8", s, len(b))
	} else {
		copy(c[:], b)
	}
	return c
}

// clientIP4 is the IPv4 client of RFC 9018 Appendix A.1 and A.2.
const (
	clientC   = "2464c4abcf10c957"
	clientIP4 = "198.51.100.100"
)

// a1Cookie is the server cookie of RFC 9018 Appendix A.1, which A.2 sends back.
const a1Cookie = "010000005cf79f111f8130c3eee29480"

// rfc9018Vector is one server cookie from RFC 9018 Appendix A.
type rfc9018Vector struct {
	name   string
	secret string
	client string
	ip     string
	cookie string
	ts     uint32
}

// The four server cookies RFC 9018 Appendix A prints that this server
// generates, plus the two it only verifies (A.3's request, A.4's request).
var generated = []rfc9018Vector{
	{"A.1 learning a new server cookie", secretA, clientC, clientIP4, a1Cookie, 1559731985},
	{"A.2 renewed (fresh) server cookie", secretA, clientC, clientIP4, "010000005cf7a871d4a564a1442aca77", 1559734385},
	{"A.3 another client, reserved zeroed in the reply", secretA, "fc93fc62807ddb86", "203.0.113.203", "010000005cf7a9acf73a7810aca2381e", 1559734700},
	{"A.4 IPv6 query, new secret", secretB, "22681ab97d52c298", "2001:db8:220:1:59de:d0f4:8769:82b8", "010000005cf7c609a6bb79d16625507a", 1559741961},
}

// TestRFC9018Vectors: serverCookie reproduces every cookie the RFC prints
// that a server generates, byte for byte. This is the SipHash-2-4 byte-order
// and input-layout check: a wrong endianness or field order cannot pass.
func TestRFC9018Vectors(t *testing.T) {
	for _, v := range generated {
		t.Run(v.name, func(t *testing.T) {
			got := serverCookie(key16(t, v.secret), client8(t, v.client), v.ts, netip.MustParseAddr(v.ip))
			if want := mustHex(t, v.cookie); !bytes.Equal(got[:], want) {
				t.Errorf("serverCookie = %x, want %x", got, want)
			}
		})
	}
}

// TestRFC9018Verifies: the cookies a client sends in Appendix A verify. A.3's
// request cookie has Reserved = abcdef ("Note that the Server Cookie has
// Reserved bytes set but is still valid with the configured secret; the Hash
// part is calculated taking along the Reserved bytes."), and A.4's was made
// under the secret the server has since rolled over from.
func TestRFC9018Verifies(t *testing.T) {
	tests := []struct {
		name, secret, client, ip, cookie string
		now                              uint32
	}{
		{"A.1 reply", secretA, clientC, clientIP4, a1Cookie, 1559731985},
		{"A.2 request, 40 minutes old", secretA, clientC, clientIP4, a1Cookie, 1559734385},
		// Checked one minute after the cookie's timestamp. The RFC answers this
		// request at 1559734700, when the cookie is 1 h 52 min old, which is
		// outside the 1-hour window RFC 9018 §4.3 says to allow ("SHOULD allow
		// cookies within a 1-hour period in the past") and which this plugin
		// enforces; the example is about the Reserved bytes, not the age.
		{"A.3 request with reserved bytes set", secretA, "fc93fc62807ddb86", "203.0.113.203", "01abcdef5cf78f71a314227b6679ebf5", 1559727985 + 60},
		{"A.4 request under the previous secret", "dd3bdf9344b678b185a6f5cb60fca715", "22681ab97d52c298", "2001:db8:220:1:59de:d0f4:8769:82b8", "010000005cf7c57926556bd0934c72f8", 1559741961},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ok := verify(key16(t, tc.secret), client8(t, tc.client), mustHex(t, tc.cookie), netip.MustParseAddr(tc.ip), tc.now)
			if !ok {
				t.Error("verify = false, want true")
			}
		})
	}
}

// TestReservedNotEnforced: RFC 9018 §4.2, "On Server Cookie verification, the
// server MUST NOT enforce those fields to be zero, and the Hash should be
// computed with the received value". A.3 above is the RFC's own example; this
// pins both halves: a cookie minted with non-zero Reserved verifies, and the
// same cookie with the Reserved bytes changed after the fact does not.
func TestReservedNotEnforced(t *testing.T) {
	secret := key16(t, secretA)
	client := client8(t, "0102030405060708")
	ip := netip.MustParseAddr("192.0.2.7")
	const ts, now = 1_700_000_000, 1_700_000_100

	// Mint with Reserved = 010203 using the recipe in the RFC.
	cookie := make([]byte, 16)
	cookie[0] = 1
	copy(cookie[1:4], []byte{1, 2, 3})
	binary.BigEndian.PutUint32(cookie[4:8], ts)
	h := siphash24(secret, hashInput(client, 1, [3]byte{1, 2, 3}, ts, ip.AsSlice()))
	binary.LittleEndian.PutUint64(cookie[8:], h)

	if !verify(secret, client, cookie, ip, now) {
		t.Fatal("a cookie with non-zero Reserved bytes must verify")
	}
	cookie[2] ^= 0xff // Tamper with Reserved after hashing.
	if verify(secret, client, cookie, ip, now) {
		t.Fatal("changing Reserved after hashing must break the hash")
	}
}

// TestClassify: RFC 7873 §5.2.2, "In summary, valid cookie lengths are 8 and
// 16 to 40 inclusive" (the summary line).
func TestClassify(t *testing.T) {
	for n := 0; n <= 64; n++ {
		want := classMalformed
		switch {
		case n == 8:
			want = classClientOnly
		case n >= 16 && n <= 40:
			want = classWithServer
		}
		if got := classify(n); got != want {
			t.Errorf("classify(%d) = %v, want %v", n, got, want)
		}
	}
}

// TestHashInputInjective: RFC 9018 §4.4, the SipHash input is exactly 20 bytes
// for an IPv4 client and 32 for IPv6, which "ensures that the input into
// SipHash-2-4 is an injective function of the elements making up the input".
func TestHashInputInjective(t *testing.T) {
	c := client8(t, "0102030405060708")
	v4 := netip.MustParseAddr("192.0.2.1")
	v6 := netip.MustParseAddr("2001:db8::1")
	if n := len(hashInput(c, 1, [3]byte{}, 7, v4.AsSlice())); n != 20 {
		t.Errorf("IPv4 input is %d bytes, want 20", n)
	}
	if n := len(hashInput(c, 1, [3]byte{}, 7, v6.AsSlice())); n != 32 {
		t.Errorf("IPv6 input is %d bytes, want 32", n)
	}

	// Distinct parts give distinct inputs, in every field.
	base := hashInput(c, 1, [3]byte{}, 7, v4.AsSlice())
	variants := map[string][]byte{
		"client":   hashInput(client8(t, "0102030405060709"), 1, [3]byte{}, 7, v4.AsSlice()),
		"version":  hashInput(c, 2, [3]byte{}, 7, v4.AsSlice()),
		"reserved": hashInput(c, 1, [3]byte{0, 0, 1}, 7, v4.AsSlice()),
		"ts":       hashInput(c, 1, [3]byte{}, 8, v4.AsSlice()),
		"ip":       hashInput(c, 1, [3]byte{}, 7, netip.MustParseAddr("192.0.2.2").AsSlice()),
		"family":   hashInput(c, 1, [3]byte{}, 7, v6.AsSlice()),
	}
	for name, in := range variants {
		if bytes.Equal(base, in) {
			t.Errorf("changing only %s did not change the SipHash input", name)
		}
	}
}

// TestIPv4MappedIsIPv4: a client that reaches us as ::ffff:192.0.2.1 hashes
// as 192.0.2.1, so the cookie does not depend on the socket family.
func TestIPv4MappedIsIPv4(t *testing.T) {
	secret := key16(t, "000102030405060708090a0b0c0d0e0f")
	c := client8(t, "0102030405060708")
	plain := netip.MustParseAddr("192.0.2.1")
	mapped := netip.MustParseAddr("::ffff:192.0.2.1")
	if serverCookie(secret, c, 99, plain) != serverCookie(secret, c, 99, mapped) {
		t.Error("IPv4-mapped IPv6 address hashed differently from the IPv4 address")
	}
}

// TestTimestampWindow: RFC 9018 §4.3, at most 1 hour in the past and at most
// 5 minutes in the future, compared in RFC 1982 serial arithmetic, so it holds
// across the wrap of the 32-bit timestamp.
func TestTimestampWindow(t *testing.T) {
	const wrap = uint64(1) << 32
	tests := []struct {
		ts   func(now uint32) uint32
		name string
		now  uint32
		want bool
	}{
		{name: "same second", ts: func(n uint32) uint32 { return n }, now: 5000, want: true},
		{name: "1 h old", ts: func(n uint32) uint32 { return n - 3600 }, now: 5000, want: true},
		{name: "1 h + 1 s old", ts: func(n uint32) uint32 { return n - 3601 }, now: 5000, want: false},
		{name: "5 min ahead", ts: func(n uint32) uint32 { return n + 300 }, now: 5000, want: true},
		{name: "5 min + 1 s ahead", ts: func(n uint32) uint32 { return n + 301 }, now: 5000, want: false},
		{name: "a day old", ts: func(n uint32) uint32 { return n - 86400 }, now: 100000, want: false},
		{name: "half the serial space ahead", ts: func(n uint32) uint32 { return n + 1<<31 }, now: 5000, want: false},
		// The timestamp wraps in February 2106. A cookie minted just before
		// it must stay valid just after, and the other way round.
		{name: "1 h old across the wrap", ts: func(n uint32) uint32 { return n - 3600 }, now: 100, want: true},
		{name: "1 h + 1 s old across the wrap", ts: func(n uint32) uint32 { return n - 3601 }, now: 100, want: false},
		{name: "5 min ahead across the wrap", ts: func(n uint32) uint32 { return n + 300 }, now: uint32(wrap - 100), want: true},
		{name: "5 min + 1 s ahead across the wrap", ts: func(n uint32) uint32 { return n + 301 }, now: uint32(wrap - 100), want: false},
		{name: "1 h old at the top of the range", ts: func(n uint32) uint32 { return n - 3600 }, now: 3599, want: true},
	}
	secret := key16(t, "000102030405060708090a0b0c0d0e0f")
	c := client8(t, "0102030405060708")
	ip := netip.MustParseAddr("192.0.2.1")
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ts := tc.ts(tc.now)
			cookie := serverCookie(secret, c, ts, ip)
			if got := verify(secret, c, cookie[:], ip, tc.now); got != tc.want {
				t.Errorf("verify(ts=%d, now=%d) = %v, want %v", ts, tc.now, got, tc.want)
			}
		})
	}
}

// TestRoundTrip: whatever serverCookie builds verifies for the same inputs,
// and for no other client address, client cookie or secret.
func TestRoundTrip(t *testing.T) {
	secret := key16(t, secretA)
	other := key16(t, "e5e973e5a6b2a43f48e7dc849e37bfce")
	c := client8(t, clientC)
	ip := netip.MustParseAddr(clientIP4)
	const ts = 1_600_000_000

	cookie := serverCookie(secret, c, ts, ip)
	if !verify(secret, c, cookie[:], ip, ts+10) {
		t.Fatal("own cookie does not verify")
	}
	if verify(other, c, cookie[:], ip, ts+10) {
		t.Error("verifies under a different secret")
	}
	if verify(secret, client8(t, "2464c4abcf10c958"), cookie[:], ip, ts+10) {
		t.Error("verifies for a different client cookie (RFC 7873 §6: behind a NAT the Client Cookie tells hosts apart)")
	}
	if verify(secret, c, cookie[:], netip.MustParseAddr("198.51.100.101"), ts+10) {
		t.Error("verifies for a different client address")
	}
}

// TestVerifyRejectsBadShape: only a 16-byte version-1 server cookie can
// verify. RFC 9018 §4.4: "the length of the received COOKIE option MUST be
// precisely 24 bytes: 8 bytes for the Client Cookie plus 16 bytes for the
// Server Cookie".
func TestVerifyRejectsBadShape(t *testing.T) {
	secret := key16(t, secretA)
	c := client8(t, clientC)
	ip := netip.MustParseAddr(clientIP4)
	good := serverCookie(secret, c, 1_600_000_000, ip)
	now := uint32(1_600_000_000)

	for n := 0; n <= 33; n++ {
		if n == 16 {
			continue
		}
		cookie := make([]byte, n)
		copy(cookie, good[:])
		if verify(secret, c, cookie, ip, now) {
			t.Errorf("a %d-byte server cookie verified", n)
		}
	}
	for v := range 256 {
		if v == 1 {
			continue
		}
		cookie := good
		cookie[0] = byte(v)
		if verify(secret, c, cookie[:], ip, now) {
			t.Errorf("version %d verified", v)
		}
	}
}

// TestSipHash24Paper checks the SipHash-2-4 reference vectors from the
// SipHash paper (Aumasson and Bernstein, appendix A): key 00 01 .. 0f, messages
// of 0, 1, 2 and so on up to 15 bytes, counting up from 00.
func TestSipHash24Paper(t *testing.T) {
	key := key16(t, "000102030405060708090a0b0c0d0e0f")
	tests := []struct {
		n    int
		want uint64
	}{
		{0, 0x726fdb47dd0e0e31},
		{1, 0x74f839c593dc67fd},
		{2, 0x0d6c8009d9a94f5a},
		{7, 0xab0200f58b01d137},
		{8, 0x93f5f5799a932462},
		{15, 0xa129ca6149be45e5},
	}
	msg := make([]byte, 64)
	for i := range msg {
		msg[i] = byte(i)
	}
	for _, tc := range tests {
		if got := siphash24(key, msg[:tc.n]); got != tc.want {
			t.Errorf("siphash24(%d bytes) = %#x, want %#x", tc.n, got, tc.want)
		}
	}
}

// leanInWindow is `inWindow` exactly as verification/lean/CorednsPlugins/
// Cookie.lean defines it, with RFC 1982 §3.2 spelled out (Serial.lean's
// serialGreater): the model the proofs are about.
func leanInWindow(now, ts uint32) bool {
	const m = uint64(1) << 32
	n, s := uint64(now), uint64(ts)
	serialGreater := func(a, b uint64) bool {
		return a != b && ((a < b && b-a > m/2) || (a > b && a-b < m/2))
	}
	return n == s ||
		(serialGreater(n, s) && (n+m-s)%m <= maxAgeSeconds) ||
		(serialGreater(s, n) && (s+m-n)%m <= maxFutureSeconds)
}

// TestInWindowMatchesLeanModel: the Go comparison, which works modulo 2^32 on
// the difference, agrees with the Lean definition, which uses RFC 1982
// serial-number comparison, on every boundary (the window edges, the 2^32
// wrap, the antipode 2^31) and on a stride through the whole space.
func TestInWindowMatchesLeanModel(t *testing.T) {
	bases := []uint32{0, 1, 299, 300, 301, 3599, 3600, 3601, 1 << 20, 1<<31 - 1, 1 << 31, 1<<31 + 1, 1<<32 - 301, 1<<32 - 300, 1<<32 - 1}
	deltas := make([]int64, 0, 24)
	for _, d := range []int64{0, 1, 299, 300, 301, 3599, 3600, 3601, 1 << 20, 1<<31 - 1, 1 << 31, 1<<31 + 1} {
		deltas = append(deltas, d, -d)
	}
	for _, now := range bases {
		for _, d := range deltas {
			ts := uint32(int64(now) - d) //nolint:gosec // G115: modulo 2^32 is the point of the test
			if got, want := inWindow(now, ts), leanInWindow(now, ts); got != want {
				t.Errorf("inWindow(%d, %d) = %v, Lean model says %v", now, ts, got, want)
			}
		}
	}
	for now := uint64(0); now < 1<<32; now += 0x01234567 {
		for ts := uint64(0); ts < 1<<32; ts += 0x0765432d {
			if got, want := inWindow(uint32(now), uint32(ts)), leanInWindow(uint32(now), uint32(ts)); got != want {
				t.Fatalf("inWindow(%d, %d) = %v, Lean model says %v", now, ts, got, want)
			}
		}
	}
}

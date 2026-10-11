package cookie

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
)

// FuzzVerify: for any server cookie bytes and any times, verify never panics,
// only ever accepts a 16-byte version-1 cookie, and a cookie it accepts is one
// serverCookie would have produced for the received Reserved bytes (the hash
// is over the received value, RFC 9018 §4.2).
func FuzzVerify(f *testing.F) {
	secret := key16(f, "e5e973e5a6b2a43f48e7dc849e37bfcf")
	client := client8(f, "2464c4abcf10c957")
	ip4 := netip.MustParseAddr("198.51.100.100")
	good := serverCookie(secret, client, 1559731985, ip4)
	f.Add(good[:], uint32(1559731985), false)
	f.Add(good[:], uint32(1559731985+3600), false)
	f.Add(good[:15], uint32(0), true)
	f.Add([]byte{}, uint32(1<<32-1), true)

	f.Fuzz(func(t *testing.T, server []byte, now uint32, v6 bool) {
		ip := ip4
		if v6 {
			ip = netip.MustParseAddr("2001:db8::1")
		}
		if !verify(secret, client, server, ip, now) {
			return
		}
		if len(server) != serverCookieLen || server[0] != versionSIPHash24 {
			t.Fatalf("accepted a %d-byte cookie with version %d", len(server), server[0])
		}
		// Rebuild with the received Reserved bytes: must be byte-identical.
		var res [3]byte
		copy(res[:], server[1:4])
		ts := binary.BigEndian.Uint32(server[4:8])
		h := siphash24(secret, hashInput(client, server[0], res, ts, addrBytes(ip)))
		var want [8]byte
		binary.LittleEndian.PutUint64(want[:], h)
		if !bytes.Equal(server[8:], want[:]) {
			t.Fatal("accepted a cookie whose hash does not match")
		}
		if !inWindow(now, ts) {
			t.Fatal("accepted a cookie outside the window")
		}
	})
}

// FuzzClassify: classify agrees with RFC 7873 §5.2.2 for every int.
func FuzzClassify(f *testing.F) {
	for _, n := range []int{-1, 0, 7, 8, 9, 15, 16, 40, 41, 1 << 20} {
		f.Add(n)
	}
	f.Fuzz(func(t *testing.T, n int) {
		want := classMalformed
		if n == 8 {
			want = classClientOnly
		} else if n >= 16 && n <= 40 {
			want = classWithServer
		}
		if got := classify(n); got != want {
			t.Fatalf("classify(%d) = %v, want %v", n, got, want)
		}
	})
}

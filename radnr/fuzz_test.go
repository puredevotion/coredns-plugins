package radnr

import "testing"

// FuzzParseNDP: ICMPv6 bytes read off the link by the router-solicitation
// listener. No panic; an accepted message always had ICMP Code 0.
func FuzzParseNDP(f *testing.F) {
	f.Add([]byte{133, 0, 0, 0, 0, 0, 0, 0})           // Router Solicitation.
	f.Add([]byte{133, 1, 0, 0, 0, 0, 0, 0})           // Non-zero Code.
	f.Add([]byte{134, 0, 0, 0, 64, 0, 0x07, 0x08, 0}) // Short Router Advertisement.
	f.Add([]byte{})
	f.Add([]byte{133})
	f.Fuzz(func(t *testing.T, b []byte) {
		m, ok := parseNDP(b)
		if !ok {
			if m != nil {
				t.Fatalf("rejected but returned %v", m)
			}
			return
		}
		if m == nil || len(b) < 2 || b[1] != 0 {
			t.Fatalf("accepted % x as %v", b, m)
		}
	})
}

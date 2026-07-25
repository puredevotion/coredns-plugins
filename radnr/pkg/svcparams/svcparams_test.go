package svcparams

import (
	"bytes"
	"testing"
)

// RFC 9460 §2.2 SvcParams wire: sequence of (key uint16, len uint16, value)
// ordered by ascending key. Keys: alpn=1, port=3, dohpath=7 (RFC 9461).

func TestEncode_ALPN(t *testing.T) {
	got, err := Encode(Params{ALPN: []string{"dot"}})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	// key=1, len=4, value = \x03dot (alpn-id list: 1-octet len + "dot")
	want := []byte{0x00, 0x01, 0x00, 0x04, 0x03, 'd', 'o', 't'}
	if !bytes.Equal(got, want) {
		t.Fatalf("alpn: got=%x want=%x", got, want)
	}
}

func TestEncode_Port(t *testing.T) {
	got, err := Encode(Params{Port: 853})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	// key=3, len=2, value = 853 = 0x0355
	want := []byte{0x00, 0x03, 0x00, 0x02, 0x03, 0x55}
	if !bytes.Equal(got, want) {
		t.Fatalf("port: got=%x want=%x", got, want)
	}
}

func TestEncode_DohPath(t *testing.T) {
	got, err := Encode(Params{DohPath: "/dns-query{?dns}"})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	// key=7, len=16, value = "/dns-query{?dns}"
	v := []byte("/dns-query{?dns}")
	want := append([]byte{0x00, 0x07, 0x00, byte(len(v))}, v...)
	if !bytes.Equal(got, want) {
		t.Fatalf("dohpath: got=%x want=%x", got, want)
	}
}

func TestEncode_KeysSortedAscending(t *testing.T) {
	// Provide out-of-order conceptually; output MUST be alpn(1), port(3), dohpath(7).
	got, err := Encode(Params{DohPath: "/d", Port: 443, ALPN: []string{"h2"}})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	// keys appear in order 1,3,7
	if !(got[0] == 0 && got[1] == 1) {
		t.Fatalf("first key not 1 (alpn): %x", got[:2])
	}
	// find sequence — assert 1 before 3 before 7 by scanning keys
	keys := scanKeys(t, got)
	for i := 1; i < len(keys); i++ {
		if keys[i] <= keys[i-1] {
			t.Fatalf("keys not strictly ascending: %v", keys)
		}
	}
}

func TestEncode_ALPNMulti(t *testing.T) {
	got, err := Encode(Params{ALPN: []string{"dot", "doq"}})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	// value = \x03dot\x03doq = 8 octets, len=8
	want := []byte{0x00, 0x01, 0x00, 0x08, 0x03, 'd', 'o', 't', 0x03, 'd', 'o', 'q'}
	if !bytes.Equal(got, want) {
		t.Fatalf("alpn multi: got=%x want=%x", got, want)
	}
}

func TestEncode_Empty(t *testing.T) {
	got, err := Encode(Params{})
	if err != nil {
		t.Fatalf("Encode empty: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("empty params should yield empty bytes, got %x", got)
	}
}

func TestEncode_Errors(t *testing.T) {
	cases := []struct {
		name string
		p    Params
	}{
		{"alpn id too long", Params{ALPN: []string{string(make([]byte, 256))}}},
		{"alpn empty id", Params{ALPN: []string{""}}},
		{"ipv4hint forbidden", Params{Forbidden: map[string]string{"ipv4hint": "1.2.3.4"}}},
		{"ipv6hint forbidden", Params{Forbidden: map[string]string{"ipv6hint": "::1"}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := Encode(c.p); err == nil {
				t.Fatalf("expected error for %s", c.name)
			}
		})
	}
}

// scanKeys walks the SvcParams wire and returns the key sequence.
func scanKeys(t *testing.T, b []byte) []uint16 {
	t.Helper()
	var keys []uint16
	for len(b) >= 4 {
		k := uint16(b[0])<<8 | uint16(b[1])
		l := int(b[2])<<8 | int(b[3])
		keys = append(keys, k)
		if 4+l > len(b) {
			t.Fatalf("svcparams truncated")
		}
		b = b[4+l:]
	}
	return keys
}

func TestEncode_ForbiddenUnsupportedKey(t *testing.T) {
	if _, err := Encode(Params{Forbidden: map[string]string{"mandatory": "x"}}); err == nil {
		t.Fatalf("expected error for unsupported forbidden key")
	}
}

func TestEncode_DohPathTooLong(t *testing.T) {
	long := make([]byte, 70000)
	for i := range long {
		long[i] = 'a'
	}
	if _, err := Encode(Params{DohPath: string(long)}); err == nil {
		t.Fatalf("expected error for oversized dohpath")
	}
}

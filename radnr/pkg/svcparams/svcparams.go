// Package svcparams encodes DNS SvcParams (RFC 9460 §2.2) for use in the
// RFC 9463 Encrypted DNS option. Keys are emitted in strictly ascending order
// as required by RFC 9460.
package svcparams

import (
	"encoding/binary"
	"fmt"
	"sort"
)

// SvcParamKey numbers (RFC 9460 §14.3.2 / RFC 9461).
const (
	keyALPN    uint16 = 1
	keyPort    uint16 = 3
	keyDohPath uint16 = 7
)

// Params is a high-level description of the SvcParams to encode.
type Params struct {
	ALPN    []string // e.g. {"dot","doq","h2","h3"}
	Port    uint16   // 0 = omit
	DohPath string   // e.g. "/dns-query{?dns}"; "" = omit
	// Forbidden carries keys that must be rejected (ipv4hint/ipv6hint are
	// forbidden in the RFC 9463 option — addresses go in the option itself).
	Forbidden map[string]string
}

// Encode returns the RFC 9460 §2.2 wire encoding of params (keys ascending).
func Encode(p Params) ([]byte, error) {
	for k := range p.Forbidden {
		if k == "ipv4hint" || k == "ipv6hint" {
			return nil, fmt.Errorf("svcparams: %q is forbidden in the RFC 9463 option", k)
		}
		return nil, fmt.Errorf("svcparams: unsupported forbidden key %q", k)
	}

	type kv struct {
		key uint16
		val []byte
	}
	var params []kv

	if len(p.ALPN) > 0 {
		val, err := encodeALPN(p.ALPN)
		if err != nil {
			return nil, err
		}
		params = append(params, kv{keyALPN, val})
	}
	if p.Port != 0 {
		v := make([]byte, 2)
		binary.BigEndian.PutUint16(v, p.Port)
		params = append(params, kv{keyPort, v})
	}
	if p.DohPath != "" {
		if len(p.DohPath) > 0xffff {
			return nil, fmt.Errorf("svcparams: dohpath too long")
		}
		params = append(params, kv{keyDohPath, []byte(p.DohPath)})
	}

	sort.Slice(params, func(i, j int) bool { return params[i].key < params[j].key })

	var out []byte
	for _, p := range params {
		valLen, err := checkedUint16(len(p.val), fmt.Sprintf("svcparam key %d value", p.key))
		if err != nil {
			return nil, err
		}
		hdr := make([]byte, 4)
		binary.BigEndian.PutUint16(hdr[0:2], p.key)
		binary.BigEndian.PutUint16(hdr[2:4], valLen)
		out = append(out, hdr...)
		out = append(out, p.val...)
	}
	return out, nil
}

// checkedUint16 converts n to uint16, erroring instead of silently
// truncating if it doesn't fit — every SvcParam value length prefix (RFC
// 9460 §2.2) is a 16-bit field.
func checkedUint16(n int, what string) (uint16, error) {
	if n < 0 || n > 0xffff {
		return 0, fmt.Errorf("svcparams: %s length %d exceeds uint16 range", what, n)
	}
	return uint16(n), nil
}

// checkedByte converts n to a byte, erroring instead of silently truncating
// if it exceeds 255 — RFC 9460 §7.1's ALPN ids are single-octet length
// prefixed.
func checkedByte(n int, what string) (byte, error) {
	if n < 0 || n > 0xff {
		return 0, fmt.Errorf("svcparams: %s too long (%d octets)", what, n)
	}
	return byte(n), nil
}

// encodeALPN encodes the alpn SvcParamValue: a sequence of length-prefixed
// protocol identifiers (RFC 9460 §7.1).
func encodeALPN(ids []string) ([]byte, error) {
	var out []byte
	for _, id := range ids {
		if len(id) == 0 {
			return nil, fmt.Errorf("svcparams: empty alpn id")
		}
		idLen, err := checkedByte(len(id), fmt.Sprintf("alpn id %q", id))
		if err != nil {
			return nil, err
		}
		out = append(out, idLen)
		out = append(out, id...)
	}
	return out, nil
}

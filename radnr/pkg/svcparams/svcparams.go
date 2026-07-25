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
		hdr := make([]byte, 4)
		binary.BigEndian.PutUint16(hdr[0:2], p.key)
		binary.BigEndian.PutUint16(hdr[2:4], uint16(len(p.val)))
		out = append(out, hdr...)
		out = append(out, p.val...)
	}
	return out, nil
}

// encodeALPN encodes the alpn SvcParamValue: a sequence of length-prefixed
// protocol identifiers (RFC 9460 §7.1).
func encodeALPN(ids []string) ([]byte, error) {
	var out []byte
	for _, id := range ids {
		if len(id) == 0 {
			return nil, fmt.Errorf("svcparams: empty alpn id")
		}
		if len(id) > 0xff {
			return nil, fmt.Errorf("svcparams: alpn id %q too long", id)
		}
		out = append(out, byte(len(id)))
		out = append(out, id...)
	}
	return out, nil
}

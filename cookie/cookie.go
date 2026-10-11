// Package cookie implements DNS Cookies (RFC 7873) with the interoperable
// SipHash-2-4 server cookie of RFC 9018 as a CoreDNS plugin. See
// docs/cookie-plugin.md for the design, what it can and cannot do, and the
// decisions behind it.
package cookie

import (
	"crypto/subtle"
	"encoding/binary"
	"net/netip"
)

// Sizes and limits from RFC 7873 §4 and RFC 9018 §4.
const (
	clientCookieLen = 8
	serverCookieLen = 16                   // Version 1: Version(1) + Reserved(3) + Timestamp(4) + Hash(8).
	minWithServer   = clientCookieLen + 8  // RFC 7873 §4: server cookie 8..32 bytes.
	maxWithServer   = clientCookieLen + 32 //
	verifyOptionLen = clientCookieLen + serverCookieLen

	versionSIPHash24 = 1

	// RFC 9018 §4.3: "The DNS server SHOULD allow cookies within a 1-hour
	// period in the past and a 5-minute period into the future". Fixed, not
	// configurable: every server of an anycast set must apply the same window.
	maxAgeSeconds    = 3600
	maxFutureSeconds = 300
)

// class is what the length of a COOKIE option says it is (RFC 7873 §5.2.2:
// "valid cookie lengths are 8 and 16 to 40 inclusive").
type class int

const (
	classMalformed class = iota
	classClientOnly
	classWithServer
)

func (c class) String() string {
	switch c {
	case classMalformed:
		return "malformed"
	case classClientOnly:
		return "client_only"
	case classWithServer:
		return "with_server"
	}
	return "malformed"
}

// classify maps an OPTION-LENGTH to its class.
func classify(optLen int) class {
	switch {
	case optLen == clientCookieLen:
		return classClientOnly
	case optLen >= minWithServer && optLen <= maxWithServer:
		return classWithServer
	default:
		return classMalformed
	}
}

// hashInput is the SipHash-2-4 message of RFC 9018 §4.4:
//
//	Client Cookie | Version | Reserved | Timestamp | Client-IP
//
// ip is 4 bytes (IPv4) or 16 (IPv6), so the result is exactly 20 or 32 bytes,
// which is what makes it an injective function of its parts.
func hashInput(client [clientCookieLen]byte, version byte, reserved [3]byte, ts uint32, ip []byte) []byte {
	in := make([]byte, 0, clientCookieLen+8+len(ip))
	in = append(in, client[:]...)
	in = append(in, version)
	in = append(in, reserved[:]...)
	in = binary.BigEndian.AppendUint32(in, ts)
	return append(in, ip...)
}

// addrBytes is the Client-IP as hashed: 4 bytes for IPv4 (an IPv4-mapped IPv6
// address included), 16 for IPv6.
func addrBytes(ip netip.Addr) []byte {
	return ip.Unmap().AsSlice()
}

// serverCookie builds a version 1 Server Cookie (RFC 9018 §4): version 1,
// Reserved zero ("On construction, it MUST be set to zero octets"), the
// timestamp big endian, then the 8-byte hash, which is SipHash's 64-bit result
// written little endian.
func serverCookie(secret [16]byte, client [clientCookieLen]byte, ts uint32, ip netip.Addr) [serverCookieLen]byte {
	var out [serverCookieLen]byte
	out[0] = versionSIPHash24
	binary.BigEndian.PutUint32(out[4:8], ts)
	h := siphash24(secret, hashInput(client, versionSIPHash24, [3]byte{}, ts, addrBytes(ip)))
	binary.LittleEndian.PutUint64(out[8:], h)
	return out
}

// inWindow reports whether a cookie stamped ts is acceptable at time now: at
// most maxAgeSeconds old or maxFutureSeconds ahead. RFC 9018 §4.3: "All
// comparisons involving these fields MUST use 'Serial number arithmetic', as
// defined in [RFC1982]". Both operands are 32-bit and the difference is taken
// modulo 2^32, so a window straddling the wrap in 2106 behaves.
func inWindow(now, ts uint32) bool {
	age := now - ts // Seconds the cookie is in the past, mod 2^32.
	return age <= maxAgeSeconds || age >= (1<<32-maxFutureSeconds)
}

// verify reports whether server is a valid version 1 Server Cookie under
// secret for this client cookie and address at time now.
//
// RFC 9018 §4.4: "the length of the received COOKIE option MUST be precisely
// 24 bytes", so anything but a 16-byte server cookie is not verified at all.
// §4.2: "the server MUST NOT enforce those fields [Reserved] to be zero, and
// the Hash should be computed with the received value".
func verify(secret [16]byte, client [clientCookieLen]byte, server []byte, ip netip.Addr, now uint32) bool {
	if len(server) != serverCookieLen || server[0] != versionSIPHash24 {
		return false
	}
	ts := binary.BigEndian.Uint32(server[4:8])
	if !inWindow(now, ts) {
		return false
	}
	var reserved [3]byte
	copy(reserved[:], server[1:4])
	h := siphash24(secret, hashInput(client, server[0], reserved, ts, addrBytes(ip)))
	var want [8]byte
	binary.LittleEndian.PutUint64(want[:], h)
	return subtle.ConstantTimeCompare(want[:], server[8:]) == 1
}

// secrets is the generating secret plus the verify-only ones (RFC 9018 §5).
type secrets struct {
	verifyOnly [][16]byte
	generate   [16]byte
}

// check reports how server fares: valid under the generating secret, valid
// under a verify-only one (RFC 7873 §7.1's "previous secret"), or neither.
func (s *secrets) check(client [clientCookieLen]byte, server []byte, ip netip.Addr, now uint32) status {
	if verify(s.generate, client, server, ip, now) {
		return statusValid
	}
	for _, k := range s.verifyOnly {
		if verify(k, client, server, ip, now) {
			return statusValidPrevious
		}
	}
	return statusInvalidServer
}

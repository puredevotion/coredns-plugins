package probe

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// ECHConfigList construction, for RFC 9848's `ech=` SVCB parameter.
//
// # What this is FOR, and what it is not
//
// This is a TRANSPORT CANARY, not a functional ECH deployment. The measurement is
// "does an uncommon RR type carrying a large opaque parameter survive the path
// between us and the visitor?" — resolvers and middleboxes are known to strip,
// truncate or refuse SVCB/HTTPS parameters they do not understand, and `ech=` is
// the parameter most likely to be interfered with deliberately, because stripping
// it is exactly how an operator forces SNI back into the clear.
//
// So what matters here is that the bytes are WELL-FORMED and DETERMINISTIC, not
// that anybody can complete an ECH handshake with them. Nothing holds the private
// half of the key below, on purpose: publishing a usable ECH config from a
// measurement zone would invite clients to attempt real ECH against names that
// serve no TLS at all.
//
// That is stated in the plugin README too, because "we publish an ECH config" reads
// as a capability claim and it is not one.
//
// # Wire format
//
// From draft-ietf-tls-esni / RFC 9849:
//
//	ECHConfigList  = 2-byte length, then one or more ECHConfig
//	ECHConfig      = 2-byte version, 2-byte length, contents
//	contents       = HpkeKeyConfig
//	                 1-byte maximum_name_length
//	                 1-byte public_name length, public_name
//	                 2-byte extensions length, extensions
//	HpkeKeyConfig  = 1-byte config_id
//	                 2-byte kem_id
//	                 2-byte public_key length, public_key
//	                 2-byte cipher_suites length, cipher_suites (4 bytes each)
//
// Hand-built because Go exposes no ECHConfig encoder — crypto/tls consumes these
// but does not construct them. Every length prefix below is therefore load-bearing
// and a wrong one produces bytes a resolver may happily forward while no client can
// parse them, which is the failure this file's tests exist to catch.
const (
	// echVersion is draft-ietf-tls-esni's final codepoint, the one shipping
	// browsers use.
	echVersion uint16 = 0xfe0d

	// echKEMX25519 is DHKEM(X25519, HKDF-SHA256) from RFC 9180's registry.
	echKEMX25519 uint16 = 0x0020

	// echKDFHKDFSHA256 and echAEADAES128GCM are the mandatory-to-implement pair,
	// so a client that supports ECH at all supports this suite.
	echKDFHKDFSHA256 uint16 = 0x0001
	echAEADAES128GCM uint16 = 0x0001

	// x25519PubKeyLen is fixed by the curve; a config carrying any other length is
	// malformed rather than merely unusual.
	x25519PubKeyLen = 32

	// echMaxNameLength is the padding hint. 0 means "no guidance", which is
	// honest here: this config is never used to encrypt anything, so inventing a
	// padding length would imply a deployment that does not exist.
	echMaxNameLength uint8 = 0
)

// ErrECHPublicKeyLen means the supplied key was not a 32-byte X25519 point.
var ErrECHPublicKeyLen = errors.New("probe: ECH public key must be 32 bytes")

// BuildECHConfigList encodes a single-config ECHConfigList.
//
// publicName is the SNI a client would send on the OUTER ClientHello. It must be a
// name the visitor can plausibly reach, so the zone apex is the sensible choice —
// an outer SNI naming something unroutable turns a privacy feature into a
// connection failure.
func BuildECHConfigList(configID byte, publicKey []byte, publicName string) ([]byte, error) {
	if len(publicKey) != x25519PubKeyLen {
		return nil, fmt.Errorf("%w, got %d", ErrECHPublicKeyLen, len(publicKey))
	}
	if len(publicName) > 255 {
		// The length prefix is one byte; a longer name cannot be encoded, and
		// silently truncating a name would produce a config that points somewhere
		// else entirely.
		return nil, fmt.Errorf("probe: ECH public_name %q exceeds 255 bytes", publicName)
	}

	// HpkeKeyConfig
	var key []byte
	key = append(key, configID)
	key = binary.BigEndian.AppendUint16(key, echKEMX25519)
	key = binary.BigEndian.AppendUint16(key, uint16(len(publicKey)))
	key = append(key, publicKey...)

	// One cipher suite: kdf_id + aead_id, 4 bytes.
	var suites []byte
	suites = binary.BigEndian.AppendUint16(suites, echKDFHKDFSHA256)
	suites = binary.BigEndian.AppendUint16(suites, echAEADAES128GCM)
	key = binary.BigEndian.AppendUint16(key, uint16(len(suites)))
	key = append(key, suites...)

	// ECHConfig contents
	contents := key
	contents = append(contents, echMaxNameLength)
	contents = append(contents, byte(len(publicName)))
	contents = append(contents, publicName...)
	contents = binary.BigEndian.AppendUint16(contents, 0) // no extensions

	// ECHConfig
	var cfg []byte
	cfg = binary.BigEndian.AppendUint16(cfg, echVersion)
	cfg = binary.BigEndian.AppendUint16(cfg, uint16(len(contents)))
	cfg = append(cfg, contents...)

	// ECHConfigList: the outer length prefix miekg/dns's SVCBECHConfig expects to
	// be present ("including the redundant length prefix", per its own comment).
	var list []byte
	list = binary.BigEndian.AppendUint16(list, uint16(len(cfg)))
	list = append(list, cfg...)
	return list, nil
}

// ParseECHConfigList does the minimum needed to verify our own encoding and to
// check that a config read back from the network is intact.
//
// Not a general ECH parser: it validates structure and returns the fields this
// zone compares, which is enough to distinguish "arrived intact" from "something
// on the path rewrote it" — the actual measurement.
func ParseECHConfigList(b []byte) (configID byte, publicKey []byte, publicName string, err error) {
	fail := func(what string) (byte, []byte, string, error) {
		return 0, nil, "", fmt.Errorf("probe: malformed ECHConfigList: %s", what)
	}

	if len(b) < 2 {
		return fail("shorter than its own length prefix")
	}
	outer := int(binary.BigEndian.Uint16(b[0:2]))
	b = b[2:]
	if outer != len(b) {
		// A mismatch here is the single most likely symptom of truncation on the
		// path, so it is reported distinctly rather than as generic corruption.
		return fail(fmt.Sprintf("list length %d but %d bytes follow", outer, len(b)))
	}
	if len(b) < 4 {
		return fail("no room for an ECHConfig header")
	}

	version := binary.BigEndian.Uint16(b[0:2])
	if version != echVersion {
		return fail(fmt.Sprintf("unexpected version %#04x", version))
	}
	clen := int(binary.BigEndian.Uint16(b[2:4]))
	b = b[4:]
	if clen > len(b) {
		return fail("config length exceeds available bytes")
	}
	c := b[:clen]

	// HpkeKeyConfig
	if len(c) < 1+2+2 {
		return fail("truncated HpkeKeyConfig")
	}
	configID = c[0]
	kem := binary.BigEndian.Uint16(c[1:3])
	if kem != echKEMX25519 {
		return fail(fmt.Sprintf("unexpected KEM %#04x", kem))
	}
	klen := int(binary.BigEndian.Uint16(c[3:5]))
	c = c[5:]
	if klen > len(c) {
		return fail("public key length exceeds available bytes")
	}
	publicKey = c[:klen]
	c = c[klen:]

	if len(c) < 2 {
		return fail("truncated cipher suite list")
	}
	slen := int(binary.BigEndian.Uint16(c[0:2]))
	c = c[2:]
	if slen > len(c) || slen%4 != 0 {
		return fail("cipher suite list length invalid")
	}
	c = c[slen:]

	if len(c) < 2 {
		return fail("truncated public_name")
	}
	// maximum_name_length, then the name.
	c = c[1:]
	nlen := int(c[0])
	c = c[1:]
	if nlen > len(c) {
		return fail("public_name length exceeds available bytes")
	}
	publicName = string(c[:nlen])

	return configID, publicKey, publicName, nil
}

package zoneversion

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/miekg/dns"
)

// RFC 9660 wire constants. The Lean model (verification/lean/CorednsPlugins/
// ZoneVersion.lean) uses the same numbers; a change here must move there too.
const (
	// OptionCode is the EDNS(0) OPTION-CODE (RFC 9660 §2.1, §6.1).
	optionCode = dns.EDNS0ZONEVERSION
	// TypeSOASerial is the only TYPE RFC 9660 defines (§4): "The value for
	// this type is "0"".
	typeSOASerial = 0
	// SerialLen is the VERSION length for SOA-SERIAL: a copy of the 32-bit
	// SOA SERIAL field (§4).
	serialLen = 4
	// HeaderLen is LABELCOUNT plus TYPE (§2.1, Figure 1).
	headerLen = 2
	// WireLen is the OPTION-LENGTH of an SOA-SERIAL response option, which
	// "MUST be set to "6" in responses" (§4).
	wireLen = headerLen + serialLen
	// MaxLabels bounds LABELCOUNT: a name of at most 255 octets has at most
	// 127 labels besides the root (RFC 1035 §3.1), and LABELCOUNT never
	// counts the root (RFC 9660 §2.1).
	maxLabels = 127
)

// Errors returned by Validate, NewVersion and Decode.
var (
	errRootZone    = errors.New("zoneversion: the root zone is not supported")
	errNotAncestor = errors.New("zoneversion: zone does not enclose the query name")
	errLabelCount  = errors.New("zoneversion: label count out of range")
	errLength      = errors.New("zoneversion: option data is not 6 octets")
	errType        = errors.New("zoneversion: version type is not SOA-SERIAL")
	errBadName     = errors.New("zoneversion: not a valid domain name")
)

// Version is one SOA-SERIAL ZONEVERSION: the zone's label count (counted
// without the root label, RFC 9660 §2.1) and its SOA serial (§4).
//
// The fields are unexported and every Version is made by NewVersion or Decode,
// both of which end in Validate, so a Version outside this package is always
// one the plugin may put on the wire: never the root zone (LABELCOUNT 0, see
// docs/zoneversion-plugin.md R4), never more labels than a name can have.
type Version struct {
	serial     uint32
	labelCount uint8
}

// Validate is the single check every constructor ends in.
func (v Version) Validate() error {
	if v.labelCount == 0 {
		return errRootZone
	}
	if v.labelCount > maxLabels {
		return fmt.Errorf("%w: %d", errLabelCount, v.labelCount)
	}
	return nil
}

// NewVersion returns the version to advertise for zone, at serial, in a
// response to a query for qname. RFC 9660 §2.1: LABELCOUNT is the number of
// labels of the zone name, which "MUST be less than or equal to the number of
// labels in the original QNAME": so zone must be qname or one of its
// ancestors. Names compare case-insensitively (RFC 4343).
func NewVersion(zone, qname string, serial uint32) (Version, error) {
	if _, ok := dns.IsDomainName(zone); !ok {
		return Version{}, errBadName
	}
	if _, ok := dns.IsDomainName(qname); !ok {
		return Version{}, errBadName
	}
	z, q := dns.Fqdn(zone), dns.Fqdn(qname)
	if z == "." {
		return Version{}, errRootZone
	}
	if !dns.IsSubDomain(z, q) {
		return Version{}, errNotAncestor
	}
	n := dns.CountLabel(z)
	if n <= 0 || n > maxLabels {
		return Version{}, fmt.Errorf("%w: %d", errLabelCount, n)
	}
	v := Version{labelCount: uint8(n), serial: serial} // 1 <= n <= 127, checked just above.
	return v, v.Validate()
}

// Serial is the advertised SOA serial.
func (v Version) Serial() uint32 { return v.serial }

// LabelCount is the advertised LABELCOUNT.
func (v Version) LabelCount() uint8 { return v.labelCount }

// Encode returns OPTION-DATA: LABELCOUNT, TYPE 0, then the serial as four
// octets in network byte order (RFC 9660 §2.1 Figure 1, §4). Always six
// octets. The §5 example, www.example.com in example.com at serial
// 2023073001, encodes as 02 00 78 95 a4 e9.
func (v Version) Encode() [wireLen]byte {
	var b [wireLen]byte
	b[0] = v.labelCount
	b[1] = typeSOASerial
	binary.BigEndian.PutUint32(b[headerLen:], v.serial)
	return b
}

// Decode parses SOA-SERIAL OPTION-DATA, the inverse of Encode: Decode(Encode
// v) = v for every valid v, and Encode(Decode b) = b for every b Decode
// accepts (both proved in ZoneVersion.lean, decode_encode and
// encode_decode). It refuses anything that is not exactly the six-octet
// SOA-SERIAL form, rather than guess at a type it does not know.
func Decode(b []byte) (Version, error) {
	if len(b) != wireLen {
		return Version{}, errLength
	}
	if b[1] != typeSOASerial {
		return Version{}, errType
	}
	v := Version{labelCount: b[0], serial: binary.BigEndian.Uint32(b[headerLen:])}
	if err := v.Validate(); err != nil {
		return Version{}, err
	}
	return v, nil
}

// EDNS0 returns the option as miekg/dns represents it. Version is a string of
// opaque octets, not text: the serial is NOT formatted in decimal here.
func (v Version) EDNS0() *dns.EDNS0_ZONEVERSION {
	var s [serialLen]byte
	binary.BigEndian.PutUint32(s[:], v.serial)
	return &dns.EDNS0_ZONEVERSION{
		Code:       optionCode,
		LabelCount: v.labelCount,
		Type:       typeSOASerial,
		Version:    string(s[:]),
	}
}

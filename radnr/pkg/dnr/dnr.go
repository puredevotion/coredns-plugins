// Package dnr encodes the RFC 9463 Encrypted DNS option (RA option type 144)
// for IPv6 Router Advertisements. The option advertises an encrypted DNS
// resolver: an Authentication Domain Name (ADN), zero or more IPv6 addresses,
// and SvcParams (alpn/port/dohpath).
//
// Wire layout (RFC 9463 §6.1):
//
//	Type(1)=144 | Length(1, units of 8) | ServicePriority(2) | Lifetime(4) |
//	ADNLength(2) | ADN(DNS wire labels) | AddrLength(2, mult of 16) |
//	IPv6 addrs(16 each) | SvcParamsLength(2) | SvcParams | zero-pad to mult of 8
//
//nolint:misspell // ADN throughout this file: RFC 9463 Authentication Domain Name, not a typo for AND
package dnr

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// OptionType is the RA option type for the Encrypted DNS option (RFC 9463).
const OptionType = 144

// Wire-format field sizes and limits (RFC 9463 §6.1, RFC 1035 §3.1).
const (
	headerSize       = 2    // Type(1) + Length(1) octets.
	octetUnit        = 8    // Length field units, and the padding modulus.
	maxLengthUnits   = 0xff // Max value of the 1-octet Length field.
	uint16Size       = 2
	uint32Size       = 4
	ipv6Size         = 16   // Octets in one IPv6 address.
	maxLabelLen      = 63   // Max length of a single DNS wire-format label.
	maxNameLen       = 255  // Max length of a DNS wire-format name.
	rootLabel        = 0x00 // The zero-length root label terminating a name.
	wireNameOverhead = 2    // Leading length octet of the first label plus the trailing root label.
)

// EncryptedDNS is a decoded RFC 9463 RA Encrypted DNS option. The zero value
// is not valid (the ADN is required); use Validate to check one built by hand.
// Marshal and Unmarshal both go through Validate, so exactly the options that
// Validate accepts can be encoded, and exactly those can be decoded.
type EncryptedDNS struct {
	ADN             DomainName // Authentication domain name, e.g. "dns.example.com".
	Addrs           []netip.Addr
	SvcParams       []byte // Pre-encoded RFC 9460 SvcParams (see pkg/svcparams).
	ServicePriority uint16
	Lifetime        uint32 // Seconds.
}

// DomainName is a validated DNS name in dotted presentation form, held without
// a trailing dot. It can only be built by ParseDomainName (or by decoding a
// wire option), so a DomainName that is not the zero value always encodes to a
// legal RFC 1035 wire name: no empty labels, labels of at most 63 octets, and
// at most 255 octets on the wire. The zero value is invalid.
type DomainName struct{ s string }

// ParseDomainName validates a dotted domain name. One trailing dot (the root)
// is accepted and normalised away. The name is not case-folded.
func ParseDomainName(name string) (DomainName, error) {
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return DomainName{}, errors.New("dnr: empty ADN")
	}
	// Presentation form plus one length octet per label and the root label:
	// len(name)+2 octets on the wire.
	if len(name)+wireNameOverhead > maxNameLen {
		return DomainName{}, fmt.Errorf("dnr: ADN %q exceeds %d octets", name, maxNameLen)
	}
	for label := range strings.SplitSeq(name, ".") {
		if label == "" {
			return DomainName{}, fmt.Errorf("dnr: empty label in ADN %q", name)
		}
		if len(label) > maxLabelLen {
			return DomainName{}, fmt.Errorf("dnr: label %q exceeds %d octets", label, maxLabelLen)
		}
	}
	return DomainName{s: name}, nil
}

// MustParseDomainName is like ParseDomainName but panics on error. It is meant
// for constants and tests.
func MustParseDomainName(name string) DomainName {
	d, err := ParseDomainName(name)
	if err != nil {
		panic(err)
	}
	return d
}

// String returns the dotted form without a trailing dot ("" for the zero value).
func (d DomainName) String() string { return d.s }

// IsZero reports whether d is the (invalid) zero value.
func (d DomainName) IsZero() bool { return d.s == "" }

// Validate reports an error for the zero value. Every other DomainName was
// checked when it was constructed.
func (d DomainName) Validate() error {
	if d.s == "" {
		return errors.New("dnr: empty ADN")
	}
	return nil
}

// wire encodes the name as length-prefixed labels, root-terminated. It must
// only be called on a valid DomainName.
func (d DomainName) wire() []byte {
	out := make([]byte, 0, len(d.s)+wireNameOverhead)
	for label := range strings.SplitSeq(d.s, ".") {
		out = append(out, byte(len(label))) //nolint:gosec // G115: ParseDomainName bounds every label to maxLabelLen (63).
		out = append(out, label...)
	}
	return append(out, rootLabel)
}

// checkedUint16 errors if n does not fit a uint16: every length prefix in the RFC 9463 wire format is a
// 16-bit field.
func checkedUint16(n int, what string) error {
	if n < 0 || n > 0xffff {
		return fmt.Errorf("dnr: %s length %d exceeds uint16 range", what, n)
	}
	return nil
}

// wireSize returns the padded on-the-wire size of o in octets. Callers must
// have checked the individual fields first.
func (o EncryptedDNS) wireSize() int {
	body := uint16Size + uint32Size + uint16Size + len(o.ADN.s) + wireNameOverhead + uint16Size + len(o.Addrs)*ipv6Size + uint16Size + len(o.SvcParams)
	total := headerSize + body
	return total + (octetUnit-total%octetUnit)%octetUnit
}

// Validate reports whether o can be encoded as an RA option: a valid ADN,
// native (non-IPv4-mapped, zone-less) IPv6 addresses, every length-prefixed
// field within its 16-bit prefix, and a total size that fits the 1-octet
// Length field. It is the single source of truth shared by Marshal and
// Unmarshal.
func (o EncryptedDNS) Validate() error {
	if err := o.ADN.Validate(); err != nil {
		return err
	}
	for _, a := range o.Addrs {
		// Is6 is false for the zero Addr and for plain IPv4; IPv4-mapped
		// addresses report Is6 but decode ambiguously, and a zone has no
		// wire form.
		if !a.Is6() || a.Is4In6() || a.Zone() != "" {
			return fmt.Errorf("dnr: address %s is not IPv6", a)
		}
	}
	if err := checkedUint16(len(o.Addrs)*ipv6Size, "address list"); err != nil {
		return err
	}
	if err := checkedUint16(len(o.SvcParams), "svcparams"); err != nil {
		return err
	}
	if total := o.wireSize(); total/octetUnit > maxLengthUnits {
		return fmt.Errorf("dnr: option too large (%d octets)", total)
	}
	return nil
}

// Marshal encodes the option to its RA wire form, zero-padded to a multiple of
// 8 octets. It returns the error from Validate if the option is invalid.
func (o EncryptedDNS) Marshal() ([]byte, error) {
	if err := o.Validate(); err != nil {
		return nil, err
	}
	adn := o.ADN.wire()
	// Validate bounded every length below to its prefix width.
	adnLen := uint16(len(adn))                 //nolint:gosec // G115: a valid name is at most 255 octets.
	addrLen := uint16(len(o.Addrs) * ipv6Size) //nolint:gosec // G115: bounded by Validate.
	svcParamsLen := uint16(len(o.SvcParams))   //nolint:gosec // G115: bounded by Validate.
	total := o.wireSize()

	out := make([]byte, 0, total)
	out = append(out, OptionType, byte(total/octetUnit)) //nolint:gosec // G115: <= maxLengthUnits, checked by Validate.
	out = binary.BigEndian.AppendUint16(out, o.ServicePriority)
	out = binary.BigEndian.AppendUint32(out, o.Lifetime)
	out = binary.BigEndian.AppendUint16(out, adnLen)
	out = append(out, adn...)
	out = binary.BigEndian.AppendUint16(out, addrLen)
	for _, a := range o.Addrs {
		b := a.As16()
		out = append(out, b[:]...)
	}
	out = binary.BigEndian.AppendUint16(out, svcParamsLen)
	out = append(out, o.SvcParams...)
	return out[:total], nil // The tail of the allocation is the zero padding.
}

// parseADNField decodes the ADN field starting at p, given its already-read
// length prefix, and returns the decoded name and the remaining bytes after
// the field.
func parseADNField(p []byte, adnLen uint16) (name DomainName, rest []byte, err error) {
	if int(adnLen) > len(p) {
		return DomainName{}, nil, fmt.Errorf("dnr: ADN length %d exceeds remaining %d", adnLen, len(p))
	}
	name, err = decodeADN(p[:adnLen])
	if err != nil {
		return DomainName{}, nil, err
	}
	return name, p[adnLen:], nil
}

// parseAddrs decodes the fixed-width IPv6 address list starting at p, given
// its already-read length prefix, and returns the addresses and the
// remaining bytes after the field.
func parseAddrs(p []byte, addrLen uint16) ([]netip.Addr, []byte, error) {
	if addrLen%ipv6Size != 0 {
		return nil, nil, fmt.Errorf("dnr: AddrLength %d not a multiple of %d", addrLen, ipv6Size)
	}
	if int(addrLen) > len(p) {
		return nil, nil, fmt.Errorf("dnr: AddrLength %d exceeds remaining %d", addrLen, len(p))
	}
	addrs := make([]netip.Addr, 0, int(addrLen)/ipv6Size)
	for i := 0; i < int(addrLen); i += ipv6Size {
		var a16 [ipv6Size]byte
		copy(a16[:], p[i:i+ipv6Size])
		addrs = append(addrs, netip.AddrFrom16(a16))
	}
	return addrs, p[addrLen:], nil
}

// parseSvcParams decodes the trailing SvcParams field starting at p, given
// its already-read length prefix.
func parseSvcParams(p []byte, spLen uint16) ([]byte, error) {
	if int(spLen) > len(p) {
		return nil, fmt.Errorf("dnr: SvcParamsLength %d exceeds remaining %d", spLen, len(p))
	}
	if spLen == 0 {
		return nil, nil
	}
	return append([]byte(nil), p[:spLen]...), nil
}

// parseHeader validates the (Type, Length) header of the wire form and
// returns the body bytes it delimits (after the 2-octet header itself).
func parseHeader(b []byte) ([]byte, error) {
	if len(b) < octetUnit {
		return nil, fmt.Errorf("dnr: too short (%d octets)", len(b))
	}
	if b[0] != OptionType {
		return nil, fmt.Errorf("dnr: wrong type %d", b[0])
	}
	total := int(b[1]) * octetUnit
	if total == 0 || total > len(b) {
		return nil, fmt.Errorf("dnr: length field %d octets exceeds buffer %d", total, len(b))
	}
	return b[headerSize:total], nil
}

// Unmarshal decodes an RA Encrypted DNS option from its wire form.
func Unmarshal(b []byte) (EncryptedDNS, error) {
	var o EncryptedDNS
	p, err := parseHeader(b)
	if err != nil {
		return o, err
	}

	read16 := func() (uint16, error) {
		if len(p) < uint16Size {
			return 0, fmt.Errorf("dnr: truncated")
		}
		v := binary.BigEndian.Uint16(p)
		p = p[uint16Size:]
		return v, nil
	}

	if o.ServicePriority, err = read16(); err != nil {
		return o, err
	}
	if len(p) < uint32Size {
		return o, fmt.Errorf("dnr: truncated lifetime")
	}
	o.Lifetime = binary.BigEndian.Uint32(p)
	p = p[uint32Size:]

	adnLen, err := read16()
	if err != nil {
		return o, err
	}
	o.ADN, p, err = parseADNField(p, adnLen)
	if err != nil {
		return o, err
	}

	addrLen, err := read16()
	if err != nil {
		return o, err
	}
	o.Addrs, p, err = parseAddrs(p, addrLen)
	if err != nil {
		return o, err
	}

	spLen, err := read16()
	if err != nil {
		return o, err
	}
	o.SvcParams, err = parseSvcParams(p, spLen)
	if err != nil {
		return o, err
	}
	// Semantic checks live in one place, shared with Marshal.
	if err := o.Validate(); err != nil {
		return EncryptedDNS{}, err
	}
	return o, nil
}

// decodeADN parses DNS wire-format labels into a DomainName. Only wire-level
// framing is checked here; name rules are DomainName's.
func decodeADN(b []byte) (DomainName, error) {
	var labels []string
	for len(b) > 0 {
		n := int(b[0])
		b = b[1:]
		if n == 0 {
			return ParseDomainName(strings.Join(labels, "."))
		}
		if n > len(b) {
			return DomainName{}, fmt.Errorf("dnr: ADN label length %d exceeds remaining", n)
		}
		label := string(b[:n])
		// A '.' inside a wire label cannot be expressed in the dotted form
		// DomainName holds, and would re-encode as a different name.
		if strings.Contains(label, ".") {
			return DomainName{}, fmt.Errorf("dnr: ADN label %q contains '.'", label)
		}
		labels = append(labels, label)
		b = b[n:]
	}
	return DomainName{}, errors.New("dnr: ADN not root-terminated")
}

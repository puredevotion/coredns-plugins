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
	"fmt"
	"net/netip"
	"strings"
)

// OptionType is the RA option type for the Encrypted DNS option (RFC 9463).
const OptionType = 144

// Wire-format field sizes and limits (RFC 9463 §6.1, RFC 1035 §3.1).
const (
	headerSize     = 2    // Type(1) + Length(1) octets.
	octetUnit      = 8    // Length field units, and the padding modulus.
	maxLengthUnits = 0xff // Max value of the 1-octet Length field.
	uint16Size     = 2
	uint32Size     = 4
	ipv6Size       = 16   // Octets in one IPv6 address.
	maxLabelLen    = 63   // Max length of a single DNS wire-format label.
	maxNameLen     = 255  // Max length of a DNS wire-format name.
	rootLabel      = 0x00 // The zero-length root label terminating a name.
)

// EncryptedDNS is a decoded RFC 9463 RA Encrypted DNS option.
type EncryptedDNS struct {
	ADN             string // Authentication domain name, e.g. "dns.example.com".
	Addrs           []netip.Addr
	SvcParams       []byte // Pre-encoded RFC 9460 SvcParams (see pkg/svcparams).
	ServicePriority uint16
	Lifetime        uint32 // Seconds.
}

// checkedUint16 converts n to uint16, erroring instead of silently truncating
// if it doesn't fit — every length prefix in the RFC 9463 wire format is a
// 16-bit field.
func checkedUint16(n int, what string) (uint16, error) {
	if n < 0 || n > 0xffff {
		return 0, fmt.Errorf("dnr: %s length %d exceeds uint16 range", what, n)
	}
	return uint16(n), nil
}

// checkedByteMax converts n to a byte, erroring instead of silently
// truncating if it exceeds max (which itself must fit in a byte).
func checkedByteMax(n, maxVal int, what string) (byte, error) {
	if n < 0 || n > maxVal {
		return 0, fmt.Errorf("dnr: %s exceeds %d octets", what, maxVal)
	}
	return byte(n), nil //nolint:gosec // G115: bounds-checked immediately above; this is the checked conversion itself, not a suppressed truncation.
}

// Marshal encodes the option to its RA wire form, zero-padded to a multiple of
// 8 octets. It returns an error if the option is invalid (empty/oversized ADN,
// non-IPv6 address, or oversized fields).
func (o EncryptedDNS) Marshal() ([]byte, error) {
	adn, err := encodeADN(o.ADN)
	if err != nil {
		return nil, err
	}
	adnLen, err := checkedUint16(len(adn), "ADN")
	if err != nil {
		return nil, err
	}

	addrBytes := make([]byte, 0, len(o.Addrs)*ipv6Size)
	for _, a := range o.Addrs {
		if !a.Is6() || a.Is4In6() {
			return nil, fmt.Errorf("dnr: address %s is not IPv6", a)
		}
		b := a.As16()
		addrBytes = append(addrBytes, b[:]...)
	}
	addrLen, err := checkedUint16(len(addrBytes), "address list")
	if err != nil {
		return nil, err
	}
	svcParamsLen, err := checkedUint16(len(o.SvcParams), "svcparams")
	if err != nil {
		return nil, err
	}

	// One allocation, sized up front: the header, the three length-prefixed
	// fields, and the zero padding that rounds the option to 8-octet units.
	// The old version appended field by field into a growing slice and then
	// copied the result behind the header.
	body := uint16Size + uint32Size + uint16Size + len(adn) + uint16Size + len(addrBytes) + uint16Size + len(o.SvcParams)
	total := headerSize + body
	total += (octetUnit - total%octetUnit) % octetUnit
	if total/octetUnit > maxLengthUnits {
		return nil, fmt.Errorf("dnr: option too large (%d octets)", total)
	}

	out := make([]byte, 0, total)
	out = append(out, OptionType, byte(total/octetUnit))
	out = binary.BigEndian.AppendUint16(out, o.ServicePriority)
	out = binary.BigEndian.AppendUint32(out, o.Lifetime)
	out = binary.BigEndian.AppendUint16(out, adnLen)
	out = append(out, adn...)
	out = binary.BigEndian.AppendUint16(out, addrLen)
	out = append(out, addrBytes...)
	out = binary.BigEndian.AppendUint16(out, svcParamsLen)
	out = append(out, o.SvcParams...)
	return out[:total], nil // The tail of the allocation is the zero padding.
}

// parseADNField decodes the ADN field starting at p, given its already-read
// length prefix, and returns the decoded name and the remaining bytes after
// the field.
func parseADNField(p []byte, adnLen uint16) (name string, rest []byte, err error) {
	if int(adnLen) > len(p) {
		return "", nil, fmt.Errorf("dnr: ADN length %d exceeds remaining %d", adnLen, len(p))
	}
	name, err = decodeADN(p[:adnLen])
	if err != nil {
		return "", nil, err
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
	return o, nil
}

// encodeADN encodes a domain name into DNS wire format (length-prefixed labels,
// root-terminated). RFC 8415 §10.
func encodeADN(name string) ([]byte, error) {
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return nil, fmt.Errorf("dnr: empty ADN")
	}
	// Wire form is the presentation form plus one length octet per label and
	// the root label: len(name)+2 exactly, so size it once.
	out := make([]byte, 0, len(name)+2) //nolint:mnd // The leading length octet of the first label and the trailing root label.
	for label := range strings.SplitSeq(name, ".") {
		if label == "" {
			return nil, fmt.Errorf("dnr: empty label in ADN %q", name)
		}
		labelLen, err := checkedByteMax(len(label), maxLabelLen, fmt.Sprintf("label %q", label))
		if err != nil {
			return nil, err
		}
		out = append(out, labelLen)
		out = append(out, label...)
	}
	out = append(out, rootLabel)
	if len(out) > maxNameLen {
		return nil, fmt.Errorf("dnr: ADN %q exceeds 255 octets", name)
	}
	return out, nil
}

// decodeADN parses DNS wire-format labels back to a dotted name.
func decodeADN(b []byte) (string, error) {
	var labels []string
	for len(b) > 0 {
		n := int(b[0])
		b = b[1:]
		if n == 0 {
			return strings.Join(labels, "."), nil
		}
		if n > len(b) {
			return "", fmt.Errorf("dnr: ADN label length %d exceeds remaining", n)
		}
		labels = append(labels, string(b[:n]))
		b = b[n:]
	}
	return "", fmt.Errorf("dnr: ADN not root-terminated")
}

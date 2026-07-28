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
package dnr

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"
)

// OptionType is the RA option type for the Encrypted DNS option (RFC 9463).
const OptionType = 144

// EncryptedDNS is a decoded RFC 9463 RA Encrypted DNS option.
type EncryptedDNS struct {
	ServicePriority uint16
	Lifetime        uint32 // seconds
	ADN             string // authentication domain name, e.g. "dns.example.com"
	Addrs           []netip.Addr
	SvcParams       []byte // pre-encoded RFC 9460 SvcParams (see pkg/svcparams)
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
func checkedByteMax(n, max int, what string) (byte, error) {
	if n < 0 || n > max {
		return 0, fmt.Errorf("dnr: %s exceeds %d octets", what, max)
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

	var addrBytes []byte
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

	// Body after the 2-octet (Type,Length) header.
	var body []byte
	body = binary.BigEndian.AppendUint16(body, o.ServicePriority)
	body = binary.BigEndian.AppendUint32(body, o.Lifetime)
	body = binary.BigEndian.AppendUint16(body, adnLen)
	body = append(body, adn...)
	body = binary.BigEndian.AppendUint16(body, addrLen)
	body = append(body, addrBytes...)
	body = binary.BigEndian.AppendUint16(body, svcParamsLen)
	body = append(body, o.SvcParams...)

	total := 2 + len(body)
	if pad := (8 - total%8) % 8; pad != 0 {
		body = append(body, make([]byte, pad)...)
		total += pad
	}
	if total/8 > 0xff {
		return nil, fmt.Errorf("dnr: option too large (%d octets)", total)
	}

	out := make([]byte, 0, total)
	out = append(out, OptionType, byte(total/8))
	out = append(out, body...)
	return out, nil
}

// Unmarshal decodes an RA Encrypted DNS option from its wire form.
func Unmarshal(b []byte) (EncryptedDNS, error) {
	var o EncryptedDNS
	if len(b) < 8 {
		return o, fmt.Errorf("dnr: too short (%d octets)", len(b))
	}
	if b[0] != OptionType {
		return o, fmt.Errorf("dnr: wrong type %d", b[0])
	}
	total := int(b[1]) * 8
	if total == 0 || total > len(b) {
		return o, fmt.Errorf("dnr: length field %d octets exceeds buffer %d", total, len(b))
	}
	p := b[2:total]

	read16 := func() (uint16, error) {
		if len(p) < 2 {
			return 0, fmt.Errorf("dnr: truncated")
		}
		v := binary.BigEndian.Uint16(p)
		p = p[2:]
		return v, nil
	}

	var err error
	if o.ServicePriority, err = read16(); err != nil {
		return o, err
	}
	if len(p) < 4 {
		return o, fmt.Errorf("dnr: truncated lifetime")
	}
	o.Lifetime = binary.BigEndian.Uint32(p)
	p = p[4:]

	adnLen, err := read16()
	if err != nil {
		return o, err
	}
	if int(adnLen) > len(p) {
		return o, fmt.Errorf("dnr: ADN length %d exceeds remaining %d", adnLen, len(p))
	}
	o.ADN, err = decodeADN(p[:adnLen])
	if err != nil {
		return o, err
	}
	p = p[adnLen:]

	addrLen, err := read16()
	if err != nil {
		return o, err
	}
	if addrLen%16 != 0 {
		return o, fmt.Errorf("dnr: AddrLength %d not a multiple of 16", addrLen)
	}
	if int(addrLen) > len(p) {
		return o, fmt.Errorf("dnr: AddrLength %d exceeds remaining %d", addrLen, len(p))
	}
	for i := 0; i < int(addrLen); i += 16 {
		var a16 [16]byte
		copy(a16[:], p[i:i+16])
		o.Addrs = append(o.Addrs, netip.AddrFrom16(a16))
	}
	p = p[addrLen:]

	spLen, err := read16()
	if err != nil {
		return o, err
	}
	if int(spLen) > len(p) {
		return o, fmt.Errorf("dnr: SvcParamsLength %d exceeds remaining %d", spLen, len(p))
	}
	if spLen > 0 {
		o.SvcParams = append([]byte(nil), p[:spLen]...)
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
	var out []byte
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 {
			return nil, fmt.Errorf("dnr: empty label in ADN %q", name)
		}
		labelLen, err := checkedByteMax(len(label), 63, fmt.Sprintf("label %q", label))
		if err != nil {
			return nil, err
		}
		out = append(out, labelLen)
		out = append(out, label...)
	}
	out = append(out, 0x00) // root
	if len(out) > 255 {
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

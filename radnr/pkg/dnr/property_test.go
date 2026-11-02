//nolint:misspell // ADN/adn throughout this file: RFC 9463 Authentication Domain Name, not a typo for AND
package dnr

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

// propIterations keeps each property loop well under a second.
const propIterations = 3000

// propSeed fixes the generator so failures reproduce.
const propSeed = 9463

// randByte returns a uniformly random octet.
func randByte(r *rand.Rand) byte {
	return byte(r.Uint32() & 0xff)
}

// fill overwrites b with random octets.
func fill(r *rand.Rand, b []byte) {
	for i := range b {
		b[i] = randByte(r)
	}
}

// randLabel returns a label of 1..max octets, mostly lowercase letters, with
// the occasional '.', '\x00' or high byte to probe the validators.
func randLabel(r *rand.Rand, maxLen int) string {
	n := 1 + r.Intn(maxLen)
	b := make([]byte, n)
	for i := range b {
		switch r.Intn(20) {
		case 0:
			b[i] = '.'
		case 1:
			b[i] = randByte(r)
		default:
			b[i] = 'a' + randByte(r)%26
		}
	}
	return string(b)
}

// randName builds a dotted name from 0..6 labels, sometimes with a trailing
// dot, sometimes with an empty label or an oversized label.
func randName(r *rand.Rand) string {
	parts := make([]string, 0, 6)
	for range r.Intn(7) {
		maxLen := 12
		if r.Intn(30) == 0 {
			maxLen = 80
		}
		parts = append(parts, randLabel(r, maxLen))
	}
	name := strings.Join(parts, ".")
	if r.Intn(4) == 0 {
		name += "."
	}
	if r.Intn(30) == 0 {
		name += ".."
	}
	return name
}

func randAddr(r *rand.Rand) netip.Addr {
	var b [ipv6Size]byte
	fill(r, b[:])
	switch r.Intn(12) {
	case 0: // IPv4-mapped.
		copy(b[:10], make([]byte, 10))
		b[10], b[11] = 0xff, 0xff
	case 1: // Zero Addr.
		return netip.Addr{}
	case 2: // IPv4.
		return netip.AddrFrom4([4]byte(b[:4]))
	case 3: // Zoned.
		return netip.AddrFrom16(b).WithZone("eth0")
	}
	return netip.AddrFrom16(b)
}

func randOption(r *rand.Rand) EncryptedDNS {
	o := EncryptedDNS{ServicePriority: uint16(r.Uint32() & 0xffff), Lifetime: r.Uint32()}
	if r.Intn(10) != 0 { // Otherwise leave the zero (invalid) ADN.
		if d, err := ParseDomainName(randName(r)); err == nil {
			o.ADN = d
		}
	}
	for range r.Intn(4) {
		o.Addrs = append(o.Addrs, randAddr(r))
	}
	if n := r.Intn(40); n > 0 {
		o.SvcParams = make([]byte, n)
		fill(r, o.SvcParams)
	}
	if r.Intn(50) == 0 { // Large enough to overflow the 1-octet Length field.
		o.SvcParams = make([]byte, 1800+r.Intn(400))
	}
	return o
}

func sameOption(a, b EncryptedDNS) bool {
	return a.ADN == b.ADN && a.ServicePriority == b.ServicePriority && a.Lifetime == b.Lifetime &&
		bytes.Equal(a.SvcParams, b.SvcParams) && slices.Equal(a.Addrs, b.Addrs)
}

// Validate, Marshal and Unmarshal(Marshal(x)) agree on what is acceptable, and
// whatever is accepted round-trips exactly.
func TestProperty_ValidateMarshalUnmarshalAgree(t *testing.T) {
	r := rand.New(rand.NewSource(propSeed)) //nolint:gosec // G404: deterministic test generator.
	var valid, invalid int
	for range propIterations {
		o := randOption(r)
		verr := o.Validate()
		enc, merr := o.Marshal()
		if (verr == nil) != (merr == nil) {
			t.Fatalf("Validate=%v but Marshal=%v for %+v", verr, merr, o)
		}
		if merr != nil {
			invalid++
			continue
		}
		valid++
		got, uerr := Unmarshal(enc)
		if uerr != nil {
			t.Fatalf("Unmarshal(Marshal(x)) failed: %v for %+v", uerr, o)
		}
		if !sameOption(o, got) {
			t.Fatalf("round trip changed option:\n%+v\n%+v", o, got)
		}
		// Re-encoding the decoded option is byte-identical.
		again, err := got.Marshal()
		if err != nil || !bytes.Equal(again, enc) {
			t.Fatalf("Marshal(Unmarshal(b)) != b: %v\n% x\n% x", err, again, enc)
		}
	}
	if valid < propIterations/10 || invalid < propIterations/10 {
		t.Fatalf("generator is unbalanced: %d valid, %d invalid", valid, invalid)
	}
}

// Anything Unmarshal accepts, Validate accepts and Marshal can encode:
// accepted-by-Unmarshal implies accepted-by-Marshal, on arbitrary bytes.
func TestProperty_UnmarshalImpliesMarshal(t *testing.T) {
	r := rand.New(rand.NewSource(propSeed + 1)) //nolint:gosec // G404: deterministic test generator.
	base, err := EncryptedDNS{
		ADN: MustParseDomainName(testADN), Addrs: []netip.Addr{netip.MustParseAddr("2001:db8::1")},
		SvcParams: []byte{0, 1, 0, 3, 2, 'h', '2'}, ServicePriority: 1, Lifetime: 60,
	}.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	var accepted int
	for range propIterations * 4 {
		b := slices.Clone(base)
		for range 1 + r.Intn(4) { // Mutate a few bytes of a valid option.
			b[r.Intn(len(b))] = randByte(r)
		}
		if r.Intn(8) == 0 {
			b = b[:r.Intn(len(b)+1)]
		}
		o, err := Unmarshal(b)
		if err != nil {
			continue
		}
		accepted++
		if err := o.Validate(); err != nil {
			t.Fatalf("Unmarshal accepted % x but Validate rejects: %v", b, err)
		}
		if _, err := o.Marshal(); err != nil {
			t.Fatalf("Unmarshal accepted % x but Marshal rejects: %v", b, err)
		}
	}
	if accepted == 0 {
		t.Fatal("mutation never produced a decodable option")
	}
}

// ParseDomainName is idempotent and normalises exactly one trailing dot.
func TestProperty_ParseDomainNameNormalisation(t *testing.T) {
	r := rand.New(rand.NewSource(propSeed + 2)) //nolint:gosec // G404: deterministic test generator.
	for range propIterations {
		name := randName(r)
		d, err := ParseDomainName(name)
		if err != nil {
			continue
		}
		again, err := ParseDomainName(d.String())
		if err != nil || again != d {
			t.Fatalf("ParseDomainName not idempotent on %q: %v %q", name, err, again)
		}
		dotted, err := ParseDomainName(d.String() + ".")
		if err != nil || dotted != d {
			t.Fatalf("trailing dot changes %q: %v %q", name, err, dotted)
		}
		if strings.HasSuffix(d.String(), ".") || d.IsZero() {
			t.Fatalf("not normalised: %q", d)
		}
	}
	if (DomainName{}).Validate() == nil {
		t.Fatal("zero DomainName must be invalid")
	}
}

// Marshal output is always a whole number of 8-octet units, the header says so,
// size is monotonic in the variable-length fields, and the padding is zero.
func TestProperty_MarshalSize(t *testing.T) {
	r := rand.New(rand.NewSource(propSeed + 3)) //nolint:gosec // G404: deterministic test generator.
	for range propIterations {
		o := randOption(r)
		enc, err := o.Marshal()
		if err != nil {
			continue
		}
		if enc[0] != OptionType || len(enc)%octetUnit != 0 || int(enc[1])*octetUnit != len(enc) {
			t.Fatalf("bad header/length: type=%d len=%d size=%d", enc[0], enc[1], len(enc))
		}
		if len(enc) != o.wireSize() {
			t.Fatalf("wireSize %d != len %d", o.wireSize(), len(enc))
		}
		// Unpadded end of the SvcParams field; everything after is zero pad.
		adnLen := int(binary.BigEndian.Uint16(enc[8:]))
		end := 10 + adnLen + 2 + len(o.Addrs)*ipv6Size + 2 + len(o.SvcParams)
		if end > len(enc) || len(enc)-end >= octetUnit || slices.ContainsFunc(enc[end:], func(c byte) bool { return c != 0 }) {
			t.Fatalf("padding wrong: end=%d len=%d", end, len(enc))
		}
		// Growing SvcParams never shrinks the option.
		bigger := o
		bigger.SvcParams = append(slices.Clone(o.SvcParams), 0xaa)
		if enc2, err := bigger.Marshal(); err == nil && len(enc2) < len(enc) {
			t.Fatalf("size not monotonic: %d -> %d", len(enc), len(enc2))
		}
	}
}

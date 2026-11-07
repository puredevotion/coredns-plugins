package resinfo

import (
	"cmp"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
)

// Registered keys of the IANA "DNS Resolver Information Keys" registry
// (RFC 9606 §8.2), as of 2026-11-07.
const (
	// KeyQNameMin is RFC 9606 §5 "qnamemin": QNAME minimisation (RFC 9156)
	// is enabled. A boolean attribute: present, with no '=' and no value.
	KeyQNameMin = "qnamemin"
	// KeyExtErr is RFC 9606 §5 "exterr": the RFC 8914 INFO-CODEs this
	// resolver can return, as single values and "-" ranges, comma-separated.
	KeyExtErr = "exterr"
	// KeyInfoURL is RFC 9606 §5 "infourl": an https URL to unstructured
	// resolver information for IT staff.
	KeyInfoURL = "infourl"
	// KeyDeleg is "deleg", registered 2026-08-24 for draft-ietf-deleg-11
	// (a temporary registration, expiring 2027-08-24): the DELEG protocol is
	// supported. A boolean attribute.
	KeyDeleg = "deleg"

	// TempPrefix starts a key "defined for local use only" (RFC 9606 §4).
	TempPrefix = "temp-"

	// MaxString is the longest character-string: "a single length byte,
	// followed by 0-255 bytes of text data" (RFC 6763 §6.1, RFC 1035 §3.3).
	MaxString = 255
	// MaxRDATA is the largest RDLENGTH (RFC 1035 §3.2.1, 16 bits).
	MaxRDATA = 65535
)

// kind is how a key's value is shaped.
type kind uint8

const (
	kindFlag   kind = iota + 1 // Present without '=' (RFC 6763 §6.4 boolean).
	kindExtErr                 // Canonical EDE list, required.
	kindURL                    // Canonical https URL, required.
	kindTemp                   // Local-use key; value optional, printable ASCII.
)

// registered is the IANA registry, by key. A key outside it MUST begin with
// "temp-" (RFC 9606 §4).
var registered = map[string]kind{
	KeyQNameMin: kindFlag,
	KeyExtErr:   kindExtErr,
	KeyInfoURL:  kindURL,
	KeyDeleg:    kindFlag,
}

var (
	errEmpty      = errors.New("resinfo: a RESINFO record needs at least one key (RFC 1035 §3.3.14: no empty TXT-format RDATA)")
	errOrder      = errors.New("resinfo: keys are not in strictly increasing order")
	errValueShape = errors.New("resinfo: value not allowed for this key")
)

// Pair is one key[=value] character-string (RFC 6763 §6.3). HasValue
// distinguishes "key" (a boolean, no '=') from "key=" (an empty value).
type Pair struct {
	Key      string
	Value    string
	HasValue bool
}

// String renders the pair as its character-string: the key, then '=' and the
// value only when HasValue. Everything up to the first '=' is the key, so a
// valid key (which has no '=') splits back off exactly.
func (p Pair) String() string {
	if !p.HasValue {
		return p.Key
	}
	return p.Key + "=" + p.Value
}

// wireLen is the length of the rendered character-string.
func (p Pair) wireLen() int {
	if !p.HasValue {
		return len(p.Key)
	}
	return len(p.Key) + 1 + len(p.Value)
}

// splitPair is the inverse of Pair.String: key before the first '=', value
// after it, and HasValue iff there was a '=' (RFC 6763 §6.3, §6.4).
func splitPair(s string) Pair {
	k, v, ok := strings.Cut(s, "=")
	return Pair{Key: k, Value: v, HasValue: ok}
}

// Info is the RDATA of one RESINFO record in canonical form: at least one
// pair, keys strictly increasing in byte order (so no key repeats), every
// pair valid for its key, every character-string at most 255 octets, and the
// whole RDATA at most 65535 octets. The zero Info is the only invalid value
// and is never returned by New or Decode with a nil error.
type Info struct {
	pairs []Pair
}

// New sorts pairs into canonical order and validates them. The result
// depends only on the set of pairs given, never on their order, so every
// server configured with the same keys emits byte-identical RDATA
// (RFC 9606 §3: a group of resolvers "SHOULD expose a consistent RESINFO").
func New(pairs ...Pair) (Info, error) {
	ps := slices.Clone(pairs)
	slices.SortFunc(ps, func(a, b Pair) int { return cmp.Compare(a.Key, b.Key) })
	for i := 1; i < len(ps); i++ {
		if ps[i].Key == ps[i-1].Key {
			return Info{}, fmt.Errorf("resinfo: key %q given twice (RFC 6763 §6.4)", ps[i].Key)
		}
	}
	if err := validate(ps); err != nil {
		return Info{}, err
	}
	return Info{pairs: ps}, nil
}

// Decode is the exact inverse of Strings: it accepts only canonical RDATA,
// the strings some valid Info would emit, and rejects everything else. It is
// a check for what this plugin publishes, not the lenient client-side parser
// RFC 6763 §6.4 describes (which ignores unknown keys and repeats).
func Decode(txt []string) (Info, error) {
	ps := make([]Pair, len(txt))
	for i, s := range txt {
		ps[i] = splitPair(s)
	}
	if err := validate(ps); err != nil {
		return Info{}, err
	}
	return Info{pairs: ps}, nil
}

// Strings returns the character-strings of the RDATA, in canonical order. The
// slice is fresh; the caller may keep or change it.
func (i Info) Strings() []string {
	out := make([]string, len(i.pairs))
	for j, p := range i.pairs {
		out[j] = p.String()
	}
	return out
}

// Pairs returns a copy of the pairs, in canonical order.
func (i Info) Pairs() []Pair { return slices.Clone(i.pairs) }

// IsZero reports whether i is the zero (invalid) Info.
func (i Info) IsZero() bool { return len(i.pairs) == 0 }

// WireLen is the RDLENGTH of the record: one length octet per string plus
// its text.
func (i Info) WireLen() int {
	n := 0
	for _, p := range i.pairs {
		n += 1 + p.wireLen()
	}
	return n
}

// validate is the single definition of a valid Info, shared by New and
// Decode.
func validate(ps []Pair) error {
	if len(ps) == 0 {
		return errEmpty
	}
	total := 0
	for j, p := range ps {
		if j > 0 && ps[j-1].Key >= p.Key {
			return errOrder
		}
		if err := validatePair(p); err != nil {
			return err
		}
		total += 1 + p.wireLen()
	}
	if total > MaxRDATA {
		return fmt.Errorf("resinfo: RDATA of %d octets exceeds %d", total, MaxRDATA)
	}
	return nil
}

// validatePair checks one pair: key syntax, the key's value shape, and the
// 255-octet character-string limit.
func validatePair(p Pair) error {
	k, err := keyKind(p.Key)
	if err != nil {
		return err
	}
	if n := p.wireLen(); n > MaxString {
		return fmt.Errorf("resinfo: %q renders to %d octets, over %d (RFC 1035 §3.3)", p.Key, n, MaxString)
	}
	switch k {
	case kindFlag:
		if p.HasValue {
			return fmt.Errorf("%w: %q is a boolean attribute (RFC 9606 §5, RFC 6763 §6.4)", errValueShape, p.Key)
		}
	case kindExtErr:
		if !p.HasValue {
			return fmt.Errorf("%w: %q needs a value", errValueShape, p.Key)
		}
		return checkCanonicalExtErr(p.Value)
	case kindURL:
		if !p.HasValue {
			return fmt.Errorf("%w: %q needs a value", errValueShape, p.Key)
		}
		return checkInfoURL(p.Value)
	case kindTemp:
		if p.HasValue && !printable(p.Value, ' ') {
			return fmt.Errorf("%w: %q value must be printable US-ASCII", errValueShape, p.Key)
		}
	}
	return nil
}

// keyKind checks key syntax and returns how its value is shaped. Keys are one
// or more of a-z, 0-9 and '-', a strict subset of RFC 6763 §6.4's printable
// US-ASCII without '=' that leaves no case to fold ("Case is ignored when
// interpreting a key") and no spaces to get wrong; every registered key fits
// it. A key MUST be registered or begin with "temp-" (RFC 9606 §4).
func keyKind(key string) (kind, error) {
	if key == "" {
		return 0, errors.New("resinfo: empty key (RFC 6763 §6.4: at least one character)")
	}
	for i := range len(key) {
		if c := key[i]; (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return 0, fmt.Errorf("resinfo: key %q: only a-z, 0-9 and '-' are allowed", key)
		}
	}
	if k, ok := registered[key]; ok {
		return k, nil
	}
	if strings.HasPrefix(key, TempPrefix) && len(key) > len(TempPrefix) {
		return kindTemp, nil
	}
	return 0, fmt.Errorf("resinfo: key %q is neither registered nor %q-prefixed (RFC 9606 §4)", key, TempPrefix)
}

// printable reports whether every byte of s is in [lo, 0x7E].
func printable(s string, lo byte) bool {
	for i := range len(s) {
		if s[i] < lo || s[i] > '~' {
			return false
		}
	}
	return true
}

// checkInfoURL accepts an absolute https URL with a host, no userinfo, made of
// printable US-ASCII without spaces, and already in the form url.URL.String
// renders it in (so two spellings of one URL cannot both be valid). RFC 9606
// §5: "The DNS client MUST reject the URL as invalid if the scheme is not
// "https"".
func checkInfoURL(s string) error {
	if !printable(s, '!') {
		return errors.New("resinfo: infourl must be printable US-ASCII without spaces")
	}
	u, err := url.Parse(s)
	if err != nil {
		return fmt.Errorf("resinfo: infourl: %w", err)
	}
	switch {
	case u.Scheme != "https":
		return errors.New(`resinfo: infourl scheme must be "https" (RFC 9606 §5)`)
	case u.Host == "" || u.Opaque != "":
		return errors.New("resinfo: infourl needs a host")
	case u.User != nil:
		return errors.New("resinfo: infourl must not carry userinfo")
	case u.String() != s:
		return fmt.Errorf("resinfo: infourl is not in canonical form, want %q", u.String())
	}
	return nil
}

// AppendWire appends the RDATA in wire form: each character-string as one
// length octet followed by its text (RFC 1035 §3.3, §3.3.14).
func (i Info) AppendWire(b []byte) []byte {
	for _, p := range i.pairs {
		b = append(b, byte(p.wireLen())) //nolint:gosec // G115: validate caps every string at MaxString (255) octets.
		b = append(b, p.Key...)
		if p.HasValue {
			b = append(b, '=')
			b = append(b, p.Value...)
		}
	}
	return b
}

// DecodeWire reads RDATA in wire form and decodes it as Decode does. Every
// octet must belong to a character-string: a length octet that runs past the
// end is an error, not a short string.
func DecodeWire(rdata []byte) (Info, error) {
	txt, err := unpackStrings(rdata)
	if err != nil {
		return Info{}, err
	}
	return Decode(txt)
}

var errTruncated = errors.New("resinfo: character-string runs past the end of the RDATA")

// unpackStrings splits wire RDATA into its character-strings.
func unpackStrings(b []byte) ([]string, error) {
	var out []string
	for len(b) > 0 {
		n := int(b[0])
		if 1+n > len(b) {
			return nil, errTruncated
		}
		out = append(out, string(b[1:1+n]))
		b = b[1+n:]
	}
	return out, nil
}

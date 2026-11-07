package resinfo

import (
	"cmp"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// Range is an inclusive run of RFC 8914 INFO-CODEs, Lo <= Hi.
type Range struct {
	Lo, Hi uint16
}

// errExtErr is the parent of every exterr syntax error.
var errExtErr = errors.New("resinfo: exterr")

// ParseExtErr reads an RFC 9606 §5 exterr value: comma-separated items, each
// a decimal INFO-CODE or a "lo-hi" range ("Range values MUST be identified
// by "-". When multiple non-contiguous values are present, these values MUST
// be comma-separated."). Overlapping, adjacent, repeated and unordered items
// are accepted; the result is the canonical range list (see CanonicalRanges).
func ParseExtErr(s string) ([]Range, error) {
	if s == "" {
		return nil, fmt.Errorf("%w: empty list", errExtErr)
	}
	items := strings.Split(s, ",")
	rs := make([]Range, 0, len(items))
	for _, it := range items {
		r, err := ParseExtErrItem(it)
		if err != nil {
			return nil, err
		}
		rs = append(rs, r)
	}
	return CanonicalRanges(rs), nil
}

// ParseExtErrItem reads one item: "N" or "LO-HI" with LO <= HI, decimal,
// no sign, no spaces, no leading zeros.
func ParseExtErrItem(it string) (Range, error) {
	loS, hiS, isRange := strings.Cut(it, "-")
	lo, err := parseCode(loS)
	if err != nil {
		return Range{}, err
	}
	if !isRange {
		return Range{Lo: lo, Hi: lo}, nil
	}
	hi, err := parseCode(hiS)
	if err != nil {
		return Range{}, err
	}
	if lo > hi {
		return Range{}, fmt.Errorf("%w: range %q runs backwards", errExtErr, it)
	}
	return Range{Lo: lo, Hi: hi}, nil
}

func parseCode(s string) (uint16, error) {
	if s == "" || (len(s) > 1 && s[0] == '0') {
		return 0, fmt.Errorf("%w: %q is not a canonical decimal INFO-CODE", errExtErr, s)
	}
	for i := range len(s) {
		if s[i] < '0' || s[i] > '9' {
			return 0, fmt.Errorf("%w: %q is not a decimal INFO-CODE", errExtErr, s)
		}
	}
	n, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("%w: INFO-CODE %q is not 16-bit (RFC 8914 §2)", errExtErr, s)
	}
	return uint16(n), nil
}

// CanonicalRanges returns the unique canonical list covering exactly the
// codes rs covers: sorted, every range Lo <= Hi, and a gap of at least one
// missing code between consecutive ranges (Hi+1 < next Lo), so no two ranges
// overlap or touch. The Lean model (Resinfo.lean, ranges_unique) proves that
// such a list is determined by the set of codes it covers.
func CanonicalRanges(rs []Range) []Range {
	s := slices.Clone(rs)
	slices.SortFunc(s, func(a, b Range) int { return cmp.Compare(a.Lo, b.Lo) })
	out := make([]Range, 0, len(s))
	for _, r := range s {
		if n := len(out); n > 0 && uint32(r.Lo) <= uint32(out[n-1].Hi)+1 {
			out[n-1].Hi = max(out[n-1].Hi, r.Hi)
			continue
		}
		out = append(out, r)
	}
	return out
}

// FormatExtErr renders canonical ranges: a one-code range as "N", a longer
// one as "LO-HI", joined by ",". RFC 9606 §6's example "exterr=15-17" is the
// canonical rendering of {15, 16, 17}.
func FormatExtErr(rs []Range) string {
	var b strings.Builder
	for i, r := range rs {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(strconv.FormatUint(uint64(r.Lo), 10))
		if r.Hi != r.Lo {
			b.WriteByte('-')
			b.WriteString(strconv.FormatUint(uint64(r.Hi), 10))
		}
	}
	return b.String()
}

// The value s is accepted only if it is the canonical rendering of the
// codes it lists, so a given set of codes has exactly one valid spelling.
func checkCanonicalExtErr(s string) error {
	rs, err := ParseExtErr(s)
	if err != nil {
		return err
	}
	if c := FormatExtErr(rs); c != s {
		return fmt.Errorf("%w: %q is not canonical, want %q", errExtErr, s, c)
	}
	return nil
}

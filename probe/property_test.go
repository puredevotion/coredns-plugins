package probe

import (
	"math/rand"
	"slices"
	"strings"
	"testing"
)

const (
	propIterations = 5000
	propSeed       = 8145
)

// randCase flips the ASCII case of each letter with probability 1/2, as a
// 0x20-randomising resolver would.
func randCase(r *rand.Rand, s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'z' && r.Intn(2) == 0 {
			b[i] = c - 'a' + 'A'
		}
	}
	return string(b)
}

func randToken(r *rand.Rand) string {
	const hex = "0123456789abcdef"
	n := minTokenLen - 2 + r.Intn(maxTokenLen-minTokenLen+6) // Sometimes out of range.
	b := make([]byte, n)
	for i := range b {
		b[i] = hex[r.Intn(len(hex))]
	}
	if r.Intn(20) == 0 {
		b[r.Intn(n)] = 'g'
	}
	return string(b)
}

func randMods(r *rand.Rand) Modifier {
	return Modifier(r.Uint32() % (1 << (len(modifierOrder) + 1))) // One bit past the defined set.
}

// Validate, Sub and ParseQuery agree: a valid Query renders to a name that
// parses back to itself, and an invalid one never does.
func TestProperty_QueryValidateSubParse(t *testing.T) {
	r := rand.New(rand.NewSource(propSeed)) //nolint:gosec // G404: deterministic test generator.
	var valid, invalid int
	for range propIterations {
		q := Query{Token: randToken(r), Mods: randMods(r)}
		if r.Intn(2) == 0 {
			q.Mods &= ModUnsigned | ModTruncate | ModBig | ModNXNAME // Mostly consistent sets.
		}
		got, ok := ParseQuery(q.Sub())
		// A valid query round-trips. An invalid one must not: either the name
		// is refused, or (undefined modifier bits have no label) it parses to
		// a different, valid query.
		if q.Validate() != nil {
			invalid++
			if ok && (got == q || got.Validate() != nil) {
				t.Fatalf("invalid %+v parsed from %q as %+v", q, q.Sub(), got)
			}
			continue
		}
		if !ok {
			t.Fatalf("valid %+v rendered as %q, which ParseQuery refuses", q, q.Sub())
		}
		valid++
		if got != q {
			t.Fatalf("round trip %+v -> %q -> %+v", q, q.Sub(), got)
		}
		// Rendering is canonical: reparsing and rendering again is a fixed point.
		if again := got.Sub(); again != q.Sub() {
			t.Fatalf("Sub not idempotent: %q vs %q", q.Sub(), again)
		}
	}
	if valid < propIterations/10 || invalid < propIterations/10 {
		t.Fatalf("generator is unbalanced: %d valid, %d invalid", valid, invalid)
	}
	if (Query{}).Validate() == nil {
		t.Fatal("zero Query must be invalid")
	}
}

// Parsing is case-insensitive and modifier order does not matter.
func TestProperty_QueryCaseAndOrder(t *testing.T) {
	r := rand.New(rand.NewSource(propSeed + 1)) //nolint:gosec // G404: deterministic test generator.
	for range propIterations {
		q := Query{Token: randToken(r), Mods: randMods(r)}
		if q.Validate() != nil {
			continue
		}
		labels := strings.Split(q.Sub(), ".")
		mods, token := labels[:len(labels)-1], labels[len(labels)-1]
		r.Shuffle(len(mods), func(i, j int) { mods[i], mods[j] = mods[j], mods[i] })
		shuffled := strings.Join(append(slices.Clone(mods), token), ".")
		for _, name := range []string{randCase(r, q.Sub()), shuffled, randCase(r, shuffled) + "."} {
			got, ok := ParseQuery(name)
			if !ok || got != q {
				t.Fatalf("ParseQuery(%q) = %+v ok=%v, want %+v", name, got, ok, q)
			}
		}
	}
}

// Case folding is idempotent and ASCII-only, and key-tag labels round trip in
// any case.
func TestProperty_ToLowerAndKeyTags(t *testing.T) {
	r := rand.New(rand.NewSource(propSeed + 2)) //nolint:gosec // G404: deterministic test generator.
	for range propIterations {
		s := randCase(r, randToken(r)+"_Aé")
		l := toLowerASCII(s)
		if toLowerASCII(l) != l || len(l) != len(s) || l != strings.Map(func(c rune) rune {
			if c >= 'A' && c <= 'Z' {
				return c + 'a' - 'A'
			}
			return c
		}, s) {
			t.Fatalf("toLowerASCII(%q) = %q", s, l)
		}

		tags := make([]uint16, 1+r.Intn(maxKeyTagsPerQuery))
		for i := range tags {
			tags[i] = uint16(r.Uint32() & 0xffff)
		}
		label := FormatKeyTagQuery(tags)
		got, err := ParseKeyTagQuery(randCase(r, label))
		want := slices.Clone(tags)
		slices.Sort(want)
		if err != nil || !slices.Equal(got, want) {
			t.Fatalf("key tags %v: %q -> %v, %v", tags, label, got, err)
		}
	}
}

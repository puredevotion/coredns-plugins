package resinfo

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

const (
	exampleURL    = "https://resolver.example.com/guide"
	extErrExample = "15-17"
	tempX         = "temp-x"
	fullRange     = "0-65535"
	mangled       = "mangled"
)

// rfcExample is RFC 9606 §6, Figure 1's RDATA, as this plugin orders it.
func rfcExample(t *testing.T) Info {
	t.Helper()
	i, err := New(
		Pair{Key: KeyQNameMin},
		Pair{Key: KeyExtErr, Value: extErrExample, HasValue: true},
		Pair{Key: KeyInfoURL, Value: exampleURL, HasValue: true},
	)
	if err != nil {
		t.Fatal(err)
	}
	return i
}

func TestRFC9606Example(t *testing.T) {
	got := rfcExample(t).Strings()
	want := []string{"exterr=15-17", "infourl=" + exampleURL, KeyQNameMin}
	if !slices.Equal(got, want) {
		t.Fatalf("Strings() = %q, want %q", got, want)
	}

	// The presentation form of Figure 1 parses (miekg/dns) to the same
	// strings, in Figure 1's order; sorted, they are ours.
	rr, err := dns.NewRR("resolver.example.net. 7200 IN RESINFO qnamemin exterr=15-17 infourl=" + exampleURL)
	if err != nil {
		t.Fatal(err)
	}
	res, ok := rr.(*dns.RESINFO)
	if !ok {
		t.Fatalf("parsed %T", rr)
	}
	if _, err := Decode(res.Txt); err == nil {
		t.Fatal("Figure 1's order is not canonical here, yet Decode accepted it")
	}
	sorted := slices.Clone(res.Txt)
	slices.Sort(sorted)
	if !slices.Equal(sorted, want) {
		t.Fatalf("Figure 1 sorted = %q, want %q", sorted, want)
	}
}

func TestNewRejects(t *testing.T) {
	long := strings.Repeat("a", MaxString)
	for name, pairs := range map[string][]Pair{
		"empty":               nil,
		"duplicate":           {{Key: KeyQNameMin}, {Key: KeyQNameMin}},
		"unregistered":        {{Key: "papersize", Value: "A4", HasValue: true}},
		"bare temp-":          {{Key: TempPrefix}},
		"uppercase key":       {{Key: strings.ToUpper(KeyQNameMin)}},
		"key with '='":        {{Key: "temp-a=b"}},
		"key with space":      {{Key: "temp- a"}},
		"empty key":           {{Key: "", Value: "x", HasValue: true}},
		"qnamemin with value": {{Key: KeyQNameMin, Value: "", HasValue: true}},
		"deleg with value":    {{Key: KeyDeleg, Value: "1", HasValue: true}},
		"exterr no value":     {{Key: KeyExtErr}},
		"exterr unsorted":     {{Key: KeyExtErr, Value: "17,15", HasValue: true}},
		"exterr not merged":   {{Key: KeyExtErr, Value: "15,16,17", HasValue: true}},
		"exterr 15-15":        {{Key: KeyExtErr, Value: "15-15", HasValue: true}},
		"exterr leading zero": {{Key: KeyExtErr, Value: "015", HasValue: true}},
		"exterr 65536":        {{Key: KeyExtErr, Value: "65536", HasValue: true}},
		"exterr space":        {{Key: KeyExtErr, Value: "15, 17", HasValue: true}},
		"infourl http":        {{Key: KeyInfoURL, Value: "http://resolver.example.com/", HasValue: true}},
		"infourl no host":     {{Key: KeyInfoURL, Value: "https:///guide", HasValue: true}},
		"infourl opaque":      {{Key: KeyInfoURL, Value: "https:resolver.example.com", HasValue: true}},
		"infourl userinfo":    {{Key: KeyInfoURL, Value: "https://operator@resolver.example.com/", HasValue: true}},
		"infourl space":       {{Key: KeyInfoURL, Value: "https://resolver.example.com/a b", HasValue: true}},
		"infourl uppercase":   {{Key: KeyInfoURL, Value: "HTTPS://resolver.example.com/", HasValue: true}},
		"infourl no value":    {{Key: KeyInfoURL}},
		"temp control char":   {{Key: tempX, Value: "a\x00b", HasValue: true}},
		"temp non-ASCII":      {{Key: tempX, Value: "é", HasValue: true}},
		"string over 255":     {{Key: tempX, Value: long, HasValue: true}},
	} {
		if _, err := New(pairs...); err == nil {
			t.Errorf("%s: New(%v) accepted", name, pairs)
		}
	}
}

func TestNewAccepts(t *testing.T) {
	exactly255 := strings.Repeat("v", MaxString-len("temp-x="))
	for name, pairs := range map[string][]Pair{
		"one flag":           {{Key: KeyQNameMin}},
		"deleg":              {{Key: KeyDeleg}},
		"exterr single":      {{Key: KeyExtErr, Value: "0", HasValue: true}},
		"exterr full range":  {{Key: KeyExtErr, Value: fullRange, HasValue: true}},
		"exterr mixed":       {{Key: KeyExtErr, Value: "1,3-4,15-17,49152", HasValue: true}},
		"temp flag":          {{Key: tempX}},
		"temp empty value":   {{Key: tempX, HasValue: true}},
		"temp with '='":      {{Key: tempX, Value: "a=b=c", HasValue: true}},
		"temp with space":    {{Key: tempX, Value: " a b ", HasValue: true}},
		"string exactly 255": {{Key: tempX, Value: exactly255, HasValue: true}},
		"infourl query":      {{Key: KeyInfoURL, Value: "https://resolver.example.com/a?b=c", HasValue: true}},
	} {
		i, err := New(pairs...)
		if err != nil {
			t.Errorf("%s: New: %v", name, err)
			continue
		}
		back, err := Decode(i.Strings())
		if err != nil || !slices.Equal(back.Pairs(), i.Pairs()) {
			t.Errorf("%s: Decode(Strings()) = %v, %v", name, back.Pairs(), err)
		}
	}
}

// RFC 1035 §3.2.1: RDLENGTH is 16 bits. Enough 255-octet temp- strings
// exceed it and must be refused.
func TestTotalRDATALimit(t *testing.T) {
	val := strings.Repeat("v", MaxString-len("temp-000="))
	pairs := make([]Pair, 0, 256)
	for i := range 256 {
		pairs = append(pairs, Pair{Key: fmt.Sprintf("temp-%03d", i), Value: val, HasValue: true})
	}
	// 256 strings of 256 octets is 65536, one over.
	if _, err := New(pairs...); err == nil {
		t.Fatal("accepted 65536 octets of RDATA")
	}
	i, err := New(pairs[:255]...)
	if err != nil {
		t.Fatalf("255 strings: %v", err)
	}
	if i.WireLen() != 255*256 {
		t.Fatalf("WireLen = %d", i.WireLen())
	}
}

func TestDecodeRejectsNonCanonical(t *testing.T) {
	for name, txt := range map[string][]string{
		"empty":         {},
		"unsorted":      {KeyQNameMin, "exterr=15"},
		"duplicate":     {KeyQNameMin, KeyQNameMin},
		"missing key":   {"=x"},
		"empty string":  {""},
		"uppercase key": {"QnameMin"},
		"unknown key":   {"foo"},
		"flag value":    {"qnamemin="},
	} {
		if _, err := Decode(txt); err == nil {
			t.Errorf("%s: Decode(%q) accepted", name, txt)
		}
	}
}

func TestPairsAndStringsAreCopies(t *testing.T) {
	i := rfcExample(t)
	s := i.Strings()
	s[0] = mangled
	p := i.Pairs()
	p[0].Key = mangled
	if i.Strings()[0] == mangled || i.Pairs()[0].Key == mangled {
		t.Fatal("Info shares its state with the caller")
	}
	if i.IsZero() || !(Info{}).IsZero() {
		t.Fatal("IsZero")
	}
}

func TestExtErr(t *testing.T) {
	for in, want := range map[string]string{
		extErrExample:   extErrExample,
		"17,16,15":      extErrExample,
		"15,17":         "15,17",
		"15,16":         "15-16",
		"1-3,2-5,7":     "1-5,7",
		"0,65535,1":     "0-1,65535",
		"3,3,3":         "3",
		"10-12,13-14":   "10-14",
		"0-65535,15":    fullRange,
		"49152-65535,0": "0,49152-65535",
	} {
		rs, err := ParseExtErr(in)
		if err != nil {
			t.Errorf("ParseExtErr(%q): %v", in, err)
			continue
		}
		if got := FormatExtErr(rs); got != want {
			t.Errorf("ParseExtErr(%q) renders %q, want %q", in, got, want)
		}
	}
	for _, bad := range []string{"", ",", "1,", ",1", "a", "-1", "1-", "-", "2-1", "1--2", "65536", "+1", "1 ", "00", "1-02", "99999999999999999999"} {
		if _, err := ParseExtErr(bad); err == nil {
			t.Errorf("ParseExtErr(%q) accepted", bad)
		}
	}
}

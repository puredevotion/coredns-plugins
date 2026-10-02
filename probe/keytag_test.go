package probe

import (
	"context"
	"encoding/binary"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// TestParseKeyTagQueryRFCExamples uses RFC 8145 §5.1's own worked examples. Key
// tags are HEXADECIMAL and zero-padded to four digits — the natural wrong guess
// is decimal, and it would parse a lot of names into confidently wrong numbers.
func TestParseKeyTagQueryRFCExamples(t *testing.T) {
	// RFC 8145 §5.1: root key tag 17476 decimal = 0x4444.
	tags, err := ParseKeyTagQuery("_ta-4444")
	if err != nil {
		t.Fatalf("ParseKeyTagQuery: %v", err)
	}
	if len(tags) != 1 || tags[0] != 0x4444 {
		t.Errorf("tags = %v, want [0x4444] (17476 decimal)", tags)
	}
	if tags[0] != 17476 {
		t.Errorf("tag decoded as %d, want 17476 — hex, not decimal", tags[0])
	}

	// RFC 8145 §5.1: 1589, 43547, 31406 decimal for example.com.
	tags, err = ParseKeyTagQuery("_ta-0635-7aae-aa1b")
	if err != nil {
		t.Fatalf("ParseKeyTagQuery: %v", err)
	}
	want := []uint16{0x0635, 0x7aae, 0xaa1b}
	if len(tags) != 3 {
		t.Fatalf("tags = %v, want 3 entries", tags)
	}
	for i := range want {
		if tags[i] != want[i] {
			t.Errorf("tags[%d] = %#04x, want %#04x", i, tags[i], want[i])
		}
	}
	// Sanity against the RFC's decimal values.
	if tags[0] != 1589 || tags[1] != 31406 || tags[2] != 43547 {
		t.Errorf("decoded %v, want [1589 31406 43547] decimal", tags)
	}
}

// TestParseKeyTagQueryRejectsUnpadded — RFC 8145 §5.1 says values MUST be
// zero-padded to four hex digits. Accepting "635" as 0x0635 would silently
// normalise away a real implementation bug, which is the opposite of what a
// measurement zone is for.
func TestParseKeyTagQueryRejectsUnpadded(t *testing.T) {
	for _, name := range []string{"_ta-635", "_ta-4", "_ta-0635-7ae", "_ta-00635"} {
		if _, err := ParseKeyTagQuery(name); !errors.Is(err, ErrBadKeyTagQuery) {
			t.Errorf("%s: err = %v, want ErrBadKeyTagQuery", name, err)
		}
	}
}

// TestParseKeyTagQueryRejectsHostileInput — the name is chosen by the sender.
func TestParseKeyTagQueryRejectsHostileInput(t *testing.T) {
	flood := "_ta-" + strings.TrimSuffix(strings.Repeat("0001-", maxKeyTagsPerQuery+4), "-")

	for _, tc := range []struct {
		wantErr error
		name    string
		in      string
	}{
		{name: "not a key tag name", in: testToken2, wantErr: ErrNotKeyTagQuery},
		{name: "prefix only", in: "_ta-", wantErr: ErrBadKeyTagQuery},
		{name: "bare prefix without hyphen", in: "_ta", wantErr: ErrNotKeyTagQuery},
		{name: "non-hex digits", in: "_ta-zzzz", wantErr: ErrBadKeyTagQuery},
		{name: "empty tag between hyphens", in: "_ta-0635--7aae", wantErr: ErrBadKeyTagQuery},
		{name: "trailing hyphen", in: "_ta-0635-", wantErr: ErrBadKeyTagQuery},
		{name: "tag flood", in: flood, wantErr: ErrBadKeyTagQuery},
		// Key Tag queries go to the zone apex, so the prefix must be the only
		// label. A deeper name is not one, and must not be mistaken for one.
		{name: "deeper than the apex", in: "_ta-4444.something", wantErr: ErrNotKeyTagQuery},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseKeyTagQuery(tc.in)
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("err = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

// TestKeyTagSortConformanceIsRecordedNotFixed — RFC 8145 §5.1 requires
// smallest-to-largest. A sender that gets it wrong is a finding, so the parser
// preserves arrival order and sortedness is reported separately.
func TestKeyTagSortConformanceIsRecordedNotFixed(t *testing.T) {
	tags, err := ParseKeyTagQuery("_ta-aa1b-0635")
	if err != nil {
		t.Fatalf("ParseKeyTagQuery: %v", err)
	}
	if tags[0] != 0xaa1b {
		t.Errorf("parser reordered the tags: got %v, want arrival order", tags)
	}
	if KeyTagsSorted(tags) {
		t.Error("KeyTagsSorted said true for a descending list")
	}
	if !KeyTagsSorted([]uint16{0x0635, 0xaa1b}) {
		t.Error("KeyTagsSorted said false for an ascending list")
	}
}

// TestFormatKeyTagQueryRoundTrips checks the renderer against the RFC example and
// that it sorts, since the wire format requires it.
func TestFormatKeyTagQueryRoundTrips(t *testing.T) {
	if got, want := FormatKeyTagQuery([]uint16{0xaa1b, 0x0635, 0x7aae}), "_ta-0635-7aae-aa1b"; got != want {
		t.Errorf("FormatKeyTagQuery = %q, want %q (sorted, zero-padded)", got, want)
	}
	tags, err := ParseKeyTagQuery(FormatKeyTagQuery([]uint16{17476}))
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	if len(tags) != 1 || tags[0] != 17476 {
		t.Errorf("round trip gave %v, want [17476]", tags)
	}
}

// TestParseEDNSKeyTags covers option 14's payload: OPTION-LENGTH is 2 x the tag
// count, each a 16-bit value in network byte order.
func TestParseEDNSKeyTags(t *testing.T) {
	tags, ok := parseEDNSKeyTags([]byte{0x44, 0x44, 0x06, 0x35})
	if !ok {
		t.Fatal("well-formed payload rejected")
	}
	if len(tags) != 2 || tags[0] != 0x4444 || tags[1] != 0x0635 {
		t.Errorf("tags = %v, want [0x4444 0x0635]", tags)
	}

	for _, tc := range []struct {
		name string
		in   []byte
	}{
		{"empty", nil},
		// An odd length means a half tag. Returning a truncated list would be a
		// plausible-looking wrong answer.
		{"odd length", []byte{0x44, 0x44, 0x06}},
		{"single byte", []byte{0x44}},
		{"tag flood", make([]byte, (maxKeyTagsPerQuery+1)*2)},
	} {
		if _, ok := parseEDNSKeyTags(tc.in); ok {
			t.Errorf("%s: accepted", tc.name)
		}
	}
}

// TestObserveRecordsEDNSKeyTags wires option 14 through Observe. Miekg/dns has no
// type for code 14, so it arrives as an EDNS0_LOCAL and must be picked out by
// code rather than by type.
func TestObserveRecordsEDNSKeyTags(t *testing.T) {
	o := newOpt()
	o.Option = append(o.Option, &dns.EDNS0_LOCAL{
		Code: ednsKeyTagOption,
		Data: []byte{0x44, 0x44},
	})
	obs := observeWith(t, ednsQuery(o))
	if len(obs.KeyTags) != 1 || obs.KeyTags[0] != 0x4444 {
		t.Errorf("KeyTags = %v, want [0x4444]", obs.KeyTags)
	}

	// A different local option must not be mistaken for key tags.
	o2 := newOpt()
	o2.Option = append(o2.Option, &dns.EDNS0_LOCAL{Code: 65001, Data: []byte{0x44, 0x44}})
	if obs := observeWith(t, ednsQuery(o2)); len(obs.KeyTags) != 0 {
		t.Errorf("KeyTags = %v for an unrelated local option, want empty", obs.KeyTags)
	}

	// A malformed payload records nothing rather than a truncated tag.
	o3 := newOpt()
	o3.Option = append(o3.Option, &dns.EDNS0_LOCAL{Code: ednsKeyTagOption, Data: []byte{0x44}})
	if obs := observeWith(t, ednsQuery(o3)); len(obs.KeyTags) != 0 {
		t.Errorf("KeyTags = %v for an odd-length payload, want empty", obs.KeyTags)
	}
}

// TestKeyTagQueryAnsweredNODATA is the behaviour change that matters. Before this,
// `_ta-*` fell through to ParseQuery and got REFUSED — wrong per RFC 8145 §5.3
// (the response is whatever the zone content implies, and this synthesised zone
// has no `_ta-*` records, so NODATA) and a discarded measurement besides.
func TestKeyTagQueryAnsweredNODATA(t *testing.T) {
	p := newTestProbe(t, true)
	m := query(t, p, "_ta-4444."+testZone, dns.TypeNULL, false)

	if m.Rcode != dns.RcodeSuccess {
		t.Errorf("Rcode = %s, want NOERROR (NODATA, not REFUSED and not NXDOMAIN)", dns.RcodeToString[m.Rcode])
	}
	if len(m.Answer) != 0 {
		t.Errorf("answer section has %d records, want 0", len(m.Answer))
	}
	if len(m.Ns) == 0 {
		t.Error("authority section empty; NODATA should carry the SOA")
	}
}

// TestMalformedKeyTagQueryRefused — shaped like a Key Tag query but not one gets
// the same REFUSED as any other name the grammar rejects, rather than being
// silently reinterpreted.
func TestMalformedKeyTagQueryRefused(t *testing.T) {
	p := newTestProbe(t, true)
	m := query(t, p, "_ta-zzzz."+testZone, dns.TypeNULL, false)
	if m.Rcode != dns.RcodeRefused {
		t.Errorf("Rcode = %s, want REFUSED", dns.RcodeToString[m.Rcode])
	}
}

// TestKnowsZoneKeyRequiresASignal is the distinction that keeps this honest: a
// resolver that sent no key tags has not told us it lacks our key.
func TestKnowsZoneKeyRequiresASignal(t *testing.T) {
	p := newTestProbe(t, true)
	ourTag := p.Signer.DNSKEY().KeyTag()

	// No signal at all.
	m := new(dns.Msg)
	m.SetQuestion("deadbeef."+testZone, dns.TypeTXT)
	m.SetEdns0(1232, false)
	if obs := observeFromMsg(t, m); obs.KnowsZoneKey {
		t.Error("KnowsZoneKey = true with no key tags signalled")
	}

	// Signalled, and it is ours.
	withTag := func(tag uint16) *dns.Msg {
		msg := new(dns.Msg)
		msg.SetQuestion("deadbeef."+testZone, dns.TypeTXT)
		msg.SetEdns0(1232, false)
		opt := msg.IsEdns0()
		// Encoded rather than hand-shifted: option 14 is a list of 16-bit values
		// in network byte order, and PutUint16 says so without a narrowing cast.
		var raw [2]byte
		binary.BigEndian.PutUint16(raw[:], tag)
		opt.Option = append(opt.Option, &dns.EDNS0_LOCAL{
			Code: ednsKeyTagOption,
			Data: raw[:],
		})
		return msg
	}

	obs := observeFromMsg(t, withTag(ourTag))
	if len(obs.KeyTags) != 1 {
		t.Fatalf("KeyTags = %v", obs.KeyTags)
	}
	if !hasKeyTag(obs.KeyTags, ourTag) {
		t.Error("our own key tag not found in the signalled list")
	}

	// Signalled, but a different key.
	other := ourTag ^ 0xFFFF
	obs = observeFromMsg(t, withTag(other))
	if hasKeyTag(obs.KeyTags, ourTag) {
		t.Error("a foreign key tag matched ours")
	}
}

// observeFromMsg runs Observe against a hand-built message.
func observeFromMsg(t *testing.T, m *dns.Msg) Observation {
	t.Helper()
	return observeWith(t, m)
}

// keyTagOpt builds one edns-key-tag option instance carrying tags.
func keyTagOpt(tags ...uint16) *dns.EDNS0_LOCAL {
	data := make([]byte, 0, 2*len(tags))
	for _, tag := range tags {
		data = binary.BigEndian.AppendUint16(data, tag)
	}
	return &dns.EDNS0_LOCAL{Code: ednsKeyTagOption, Data: data}
}

// RFC 8145 §4.2.2.1: a recursive resolver forwarding a client's list "SHOULD
// transmit the two Key Tag lists using separate instances of the
// edns-key-tag option code". Only the last instance used to be kept.
func TestObserveKeepsEveryEDNSKeyTagInstance(t *testing.T) {
	o := newOpt()
	o.Option = append(o.Option,
		keyTagOpt(19036, 12345),
		&dns.EDNS0_LOCAL{Code: ednsKeyTagOption, Data: []byte{0x44}}, // Malformed; must not discard the others.
		keyTagOpt(19036, 34567))
	obs := observeWith(t, ednsQuery(o))
	want := []uint16{19036, 12345, 19036, 34567}
	if !slices.Equal(obs.KeyTags, want) {
		t.Errorf("KeyTags = %v, want %v", obs.KeyTags, want)
	}
}

// RFC 8145 §4.2: "A validating resolver sets the edns-key-tag option in the
// OPT RR when sending a DNSKEY query", which goes to the apex. The apex never
// looked at it, so the conforming case was the one never recorded.
func TestApexDNSKEYQueryCountsEDNSKeyTags(t *testing.T) {
	p := newTestProbe(t, true)
	ours := p.Signer.DNSKEY().KeyTag()
	counter := probeKeyTagKnowledge.WithLabelValues("dnskey", labelYes)
	before := testutil.ToFloat64(counter)

	m := new(dns.Msg)
	m.SetQuestion(testZone, dns.TypeDNSKEY)
	m.SetEdns0(1232, true)
	m.IsEdns0().Option = append(m.IsEdns0().Option, keyTagOpt(ours))
	rec := dnstest.NewRecorder(&test.ResponseWriter{})
	if _, err := p.ServeDNS(context.Background(), rec, m); err != nil {
		t.Fatalf("ServeDNS: %v", err)
	}
	if rec.Msg == nil || len(rec.Msg.Answer) == 0 {
		t.Fatal("apex DNSKEY query was not answered")
	}
	if got := testutil.ToFloat64(counter) - before; got != 1 {
		t.Errorf("dnskey/yes counter moved by %v, want 1", got)
	}

	// No option, no count: silence is not a statement about keys.
	before = testutil.ToFloat64(counter)
	query(t, p, testZone, dns.TypeDNSKEY, true)
	if got := testutil.ToFloat64(counter) - before; got != 0 {
		t.Errorf("a DNSKEY query without option 14 was counted (%v)", got)
	}
}

// RFC 8145 §5.1: "A Key Tag query consists of a standard DNS query of type
// NULL and of class IN". A `_ta-` name asked for any other type is answered
// the same way but is not a trust-anchor signal, and used to be counted.
func TestKeyTagQueryCountedOnlyForNULL(t *testing.T) {
	p := newTestProbe(t, true)
	counter := probeKeyTagQueries.WithLabelValues("sorted")

	before := testutil.ToFloat64(counter)
	m := query(t, p, "_ta-4444."+testZone, dns.TypeA, false)
	if m.Rcode != dns.RcodeSuccess || len(m.Answer) != 0 {
		t.Errorf("A at a _ta- name: rcode %s with %d answers, want NODATA", dns.RcodeToString[m.Rcode], len(m.Answer))
	}
	if got := testutil.ToFloat64(counter) - before; got != 0 {
		t.Errorf("an A query at a _ta- name was counted as a Key Tag query (%v)", got)
	}

	before = testutil.ToFloat64(counter)
	query(t, p, "_ta-4444."+testZone, dns.TypeNULL, false)
	if got := testutil.ToFloat64(counter) - before; got != 1 {
		t.Errorf("a NULL Key Tag query moved the counter by %v, want 1", got)
	}

	malformed := probeKeyTagQueries.WithLabelValues("malformed")
	before = testutil.ToFloat64(malformed)
	query(t, p, "_ta-zzzz."+testZone, dns.TypeA, false)
	if got := testutil.ToFloat64(malformed) - before; got != 0 {
		t.Errorf("an A query at a malformed _ta- name was counted (%v)", got)
	}
}

// The prefix folds case in ASCII, as DNS names do (RFC 4343 §3). No
// non-ASCII rune lower-cases to "t" or "a", so the old Unicode fold could
// not misfire here; this only guards the ASCII behaviour.
func TestParseKeyTagQueryPrefixIsCaseInsensitive(t *testing.T) {
	if tags, err := ParseKeyTagQuery("_TA-4444"); err != nil || !slices.Equal(tags, []uint16{0x4444}) {
		t.Errorf("_TA-4444: got (%v, %v), want [0x4444]", tags, err)
	}
}

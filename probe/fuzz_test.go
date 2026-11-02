package probe

import (
	"bytes"
	"encoding/binary"
	"errors"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// FuzzParseQuery: the probe-label grammar is parsed from every query name an
// untrusted resolver sends. Whatever the input: no panic; an accepted query
// has a lowercase hex token of bounded length and no conflicting modifiers;
// rendering it back and reparsing yields the same query (round trip); and the
// same name in different ASCII case parses to the same query (RFC 4343).
func FuzzParseQuery(f *testing.F) {
	for _, s := range []string{
		"", "deadbeef", "DEADBEEF", "_badsig.deadbeef", "_unsigned._truncate.deadbeef",
		"_unsigned._badsig.deadbeef", "_nxdomain._servfail.deadbeef", "_big._BIG.deadbeef",
		"foo.deadbeef", "deadbeef.", "_.deadbeef", "xyzxyzxy", strings.Repeat("a", 33),
		"_expiredsig._futuresig.0123456789abcdef", "\xff\xfe.deadbeef",
	} {
		f.Add(s)
	}
	for _, s := range stringSeeds(f) {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, sub string) {
		q, ok := ParseQuery(sub)
		if !ok {
			if q != (Query{}) {
				t.Fatalf("ParseQuery(%q) rejected but returned %+v", sub, q)
			}
			return
		}
		if err := q.Validate(); err != nil {
			t.Fatalf("ParseQuery(%q) accepted a query that fails Validate: %v", sub, err)
		}

		again, ok := ParseQuery(q.Sub())
		if !ok || again != q {
			t.Fatalf("round trip of %q: rendered %q, reparsed %+v ok=%v, want %+v", sub, q.Sub(), again, ok, q)
		}
		upper, ok := ParseQuery(strings.ToUpper(sub))
		if !ok || upper != q {
			t.Fatalf("ParseQuery is case sensitive: %q -> %+v, upper -> %+v ok=%v", sub, q, upper, ok)
		}
		// A probe query is never also a DNS-SD name; the two are tried in
		// sequence, so an overlap would make the answer order-dependent.
		if kind, _ := parseDNSSD(sub); kind != dnssdNone {
			t.Fatalf("%q parses as both a probe query and DNS-SD kind %d", sub, kind)
		}
	})
}

// FuzzParseDNSSD: no panic; a recognised name always carries a valid token,
// and it is never also a valid probe query.
func FuzzParseDNSSD(f *testing.F) {
	for _, s := range []string{
		"", "deadbeef", "_services._dns-sd._udp.deadbeef", "_PROBE._TCP.DEADBEEF",
		"probe._probe._tcp.deadbeef.", "_probe._tcp.nothex", "x._probe._tcp.deadbeef",
	} {
		f.Add(s)
	}
	for _, s := range stringSeeds(f) {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, sub string) {
		kind, token := parseDNSSD(sub)
		if kind == dnssdNone {
			if token != "" {
				t.Fatalf("kind none with token %q", token)
			}
			return
		}
		if tok, ok := parseToken(token); !ok || tok != token {
			t.Fatalf("recognised %q with invalid token %q", sub, token)
		}
		if _, ok := ParseQuery(sub); ok {
			t.Fatalf("%q is both DNS-SD and a probe query", sub)
		}
	})
}

// FuzzParseKeyTagQuery: RFC 8145 Key Tag names. No panic; an accepted name has
// 1..16 tags and equals the canonical rendering of those tags (modulo ASCII
// case and ordering); rendering any tag list parses back to its sorted self.
//
//nolint:gocognit // A fuzz target is a flat list of invariants; splitting it only hides them.
func FuzzParseKeyTagQuery(f *testing.F) {
	for _, s := range []string{
		"", "_ta-4444", "_ta-0635-7aae-aa1b", "_TA-ABCD", "_ta-635", "_ta-", "_ta-4444.x",
		"_ta-aa1b-0635", "_ta-+123", "_ta-0x12", "_ta-" + strings.Repeat("0000-", 17),
	} {
		f.Add(s)
	}
	for _, s := range stringSeeds(f) {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, sub string) {
		tags, err := ParseKeyTagQuery(sub)
		if err != nil {
			if !errors.Is(err, ErrNotKeyTagQuery) && !errors.Is(err, ErrBadKeyTagQuery) {
				t.Fatalf("unexpected error type: %v", err)
			}
			if tags != nil {
				t.Fatalf("error %v with tags %v", err, tags)
			}
			return
		}
		if len(tags) == 0 || len(tags) > maxKeyTagsPerQuery {
			t.Fatalf("accepted %d tags", len(tags))
		}
		if KeyTagsSorted(tags) {
			if got, want := FormatKeyTagQuery(tags), toLowerASCII(sub); got != want {
				t.Fatalf("sorted input %q renders as %q", sub, got)
			}
		}
		back, err := ParseKeyTagQuery(FormatKeyTagQuery(tags))
		if err != nil {
			t.Fatalf("rendered form of %v does not parse: %v", tags, err)
		}
		want := slices.Clone(tags)
		slices.Sort(want)
		if !slices.Equal(back, want) {
			t.Fatalf("round trip %v -> %v, want %v", tags, back, want)
		}
	})
}

// FuzzParseEDNSKeyTags: the edns-key-tag option payload (RFC 8145 §4.1) is
// attacker-supplied bytes. Accepted payloads re-encode byte for byte.
func FuzzParseEDNSKeyTags(f *testing.F) {
	f.Add([]byte{0x44, 0x44})
	f.Add([]byte{0x44})
	f.Add([]byte{})
	f.Add(make([]byte, 34))
	f.Fuzz(func(t *testing.T, data []byte) {
		tags, ok := parseEDNSKeyTags(data)
		if !ok {
			if tags != nil {
				t.Fatalf("rejected but returned %v", tags)
			}
			return
		}
		var enc []byte
		for _, tag := range tags {
			enc = binary.BigEndian.AppendUint16(enc, tag)
		}
		if !bytes.Equal(enc, data) {
			t.Fatalf("payload % x decoded to %v, re-encodes as % x", data, tags, enc)
		}
	})
}

// FuzzParseReport: RFC 9567 report names from untrusted resolvers. No panic;
// errors are one of the two sentinels; an accepted report is internally
// consistent and a rebuilt report name parses back to the same report.
//
//nolint:gocognit // A fuzz target is a flat list of invariants; splitting it only hides them.
func FuzzParseReport(f *testing.F) {
	const agent = "a01.agent.example."
	f.Add("_er.1.broken.test.7._er."+agent, agent, "")
	f.Add("_er.1._badsig.deadbeef.check.example.com.7._er."+agent, agent, "check.example.com.")
	f.Add("_er.1.x.7._er."+agent, "", "")
	f.Add("_er.1.x.7._er."+agent, ".", ".")
	f.Add("_er.99999.x.7._er."+agent, agent, "")
	f.Add("_er.+1.x.7._er."+agent, agent, "")
	f.Add("garbage", agent, "x.")
	for _, s := range stringSeeds(f) {
		f.Add(s, agent, "")
	}
	f.Fuzz(func(t *testing.T, qname, agentDomain, zone string) {
		r, err := ParseReport(qname, agentDomain, zone)
		if err != nil {
			if !errors.Is(err, ErrNotReport) && !errors.Is(err, ErrBadReport) {
				t.Fatalf("unexpected error type: %v", err)
			}
			return
		}
		if r.Qname == "" || r.Qname[len(r.Qname)-1] != '.' {
			t.Fatalf("Qname %q is not fully qualified", r.Qname)
		}
		if r.QtypeName == "" {
			t.Fatal("empty QtypeName")
		}
		if r.Token != "" {
			if tok, ok := parseToken(r.Token); !ok || tok != r.Token {
				t.Fatalf("invalid token %q", r.Token)
			}
		}

		rebuilt := "_er." + itoa(r.Qtype) + "." + r.Qname + itoa(r.EDE) + "._er." + agentDomain
		again, err := ParseReport(rebuilt, agentDomain, zone)
		if err != nil {
			t.Fatalf("rebuilt report %q (from %q) does not parse: %v", rebuilt, qname, err)
		}
		if again.Qtype != r.Qtype || again.EDE != r.EDE || again.Qname != r.Qname || again.Token != r.Token {
			t.Fatalf("round trip of %q: %+v != %+v", qname, again, r)
		}
	})
}

func itoa(n uint16) string { return strconv.Itoa(int(n)) }

// FuzzParseECHConfigList: an ECHConfigList read back from the network. No
// panic; whatever parses and fits our fixed shape rebuilds to something that
// parses to the same fields.
func FuzzParseECHConfigList(f *testing.F) {
	key := bytes.Repeat([]byte{7}, x25519PubKeyLen)
	good, err := BuildECHConfigList(1, key, "example.org")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(good)
	f.Add(good[:len(good)-1])
	f.Add([]byte{})
	f.Add([]byte{0, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		id, pub, name, err := ParseECHConfigList(b)
		if err != nil {
			if id != 0 || pub != nil || name != "" {
				t.Fatalf("error %v with non-zero results", err)
			}
			return
		}
		if len(pub) != x25519PubKeyLen || len(name) > 255 {
			return // Parseable but not a shape Build can produce.
		}
		rebuilt, err := BuildECHConfigList(id, pub, name)
		if err != nil {
			t.Fatalf("Build rejected fields Parse accepted: %v", err)
		}
		id2, pub2, name2, err := ParseECHConfigList(rebuilt)
		if err != nil || id2 != id || !bytes.Equal(pub2, pub) || name2 != name {
			t.Fatalf("round trip mismatch: (%d,%x,%q) -> (%d,%x,%q) err=%v", id, pub, name, id2, pub2, name2, err)
		}
	})
}

// FuzzECHBuildParse: Build then Parse is the identity for every input Build
// accepts, and Build refuses exactly the inputs that cannot be encoded.
func FuzzECHBuildParse(f *testing.F) {
	f.Add(byte(1), bytes.Repeat([]byte{7}, x25519PubKeyLen), "example.org")
	f.Add(byte(0), []byte{}, "")
	f.Add(byte(255), make([]byte, 33), strings.Repeat("a", 256))
	for _, s := range stringSeeds(f) {
		f.Add(byte(1), bytes.Repeat([]byte{7}, x25519PubKeyLen), s)
	}
	f.Fuzz(func(t *testing.T, id byte, pub []byte, name string) {
		list, err := BuildECHConfigList(id, pub, name)
		if err != nil {
			if len(pub) == x25519PubKeyLen && len(name) <= 255 {
				t.Fatalf("Build refused encodable input: %v", err)
			}
			return
		}
		if len(pub) != x25519PubKeyLen || len(name) > 255 {
			t.Fatal("Build accepted an unencodable input")
		}
		id2, pub2, name2, err := ParseECHConfigList(list)
		if err != nil || id2 != id || !bytes.Equal(pub2, pub) || name2 != name {
			t.Fatalf("round trip mismatch: (%d,%x,%q) -> (%d,%x,%q) err=%v", id, pub, name, id2, pub2, name2, err)
		}
	})
}

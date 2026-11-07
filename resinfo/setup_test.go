package resinfo

import (
	"slices"
	"strings"
	"testing"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/miekg/dns"
)

func controller(input string, keys ...string) *caddy.Controller {
	c := caddy.NewTestController("dns", input)
	if len(keys) == 0 {
		keys = []string{"."}
	}
	c.ServerBlockKeys = keys
	return c
}

func TestSetupRegistersHandler(t *testing.T) {
	c := controller("resinfo resolver.example.net {\nqnamemin\n}")
	if err := setup(c); err != nil {
		t.Fatal(err)
	}
	if n := len(dnsserver.GetConfig(c).Plugin); n != 1 {
		t.Fatalf("%d plugins registered", n)
	}
	if err := setup(controller(`resinfo`)); err == nil {
		t.Fatal("setup accepted a block with no name")
	}
}

func TestParse(t *testing.T) {
	cfg, err := parse(controller(`resinfo Resolver.Example.NET resolver.arpa. {
		qnamemin
		exterr 17 15 16 20-22 23
		infourl https://resolver.example.com/guide
		temp-zone home
		temp-flag
		deleg
		ttl 7200
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"resolver.example.net.", "resolver.arpa."}; !slices.Equal(cfg.names, want) {
		t.Errorf("names %q, want %q", cfg.names, want)
	}
	if cfg.ttl != 7200 {
		t.Errorf("ttl %d", cfg.ttl)
	}
	want := []string{
		"deleg",
		"exterr=15-17,20-23",
		"infourl=https://resolver.example.com/guide",
		KeyQNameMin,
		"temp-flag",
		"temp-zone=home",
	}
	if got := cfg.info.Strings(); !slices.Equal(got, want) {
		t.Errorf("RDATA %q, want %q", got, want)
	}
}

// The order of the directives does not change a byte of the RDATA (RFC 9606
// §3: resolvers sharing a name or anycast address "SHOULD expose a consistent
// RESINFO").
func TestParseOrderIndependent(t *testing.T) {
	a, err := parse(controller("resinfo r.example {\nqnamemin\nexterr 15-17\ninfourl https://r.example/\n}"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := parse(controller("resinfo r.example {\ninfourl https://r.example/\nexterr 17 16 15\nqnamemin\n}"))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(a.info.Strings(), b.info.Strings()) {
		t.Fatalf("%q != %q", a.info.Strings(), b.info.Strings())
	}
	if a.ttl != defaultTTL {
		t.Fatalf("default ttl %d", a.ttl)
	}
}

func TestParseRejects(t *testing.T) {
	for name, input := range map[string]string{
		"no name":             "resinfo {\nqnamemin\n}",
		"no keys":             `resinfo r.example`,
		"empty block":         "resinfo r.example {\n}",
		"root name":           "resinfo . {\nqnamemin\n}",
		"bad name":            "resinfo a..b {\nqnamemin\n}",
		"long label":          `resinfo ` + strings.Repeat("a", 64) + ".example {\nqnamemin\n}",
		"name twice":          "resinfo r.example R.EXAMPLE. {\nqnamemin\n}",
		"unknown directive":   "resinfo r.example {\npapersize A4\n}",
		"duplicate key":       "resinfo r.example {\nqnamemin\nqnamemin\n}",
		"duplicate exterr":    "resinfo r.example {\nexterr 15\nexterr 16\n}",
		"duplicate ttl":       "resinfo r.example {\nqnamemin\nttl 1\nttl 2\n}",
		"qnamemin arg":        "resinfo r.example {\nqnamemin yes\n}",
		"deleg arg":           "resinfo r.example {\ndeleg 1\n}",
		"exterr none":         "resinfo r.example {\nexterr\n}",
		"exterr word":         "resinfo r.example {\nexterr blocked\n}",
		"exterr backwards":    "resinfo r.example {\nexterr 17-15\n}",
		"exterr too big":      "resinfo r.example {\nexterr 65536\n}",
		"exterr comma":        "resinfo r.example {\nexterr 15,16\n}",
		"infourl none":        "resinfo r.example {\ninfourl\n}",
		"infourl two":         "resinfo r.example {\ninfourl https://a.example/ https://b.example/\n}",
		"infourl http":        "resinfo r.example {\ninfourl http://r.example/\n}",
		"temp two values":     "resinfo r.example {\ntemp-x a b\n}",
		"temp bad key":        "resinfo r.example {\ntemp-X a\n}",
		"ttl none":            "resinfo r.example {\nqnamemin\nttl\n}",
		"ttl word":            "resinfo r.example {\nqnamemin\nttl soon\n}",
		"ttl negative":        "resinfo r.example {\nqnamemin\nttl -1\n}",
		"ttl over 2^31-1":     "resinfo r.example {\nqnamemin\nttl 2147483648\n}",
		"second block":        "resinfo r.example {\nqnamemin\n}\nresinfo s.example {\nqnamemin\n}",
		"temp value too long": "resinfo r.example {\ntemp-x " + strings.Repeat("v", 250) + "\n}",
	} {
		if _, err := parse(controller(input)); err == nil {
			t.Errorf("%s: accepted %q", name, input)
		}
	}
}

func TestParseNameOutsideServerBlock(t *testing.T) {
	if _, err := parse(controller("resinfo resolver.example.net {\nqnamemin\n}", "dns://example.org.:53")); err == nil {
		t.Fatal("accepted a name no query to this server block can reach")
	}
	if _, err := parse(controller("resinfo resolver.example.net {\nqnamemin\n}", "dns://example.net.:53")); err != nil {
		t.Fatalf("rejected a name inside the block's zone: %v", err)
	}
	if _, err := parse(controller("resinfo resolver.arpa {\nqnamemin\n}", "dns://resolver.arpa.:53")); err != nil {
		t.Fatalf("rejected resolver.arpa in its own zone: %v", err)
	}
}

// The README's example, under its tls:// server block key, publishes the
// record the README shows.
func TestReadmeExample(t *testing.T) {
	cfg, err := parse(controller(`resinfo resolver.example.net resolver.arpa {
		qnamemin
		exterr 15 16 17
		infourl https://resolver.example.com/guide
		ttl 7200
	}`, "tls://.:853"))
	if err != nil {
		t.Fatal(err)
	}
	r := newResInfo(cfg.names, cfg.info, cfg.ttl)
	m := r.reply(query("resolver.example.net.", dns.TypeRESINFO))
	const want = "resolver.example.net.\t7200\tIN\tRESINFO\t\"exterr=15-17\" \"infourl=https://resolver.example.com/guide\" \"qnamemin\""
	if got := m.Answer[0].String(); got != want {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
}

func TestParseTTLBounds(t *testing.T) {
	for in, want := range map[string]uint32{"0": 0, "2147483647": maxTTL} {
		got, err := parseTTL([]string{in})
		if err != nil || got != want {
			t.Errorf("parseTTL(%s) = %d, %v", in, got, err)
		}
	}
}

func TestLargeRDATAWarnsButLoads(t *testing.T) {
	var b strings.Builder
	b.WriteString("resinfo r.example {\n")
	for _, k := range []string{"a", "b", "c", "d", "e", "f"} {
		b.WriteString("temp-" + k + " " + strings.Repeat("v", 240) + "\n")
	}
	b.WriteString("}")
	cfg, err := parse(controller(b.String()))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.info.WireLen() <= warnRDATA {
		t.Fatalf("test RDATA is only %d octets", cfg.info.WireLen())
	}
}

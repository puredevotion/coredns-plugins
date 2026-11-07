package geoscore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
)

func parseCorefile(t *testing.T, input string) (*GeoScore, error) {
	t.Helper()
	return parse(caddy.NewTestController("dns", input), testZone)
}

func TestParseFull(t *testing.T) {
	h, err := parseCorefile(t, `geoscore WWW {
		endpoint eu1 192.0.2.1 2001:db8::1
		endpoint us1 192.0.2.2
		store memory
		key lab:www
		mode weighted
		max-staleness 2m
		ttl 20
		fallback nodata
		refresh 2s
		timeout 50ms
		rationale-txt
	}
	geoscore api {
		endpoint a 198.51.100.1
		store memory
	}`)
	if err != nil {
		t.Fatal(err)
	}
	if len(h.instances) != 2 {
		t.Fatalf("%d instances", len(h.instances))
	}
	c := h.instances[0].cfg
	if c.Name != testName || c.KeyPrefix != "lab:www" || c.Mode != ModeWeighted || c.MaxStaleness != 2*time.Minute ||
		c.TTL != 20 || c.Fallback != FallbackNodata || c.Refresh != 2*time.Second || c.Timeout != 50*time.Millisecond ||
		!c.RationaleTXT || len(c.Endpoints) != 2 || len(c.Endpoints[0].Addrs) != 2 {
		t.Fatalf("parsed %+v", c)
	}
	d := h.instances[1].cfg
	if d.Name != "api.example.com." || d.KeyPrefix != "geoscore:api.example.com" || d.Mode != ModeBest || d.Fallback != FallbackStatic || d.TTL != defaultTTL {
		t.Fatalf("defaults: %+v", d)
	}
}

func TestParseRejects(t *testing.T) {
	const ep = "endpoint eu1 192.0.2.1\n"
	for name, body := range map[string]string{
		"no name":             "geoscore {\n" + ep + "store memory\n}",
		"two names":           "geoscore a b {\n" + ep + "store memory\n}",
		"no store":            "geoscore www {\n" + ep + "}",
		"no endpoint":         "geoscore www {\nstore memory\n}",
		"unknown property":    "geoscore www {\n" + ep + "store memory\nweight 3\n}",
		"duplicate mode":      "geoscore www {\n" + ep + "store memory\nmode best\nmode best\n}",
		"bad mode":            "geoscore www {\n" + ep + "store memory\nmode random\n}",
		"bad fallback":        "geoscore www {\n" + ep + "store memory\nfallback next\n}",
		"bad store":           "geoscore www {\n" + ep + "store redis 192.0.2.9:6379\n}",
		"memory with addr":    "geoscore www {\n" + ep + "store memory 192.0.2.9:6379\n}",
		"valkey no addr":      "geoscore www {\n" + ep + "store valkey\n}",
		"valkey no tls":       "geoscore www {\n" + ep + "store valkey 192.0.2.9:6379\n}",
		"tls_ca on memory":    "geoscore www {\n" + ep + "store memory\ntls_ca /nonexistent\n}",
		"bad address":         "geoscore www {\nendpoint eu1 192.0.2.300\nstore memory\n}",
		"endpoint no addr":    "geoscore www {\nendpoint eu1\nstore memory\n}",
		"bad duration":        "geoscore www {\n" + ep + "store memory\nmax-staleness soon\n}",
		"ttl over staleness":  "geoscore www {\n" + ep + "store memory\nmax-staleness 10s\nttl 11\n}",
		"ttl over 2^31":       "geoscore www {\n" + ep + "store memory\nttl 2147483648\n}",
		"ttl negative":        "geoscore www {\n" + ep + "store memory\nttl -1\n}",
		"rationale arg":       "geoscore www {\n" + ep + "store memory\nrationale-txt yes\n}",
		"key two args":        "geoscore www {\n" + ep + "store memory\nkey a b\n}",
		"outside zone":        "geoscore www.example.net. {\n" + ep + "store memory\n}",
		"same name twice":     "geoscore www {\n" + ep + "store memory\n}\ngeoscore WWW {\n" + ep + "store memory\n}",
		"name is a rationale": "geoscore www {\n" + ep + "store memory\nrationale-txt\n}\ngeoscore _geoscore.www {\n" + ep + "store memory\n}",
		"rationale is a name": "geoscore _geoscore.www {\n" + ep + "store memory\n}\ngeoscore www {\n" + ep + "store memory\nrationale-txt\n}",
	} {
		if _, err := parseCorefile(t, body); err == nil {
			t.Errorf("%s: accepted\n%s", name, body)
		}
	}
}

// The CA is read before any connection is attempted: a missing or empty CA
// file fails startup.
func TestParseValkeyCA(t *testing.T) {
	empty := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(empty, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, ca := range []string{"/nonexistent/ca.pem", empty} {
		in := "geoscore www {\nendpoint eu1 192.0.2.1\nstore valkey 192.0.2.9:6379\ntls_ca " + ca + "\n}"
		if _, err := parseCorefile(t, in); err == nil || !strings.Contains(err.Error(), "CA") {
			t.Errorf("tls_ca %s: %v", ca, err)
		}
	}
	if _, err := NewValkeyStore(ValkeyConfig{}); err == nil {
		t.Error("NewValkeyStore without addresses")
	}
}

func TestSetupRegistersHandler(t *testing.T) {
	c := caddy.NewTestController("dns", "geoscore www {\nendpoint eu1 192.0.2.1\nstore memory\n}")
	dnsserver.GetConfig(c).Zone = testZone
	if err := setup(c); err != nil {
		t.Fatal(err)
	}
	if n := len(dnsserver.GetConfig(c).Plugin); n != 1 {
		t.Fatalf("%d plugins registered", n)
	}
	c = caddy.NewTestController("dns", "geoscore www {\nstore memory\n}")
	dnsserver.GetConfig(c).Zone = testZone
	if err := setup(c); err == nil {
		t.Fatal("setup accepted a block with no endpoint")
	}
}

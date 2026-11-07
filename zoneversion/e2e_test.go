package zoneversion

import (
	"net"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	_ "github.com/coredns/coredns/plugin/bind" // Listen on loopback only.
	_ "github.com/coredns/coredns/plugin/file" // The zone the plugin versions.
	"github.com/miekg/dns"
)

const (
	e2eSerial = 2026110701
	e2eWWW    = "www.example.com."
	e2eNX     = "nx.example.com."
)

const e2eZone = `$ORIGIN example.com.
@   3600 IN SOA ns1.example.com. hostmaster.example.com. 2026110701 7200 3600 1209600 300
@   3600 IN NS  ns1.example.com.
ns1 3600 IN A   192.0.2.53
www 3600 IN A   192.0.2.1
`

// startCoreDNS runs a real CoreDNS server (caddy + dnsserver, the same code
// path as the coredns binary) with `zoneversion` in front of `file`, on
// loopback ports picked by the kernel. It returns the UDP and TCP addresses.
func startCoreDNS(t *testing.T) (udp, tcp string) {
	t.Helper()
	if !slices.Contains(dnsserver.Directives, pluginName) {
		// The plugin.cfg position: immediately after transfer (README).
		i := slices.Index(dnsserver.Directives, "transfer")
		if i < 0 {
			t.Fatal("no transfer directive in dnsserver.Directives")
		}
		dnsserver.Directives = slices.Insert(dnsserver.Directives, i+1, pluginName)
	}
	db := filepath.Join(t.TempDir(), "db.example.com")
	if err := os.WriteFile(db, []byte(e2eZone), 0o600); err != nil {
		t.Fatal(err)
	}
	corefile := "example.com:0 {\n\tbind 127.0.0.1\n\tzoneversion\n\tfile " + db + "\n}\n"
	inst, err := caddy.Start(caddy.CaddyfileInput{Contents: []byte(corefile), Filepath: "Corefile", ServerTypeName: "dns"})
	if err != nil {
		t.Fatalf("start CoreDNS: %v", err)
	}
	t.Cleanup(func() {
		if serr := inst.Stop(); serr != nil {
			t.Errorf("stop: %v", serr)
		}
	})
	srvs := inst.Servers()
	if len(srvs) != 1 {
		t.Fatalf("%d servers, want 1", len(srvs))
	}
	u, okU := srvs[0].LocalAddr().(*net.UDPAddr)
	a, okT := srvs[0].Addr().(*net.TCPAddr)
	if !okU || !okT {
		t.Fatalf("listeners %v / %v", srvs[0].LocalAddr(), srvs[0].Addr())
	}
	return u.String(), a.String()
}

// TestCoreDNSEndToEnd: a stock miekg/dns client sends the conformant empty
// option (EDNS0_ZONEVERSION{Empty: true} packs to OPTION-LENGTH 0) to a real
// CoreDNS server over UDP and TCP and gets the zone file's SOA serial back.
// With upstream miekg/dns v1.1.73 the server itself answered FORMERR.
func TestCoreDNSEndToEnd(t *testing.T) {
	udp, tcp := startCoreDNS(t)
	for _, tc := range []struct{ net, addr string }{{"udp", udp}, {"tcp", tcp}} {
		t.Run(tc.net, func(t *testing.T) {
			c := &dns.Client{Net: tc.net}
			for _, qc := range []struct {
				name  string
				qtype uint16
				rcode int
			}{
				{e2eWWW, dns.TypeA, dns.RcodeSuccess},
				{e2eWWW, dns.TypeAAAA, dns.RcodeSuccess}, // NODATA.
				{e2eNX, dns.TypeA, dns.RcodeNameError},
			} {
				r := e2eExchange(t, c, tc.addr, query(qc.name, qc.qtype, emptyOption()))
				if r.Rcode != qc.rcode || !r.Authoritative {
					t.Fatalf("%s %s: rcode %s aa=%v, want %s aa", qc.name, dns.TypeToString[qc.qtype],
						dns.RcodeToString[r.Rcode], r.Authoritative, dns.RcodeToString[qc.rcode])
				}
				wantVersion(t, r, e2eSerial)
				if s := versionOf(r)[0].String(); s != "2 SOA-SERIAL 2026110701" {
					t.Fatalf("presentation %q", s)
				}
			}

			// A query that did not ask gets no option (RFC 9660 §3.2.2).
			wantNoVersion(t, e2eExchange(t, c, tc.addr, query(e2eWWW, dns.TypeA)))

			// The zero-value struct sends two octets: FORMERR (§3.2.1).
			r := e2eExchange(t, c, tc.addr, query(e2eWWW, dns.TypeA, &dns.EDNS0_ZONEVERSION{Code: dns.EDNS0ZONEVERSION}))
			if r.Rcode != dns.RcodeFormatError {
				t.Fatalf("two-octet option: rcode %s, want FORMERR", dns.RcodeToString[r.Rcode])
			}
			wantNoVersion(t, r)
		})
	}
}

func e2eExchange(t *testing.T, c *dns.Client, addr string, q *dns.Msg) *dns.Msg {
	t.Helper()
	r, _, err := c.ExchangeContext(t.Context(), q, addr)
	if err != nil {
		t.Fatalf("%s: %v", q.Question[0].Name, err)
	}
	return r
}

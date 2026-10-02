package dynupdate

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// newBenchPlugin builds a plugin serving the seed zone plus n extra A records,
// so the UPDATE path can be measured against a zone of realistic size rather
// than the seven-record fixture the unit tests use.
func newBenchPlugin(b *testing.B, n int) *DynUpdate {
	b.Helper()
	var sb strings.Builder
	sb.WriteString(seedZone)
	for i := range n {
		fmt.Fprintf(&sb, "host%d A 192.0.2.%d\n", i, i%250+1)
	}
	path := filepath.Join(b.TempDir(), "db.example.org")
	if err := os.WriteFile(path, []byte(sb.String()), 0o600); err != nil {
		b.Fatal(err)
	}
	rrs, err := readZone(path, testZone)
	if err != nil {
		b.Fatalf("readZone: %v", err)
	}
	d := &DynUpdate{Zone: testZone, rrs: rrs}
	if err := d.swap(rrs); err != nil {
		b.Fatalf("swap: %v", err)
	}
	return d
}

func benchRR(b *testing.B, s string) dns.RR {
	b.Helper()
	r, err := dns.NewRR(s)
	if err != nil {
		b.Fatal(err)
	}
	return r
}

// BenchmarkUpdate measures one ACME-shaped transaction: a "name not in use"
// prerequisite, then add a TXT, against zones of increasing size. The
// documented design is O(zone) per update; this pins how steep that line is.
func BenchmarkUpdate(b *testing.B) {
	for _, n := range []int{10, 1000, 10000} {
		b.Run("records="+strconv.Itoa(n), func(b *testing.B) {
			d := newBenchPlugin(b, n)
			add := benchRR(b, "_acme-challenge.example.org. 60 IN TXT \"token\"")
			del := benchRR(b, "_acme-challenge.example.org. 0 NONE TXT \"token\"")
			// "Name is not in use" before the add, "name is in use" before the
			// delete: the §3.2 forms an ACME client actually sends.
			steps := []struct{ prereq, update dns.RR }{
				{prereqNameInUse("_acme-challenge.example.org.", dns.ClassNONE), add},
				{prereqNameInUse("_acme-challenge.example.org.", dns.ClassANY), del},
			}
			ctx := context.Background()
			b.ReportAllocs()
			for b.Loop() {
				// Add then delete, so the zone is the same size on every
				// iteration and the benchmark measures a steady state.
				for _, step := range steps {
					m := newUpdate([]dns.RR{step.prereq}, []dns.RR{step.update})
					w := &testWriter{tsigOK: true}
					if _, err := d.ServeDNS(ctx, w, m); err != nil {
						b.Fatal(err)
					}
					if w.msg.Rcode != dns.RcodeSuccess {
						b.Fatalf("rcode %s", dns.RcodeToString[w.msg.Rcode])
					}
				}
			}
		})
	}
}

// BenchmarkPrereqRRsetEquals is the value-dependent prerequisite (RFC 2136
// §3.2.3), the one that compares whole RRsets by RDATA.
func BenchmarkPrereqRRsetEquals(b *testing.B) {
	d := newBenchPlugin(b, 1000)
	prereq := benchRR(b, "www.example.org. 0 IN A 192.0.2.10")
	noop := benchRR(b, "www.example.org. 300 IN A 192.0.2.10") // Identical record: NOERROR, no change.
	ctx := context.Background()
	b.ReportAllocs()
	for b.Loop() {
		m := newUpdate([]dns.RR{prereq}, []dns.RR{noop})
		w := &testWriter{tsigOK: true}
		if _, err := d.ServeDNS(ctx, w, m); err != nil {
			b.Fatal(err)
		}
		if w.msg.Rcode != dns.RcodeSuccess {
			b.Fatalf("rcode %s", dns.RcodeToString[w.msg.Rcode])
		}
	}
}

// BenchmarkQuery is the read path, which is CoreDNS's own file plugin behind
// an RWMutex; here as the control the UPDATE numbers are read against.
func BenchmarkQuery(b *testing.B) {
	d := newBenchPlugin(b, 1000)
	m := new(dns.Msg)
	m.SetQuestion("host500.example.org.", dns.TypeA)
	ctx := context.Background()
	b.ReportAllocs()
	for b.Loop() {
		w := &testWriter{}
		if _, err := d.ServeDNS(ctx, w, m); err != nil {
			b.Fatal(err)
		}
	}
}

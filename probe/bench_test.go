package probe

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"
	"github.com/miekg/dns"
)

// Benchmarks for the per-query path. Every function here runs once per
// inbound packet on a zone that answers the public internet behind rate
// limiting, so the budget that matters is the per-query one: allocations and
// lock hold time, not throughput of any single call in isolation.
//
// Run with:
//
//	go test -run=NONE -bench=. -benchmem ./...
//
// and compare two revisions with benchstat. The numbers these were written
// against are kept in docs/performance.md.

// benchVisitor is the per-visitor label every benchmark query carries: a
// valid 16-hex-digit probe label, the shape catalog.NewToken hands out.
const benchVisitor = "a1b2c3d4e5f60718"

// benchWriter is a ResponseWriter whose addresses are fixed values. The
// coredns test writer parses its address on every RemoteAddr call, which
// costs four allocations per query that production never pays, and would
// otherwise be a third of what the end-to-end benchmark measures.
type benchWriter struct {
	remote net.Addr
	local  net.Addr
	test.ResponseWriter
}

func newBenchWriter() *benchWriter {
	return &benchWriter{
		remote: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 53), Port: 40212},
		local:  &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 53},
	}
}

func (w *benchWriter) RemoteAddr() net.Addr { return w.remote }
func (w *benchWriter) LocalAddr() net.Addr  { return w.local }

// benchQuery builds a probe query with the EDNS state a modern validating
// resolver sends: DO, a cookie, and an ECS /24 disclosure.
func benchQuery(qname string, qtype uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(qname, qtype)
	m.SetEdns0(1232, true)
	opt := m.IsEdns0()
	opt.Option = append(opt.Option,
		&dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: "0123456789abcdef"},
		&dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: 24, Address: net.IPv4(192, 0, 2, 0)},
	)
	return m
}

func BenchmarkParseQuery(b *testing.B) {
	cases := []struct{ name, sub string }{
		{"baseline", benchVisitor},
		{"one-mod", "_unsigned." + benchVisitor},
		{"three-mods", "_badsig._truncate._big." + benchVisitor},
		{"mixed-case", "_BadSig._TRUNCATE.A1B2C3D4E5F60718"},
		{"refused", "foo." + benchVisitor},
	}
	for _, c := range cases {
		b.Run(c.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				ParseQuery(c.sub)
			}
		})
	}
}

func BenchmarkObserve(b *testing.B) {
	q := Query{Token: benchVisitor, Mods: ModBadSig | ModBig}
	msg := benchQuery("_badsig._big."+benchVisitor+"."+testZone, dns.TypeTXT)
	addr := netip.MustParseAddr("192.0.2.53")
	b.ReportAllocs()
	for b.Loop() {
		Observe(q, "_BaDsIg._bIg.A1b2C3d4e5F60718."+testZone, addr, TransportUDP, dns.TypeTXT, msg)
	}
}

func BenchmarkSummary(b *testing.B) {
	q := Query{Token: benchVisitor, Mods: ModBadSig}
	msg := benchQuery(benchVisitor+"."+testZone, dns.TypeTXT)
	obs := Observe(q, benchVisitor+"."+testZone, netip.MustParseAddr("192.0.2.53"), TransportTLS, dns.TypeTXT, msg)
	obs.TLS = &TLSInfo{Version: "TLS 1.3", NamedGroup: "X25519MLKEM768"}
	obs.Seen = 3
	b.ReportAllocs()
	for b.Loop() {
		_ = obs.Summary()
	}
}

func BenchmarkRecordMetrics(b *testing.B) {
	q := Query{Token: benchVisitor}
	msg := benchQuery(benchVisitor+"."+testZone, dns.TypeA)
	obs := Observe(q, benchVisitor+"."+testZone, netip.MustParseAddr("192.0.2.53"), TransportUDP, dns.TypeA, msg)
	b.ReportAllocs()
	for b.Loop() {
		recordMetrics(&obs)
	}
}

func BenchmarkSignRRset(b *testing.B) {
	s := newTestSigner(b, time.Hour)
	rrs := testRRset()
	for _, c := range []struct {
		name string
		mods Modifier
	}{{"correct", 0}, {"badsig", ModBadSig}, {"expired-window", ModExpiredSig}} {
		b.Run(c.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, _, err := s.signRRset(rrs, c.mods); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkSignFloor is the cost of the signature alone, over a 32-byte
// digest: the test key's ECDSA P-256, and Ed25519 beside it. Everything
// signRRset spends above the P-256 line is overhead this plugin or miekg/dns
// adds; everything up to it is the algorithm the operator chose, and the
// Ed25519 line is what choosing differently would buy.
func BenchmarkSignFloor(b *testing.B) {
	digest := sha256.Sum256([]byte(benchVisitor + "." + testZone))
	b.Run("ecdsa-p256", func(b *testing.B) {
		s := newTestSigner(b, time.Hour)
		b.ReportAllocs()
		for b.Loop() {
			if _, err := s.priv.Sign(rand.Reader, digest[:], crypto.SHA256); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("ed25519", func(b *testing.B) {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			b.Fatal(err)
		}
		b.ReportAllocs()
		for b.Loop() {
			// Ed25519 signs the message itself (RFC 8080 §4 feeds it the
			// RRset wire data), so crypto.Hash(0).
			if _, err := priv.Sign(rand.Reader, digest[:], crypto.Hash(0)); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkMemStoreRecord fills the store to a realistic working set first:
// the cost that matters is Record with thousands of live tokens, not Record
// on an empty map.
func BenchmarkMemStoreRecord(b *testing.B) {
	for _, live := range []int{0, 1000, 10000} {
		b.Run("live="+strconv.Itoa(live), func(b *testing.B) {
			s := NewMemStore(10*time.Minute, live+16, 64)
			now := time.Now().UTC()
			for i := range live {
				obs := Observation{Token: strconv.FormatInt(int64(i), 16) + "deadbeef", At: now}
				if _, err := s.Record(&obs); err != nil {
					b.Fatal(err)
				}
			}
			obs := Observation{Token: benchVisitor, At: now}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				obs.At = now
				if _, err := s.Record(&obs); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkServeDNS is the end-to-end number: a packet in, a packet out,
// through the real handler with a real (in-memory) store and a real signer.
func BenchmarkServeDNS(b *testing.B) {
	cases := []struct {
		name   string
		qname  string
		qtype  uint16
		signed bool
	}{
		{"A/unsigned", benchVisitor + "." + testZone, dns.TypeA, false},
		{"A/signed", benchVisitor + "." + testZone, dns.TypeA, true},
		{"TXT/signed", benchVisitor + "." + testZone, dns.TypeTXT, true},
		{"TXT/big/signed", "_big." + benchVisitor + "." + testZone, dns.TypeTXT, true},
		{"nxname/signed", "_nxname." + benchVisitor + "." + testZone, dns.TypeA, true},
		{"refused", "foo." + benchVisitor + "." + testZone, dns.TypeA, false},
		{"not-our-zone", "www.example.net.", dns.TypeA, false},
	}
	for _, c := range cases {
		b.Run(c.name, func(b *testing.B) {
			p := &Probe{
				Zone:    testZone,
				TTL:     10,
				NSName:  "ns." + testZone,
				Mbox:    "hostmaster." + testZone,
				Store:   NewMemStore(10*time.Minute, 10000, 64),
				BigSize: defaultBigSize,
				Next:    test.NextHandler(dns.RcodeRefused, nil),
			}
			if c.signed {
				p.Signer = newTestSigner(b, time.Hour)
			}
			msg := benchQuery(c.qname, c.qtype)
			ctx := context.Background()
			b.ReportAllocs()
			for b.Loop() {
				rec := dnstest.NewRecorder(newBenchWriter())
				if _, err := p.ServeDNS(ctx, rec, msg); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

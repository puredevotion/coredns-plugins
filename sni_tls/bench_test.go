package snitls

import (
	"crypto/tls"
	"testing"
)

// BenchmarkGetCertificate is the per-handshake cost of certificate selection.
// It sits inside crypto/tls's handshake, so it is small next to the key
// exchange, but it is also the one piece of this plugin on every connection
// and it must not allocate for the common lowercase exact match.
func BenchmarkGetCertificate(b *testing.B) {
	primaryCert, primaryKey := writeTestCert(b, "primary", testSNIPrimary)
	wildCert, wildKey := writeTestCert(b, "wild", "*.example.net")
	secondaryCert, secondaryKey := writeTestCert(b, "secondary", testSNISecondary)
	store, err := buildCertStore(storeConfig{pairs: [][2]string{
		{primaryCert, primaryKey}, {wildCert, wildKey}, {secondaryCert, secondaryKey},
	}})
	if err != nil {
		b.Fatal(err)
	}
	strict := *store
	strict.strict = true

	cases := []struct {
		name  string
		store *certStore
		sni   string
	}{
		{"exact", store, testSNIPrimary},
		{"exact-mixed-case", store, "DNS.Example.COM"},
		{"wildcard", store, "dot.example.net"},
		{"absent-sni", store, ""},
		{"unmatched-fallback", store, testSNIUnknown},
		{"unmatched-strict", &strict, testSNIUnknown},
	}
	for _, c := range cases {
		b.Run(c.name, func(b *testing.B) {
			hello := &tls.ClientHelloInfo{ServerName: c.sni}
			b.ReportAllocs()
			for b.Loop() {
				if _, err := c.store.GetCertificate(hello); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

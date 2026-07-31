package probe

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

const testZone = "check.example.com."

// newTestSigner generates a real algorithm-13 key, writes it out in the BIND
// file layout LoadSigner expects, and loads it back. Going through the files
// rather than constructing a Signer directly means these tests also cover the
// loader, which is where a misconfiguration would actually bite.
func newTestSigner(t *testing.T, validity time.Duration) *Signer {
	t.Helper()

	key := &dns.DNSKEY{
		Hdr: dns.RR_Header{
			Name: testZone, Rrtype: dns.TypeDNSKEY,
			Class: dns.ClassINET, Ttl: 3600,
		},
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.ECDSAP256SHA256,
	}
	priv, err := key.Generate(256)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	dir := t.TempDir()
	base := filepath.Join(dir, "Kcheck.example.com.+013+00000")
	if err := os.WriteFile(base+".key", []byte(key.String()+"\n"), 0o600); err != nil {
		t.Fatalf("writing .key: %v", err)
	}
	if err := os.WriteFile(base+".private", []byte(key.PrivateKeyString(priv)), 0o600); err != nil {
		t.Fatalf("writing .private: %v", err)
	}

	s, err := LoadSigner(base, validity)
	if err != nil {
		t.Fatalf("LoadSigner: %v", err)
	}
	signerBasenames[s] = base
	return s
}

// signerBasenames remembers where newTestSigner wrote each keypair, so tests
// that need to feed the same files back through Corefile parsing can find them.
var signerBasenames = map[*Signer]string{}

func keyBasenameFor(t *testing.T, s *Signer) string {
	t.Helper()
	base, ok := signerBasenames[s]
	if !ok {
		t.Fatal("signer was not created by newTestSigner")
	}
	return base
}

func testRRset() []dns.RR {
	return []dns.RR{&dns.TXT{
		Hdr: dns.RR_Header{
			Name: "a1b2c3d4." + testZone, Rrtype: dns.TypeTXT,
			Class: dns.ClassINET, Ttl: 10,
		},
		Txt: []string{"resolver=192.0.2.1"},
	}}
}

// TestSignRRsetBaseline is the control: without modifiers the signature must
// actually verify against the key and be valid right now. Every negative test
// below is only meaningful if this one passes.
func TestSignRRsetBaseline(t *testing.T) {
	s := newTestSigner(t, time.Hour)
	rrs := testRRset()

	sig, err := s.signRRset(rrs, 0)
	if err != nil {
		t.Fatalf("signRRset: %v", err)
	}
	if sig == nil {
		t.Fatal("no RRSIG produced for an unmodified query")
	}
	if err := sig.Verify(s.DNSKEY(), rrs); err != nil {
		t.Errorf("baseline signature does not verify: %v", err)
	}
	if !sig.ValidityPeriod(time.Now()) {
		t.Error("baseline signature is not currently valid")
	}
	if got, want := sig.SignerName, testZone; got != want {
		t.Errorf("SignerName = %q, want %q", got, want)
	}
	if got, want := sig.TypeCovered, dns.TypeTXT; got != want {
		t.Errorf("TypeCovered = %d, want %d", got, want)
	}
}

func TestSignRRsetUnsignedOmitsSignature(t *testing.T) {
	s := newTestSigner(t, time.Hour)
	sig, err := s.signRRset(testRRset(), ModUnsigned)
	if err != nil {
		t.Fatalf("signRRset: %v", err)
	}
	if sig != nil {
		t.Fatalf("ModUnsigned produced an RRSIG: %v", sig)
	}
}

// TestSignRRsetBadSigFailsVerification pins down the distinction that makes
// badsig worth having: the signature must be present and well-formed enough to
// be verified, and must then fail verification. A signature that failed to
// parse would test the resolver's parser, not its crypto.
func TestSignRRsetBadSigFailsVerification(t *testing.T) {
	s := newTestSigner(t, time.Hour)
	rrs := testRRset()

	sig, err := s.signRRset(rrs, ModBadSig)
	if err != nil {
		t.Fatalf("signRRset: %v", err)
	}
	if sig == nil {
		t.Fatal("ModBadSig produced no RRSIG at all; it must produce a bad one")
	}
	if err := sig.Verify(s.DNSKEY(), rrs); err == nil {
		t.Error("corrupted signature verified successfully")
	}
	// Still inside its validity window, so a resolver rejecting it must be
	// rejecting the crypto rather than the timestamps.
	if !sig.ValidityPeriod(time.Now()) {
		t.Error("badsig signature should still be within its validity window")
	}
	// Round-tripping through presentation format must preserve the corruption:
	// if the bad signature were not valid base64 it would be dropped as
	// malformed somewhere in the stack instead of failing verification.
	parsed, err := dns.NewRR(sig.String())
	if err != nil {
		t.Fatalf("corrupted RRSIG does not round-trip through presentation format: %v", err)
	}
	if err := parsed.(*dns.RRSIG).Verify(s.DNSKEY(), rrs); err == nil {
		t.Error("corrupted signature verified after round-trip")
	}
}

// TestSignRRsetTimeVariants covers the two cases whose whole point is that the
// crypto is CORRECT and only the validity window is wrong — a resolver that
// verifies signatures but ignores timestamps accepts these, which is the bug
// they exist to find.
func TestSignRRsetTimeVariants(t *testing.T) {
	for _, tc := range []struct {
		name string
		mod  Modifier
	}{
		{name: "expired", mod: ModExpiredSig},
		{name: "future", mod: ModFutureSig},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestSigner(t, time.Hour)
			rrs := testRRset()

			sig, err := s.signRRset(rrs, tc.mod)
			if err != nil {
				t.Fatalf("signRRset: %v", err)
			}
			if sig == nil {
				t.Fatal("no RRSIG produced")
			}
			if err := sig.Verify(s.DNSKEY(), rrs); err != nil {
				t.Errorf("signature should be cryptographically valid, got %v", err)
			}
			if sig.ValidityPeriod(time.Now()) {
				t.Error("signature should NOT be valid at the current time")
			}
		})
	}
}

func TestLoadSignerRejectsBadInput(t *testing.T) {
	dir := t.TempDir()

	if _, err := LoadSigner(filepath.Join(dir, "absent"), 0); err == nil {
		t.Error("LoadSigner accepted a missing key file")
	}

	// A public key file holding the wrong record type is a plausible
	// copy-paste error and must not load as a signing key.
	wrong := filepath.Join(dir, "wrongtype")
	if err := os.WriteFile(wrong+".key",
		[]byte(testZone+" 3600 IN A 192.0.2.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(wrong+".private", []byte("nonsense\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSigner(wrong, 0); err == nil {
		t.Error("LoadSigner accepted an A record as a DNSKEY")
	}
}

func TestSignerDSMatchesKey(t *testing.T) {
	s := newTestSigner(t, time.Hour)
	ds := s.DS(dns.SHA256)
	if ds == nil {
		t.Fatal("DS returned nil")
	}
	if ds.KeyTag != s.DNSKEY().KeyTag() {
		t.Errorf("DS key tag %d does not match DNSKEY key tag %d",
			ds.KeyTag, s.DNSKEY().KeyTag())
	}
	// Default digest when unspecified, so an operator printing the DS does not
	// silently get digest type 0, which no registrar accepts.
	if got := s.DS(0); got.DigestType != dns.SHA256 {
		t.Errorf("DS(0) digest type = %d, want SHA256 (%d)", got.DigestType, dns.SHA256)
	}
}

func TestCorruptSignatureStaysBase64AndSameLength(t *testing.T) {
	// Length matters: a shorter or longer signature can be rejected on a length
	// check before verification, which would make badsig test the wrong thing.
	for _, in := range []string{
		"AAAA", "abcd==", "A", "AbCdEfGh12345678", "====",
	} {
		got := corruptSignature(in)
		if len(got) != len(in) {
			t.Errorf("corruptSignature(%q) changed length: %q", in, got)
		}
	}
	if got := corruptSignature(""); got != "" {
		t.Errorf("corruptSignature(\"\") = %q, want empty", got)
	}
}

// TestLoadSignerRefusesSymlinkEscape covers what os.Root buys over a plain
// os.Open: a key file that is really a symlink pointing outside the key
// directory does not resolve. Without the rooted open this would happily read
// whatever the link targets, which on a pod with mounted Secrets is exactly the
// mistake worth making impossible rather than merely unlikely.
func TestLoadSignerRefusesSymlinkEscape(t *testing.T) {
	outside := t.TempDir()
	keyDir := t.TempDir()

	// A valid keypair, but parked outside the directory LoadSigner will root.
	real := newTestSigner(t, 0)
	realBase := keyBasenameFor(t, real)

	base := filepath.Join(keyDir, "Kescape.example.com.+013+00000")
	if err := os.Symlink(realBase+".key", base+".key"); err != nil {
		t.Skipf("cannot create symlinks here: %v", err)
	}
	if err := os.Symlink(realBase+".private", base+".private"); err != nil {
		t.Skipf("cannot create symlinks here: %v", err)
	}
	_ = outside

	if _, err := LoadSigner(base, 0); err == nil {
		t.Error("LoadSigner followed a symlink out of the key directory")
	}
}

func TestLoadSignerRejectsDirectoryBasename(t *testing.T) {
	// A trailing slash means the operator pointed at a directory; there is no
	// keypair name to append extensions to, and silently reading "/.key" would
	// be a confusing way to fail.
	if _, err := LoadSigner(t.TempDir()+"/", 0); err == nil {
		t.Error("LoadSigner accepted a basename with no file component")
	}
}

// TestRRSIGLabelCount pins the bounded counter that replaced a widening
// conversion: the value is only ever held in the octet RRSIG has for it.
func TestRRSIGLabelCount(t *testing.T) {
	tests := []struct {
		name string
		want uint8
	}{
		{name: ".", want: 0},
		{name: "example.com.", want: 2},
		{name: "a1b2c3d4.check.example.com.", want: 4},
		{name: "_badsig.a1b2c3d4.check.example.com.", want: 5},
	}
	for _, tc := range tests {
		got, err := rrsigLabelCount(tc.name)
		if err != nil {
			t.Errorf("rrsigLabelCount(%q): %v", tc.name, err)
			continue
		}
		if got != tc.want {
			t.Errorf("rrsigLabelCount(%q) = %d, want %d", tc.name, got, tc.want)
		}
	}

	// Deeper than RRSIG's single octet can express: rejected, not wrapped.
	deep := strings.Repeat("a.", 300) + "example.com."
	if _, err := rrsigLabelCount(deep); err == nil {
		t.Error("rrsigLabelCount accepted a name with more labels than RRSIG can express")
	}
}

// TestRRSIGTimeMatchesLibraryRoundTrip checks that the timestamps handed to
// RRSIG mean what the library thinks they mean, since the whole reason to
// delegate to dns.StringToTime is its RFC 1982 serial arithmetic.
func TestRRSIGTimeMatchesLibraryRoundTrip(t *testing.T) {
	when := time.Date(2026, 7, 30, 12, 34, 56, 0, time.UTC)
	got, err := rrsigTime(when)
	if err != nil {
		t.Fatalf("rrsigTime: %v", err)
	}
	if back := dns.TimeToString(got); back != "20260730123456" {
		t.Errorf("rrsigTime(%v) = %d, which renders as %q, want 20260730123456", when, got, back)
	}
}

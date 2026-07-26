package sni_tls

import (
	"crypto/tls"
	"strings"
	"testing"
)

// --- certStore.GetCertificate: SNI lookup semantics -------------------------

func TestGetCertificate(t *testing.T) {
	primary := &tls.Certificate{}
	secondary := &tls.Certificate{}

	store := &certStore{
		byName: map[string]*tls.Certificate{
			"dns.example.com":      primary,
			"dns.internal.example": secondary,
		},
		fallback: primary,
	}

	tests := []struct {
		serverName string
		want       *tls.Certificate
	}{
		{"dns.example.com", primary},
		{"dns.internal.example", secondary},
		{"unknown.example.org", primary}, // falls back
		{"", primary},                    // no SNI, falls back
	}

	for _, tc := range tests {
		got, err := store.GetCertificate(&tls.ClientHelloInfo{ServerName: tc.serverName})
		if err != nil {
			t.Errorf("ServerName=%q: unexpected error: %v", tc.serverName, err)
		}
		if got != tc.want {
			t.Errorf("ServerName=%q: got wrong cert", tc.serverName)
		}
	}
}

// TestGetCertificate_CaseInsensitive covers RFC 6066 §3: "'HostName' contains
// the fully qualified DNS hostname ... using ASCII or normalized form ...
// comparisons ... are case-insensitive". A client sending mixed-case SNI must
// still match the lowercased map key.
func TestGetCertificate_CaseInsensitive(t *testing.T) {
	secondary := &tls.Certificate{}
	store := &certStore{
		byName:   map[string]*tls.Certificate{"dns.internal.example": secondary},
		fallback: &tls.Certificate{},
	}

	for _, sni := range []string{"DNS.INTERNAL.EXAMPLE", "Dns.Internal.Example", "dns.internal.example"} {
		got, err := store.GetCertificate(&tls.ClientHelloInfo{ServerName: sni})
		if err != nil {
			t.Fatalf("ServerName=%q: unexpected error: %v", sni, err)
		}
		if got != secondary {
			t.Errorf("ServerName=%q: expected case-insensitive match to dns.internal.example cert", sni)
		}
	}
}

// TestGetCertificate_Wildcard covers the real-world case that motivated
// wildcardOf: a wildcard cert (e.g. Let's Encrypt's *.sevenwoods.nl) loaded
// alongside a per-host cert. Before wildcardOf existed, no real ClientHello
// SNI ever matched the literal map key "*.sevenwoods.nl" -- caught live via
// an actual TLS handshake against a real LE wildcard cert, which silently
// fell through to the fallback cert on every connection.
func TestGetCertificate_Wildcard(t *testing.T) {
	wildcard := &tls.Certificate{}
	perHost := &tls.Certificate{}
	other := &tls.Certificate{}

	store := &certStore{
		byName: map[string]*tls.Certificate{
			"*.sevenwoods.nl": wildcard,
			"dns.home.arpa":   perHost,
		},
		fallback: other,
	}

	tests := []struct {
		serverName string
		want       *tls.Certificate
	}{
		{"dns.sevenwoods.nl", wildcard},    // single-label subdomain: matches
		{"argocd.sevenwoods.nl", wildcard}, // any single-label subdomain matches
		{"dns.home.arpa", perHost},         // exact match still wins over any wildcard derivation
		{"sevenwoods.nl", other},           // bare domain itself: wildcard must NOT match this
		{"a.b.sevenwoods.nl", other},       // two labels deep: single-level wildcard must NOT match
		{"DNS.SEVENWOODS.NL", wildcard},    // case-insensitive, same as exact-match SNI comparison
	}

	for _, tc := range tests {
		got, err := store.GetCertificate(&tls.ClientHelloInfo{ServerName: tc.serverName})
		if err != nil {
			t.Errorf("ServerName=%q: unexpected error: %v", tc.serverName, err)
		}
		if got != tc.want {
			t.Errorf("ServerName=%q: got wrong cert", tc.serverName)
		}
	}
}

func TestWildcardOf(t *testing.T) {
	tests := []struct {
		name   string
		want   string
		wantOK bool
	}{
		{"dns.sevenwoods.nl", "*.sevenwoods.nl", true},
		{"a.b.sevenwoods.nl", "*.b.sevenwoods.nl", true},
		// "sevenwoods.nl" has a dot too, so it derives *.nl -- wildcardOf only
		// asks "is there a leftmost label to replace", not "is the remainder
		// a plausible real-world wildcard cert domain". That's fine: it's
		// only ever used to look up an existing store entry, and nobody
		// loads a "*.nl" cert. The actual safety property -- a bare domain
		// must not match ITS OWN wildcard -- is covered by
		// TestGetCertificate_Wildcard's {"sevenwoods.nl", other} case.
		{"sevenwoods.nl", "*.nl", true},
		{"nl", "", false}, // truly single-label: no dot, no wildcard form
		{"", "", false},
	}
	for _, tc := range tests {
		got, ok := wildcardOf(tc.name)
		if ok != tc.wantOK || got != tc.want {
			t.Errorf("wildcardOf(%q) = (%q, %v), want (%q, %v)", tc.name, got, ok, tc.want, tc.wantOK)
		}
	}
}

// --- loadCert: real cert/key loading + SAN extraction -----------------------

// TestLoadCert_ExtractsSANs exercises the actual tls.LoadX509KeyPair +
// x509.ParseCertificate(cert.Certificate[0]) path against a real generated
// cert — the part the original stub never implemented. Design doc step 1
// notes that older Go's LoadX509KeyPair left cert.Leaf nil, requiring an
// explicit parse to read SANs; Go 1.23+ populates Leaf by default, but
// loadCert's explicit x509.ParseCertificate call is correct either way (it
// never depends on Leaf), so this test only asserts the SAN extraction
// result, not the Leaf field's toolchain-dependent population.
func TestLoadCert_ExtractsSANs(t *testing.T) {
	certPath, keyPath := writeTestCert(t, "primary", "dns.example.com", "extra.example.com")

	cert, names, err := loadCert(certPath, keyPath)
	if err != nil {
		t.Fatalf("loadCert: %v", err)
	}
	if cert == nil {
		t.Fatal("loadCert returned nil cert")
	}

	want := map[string]bool{"dns.example.com": true, "extra.example.com": true}
	if len(names) != len(want) {
		t.Fatalf("got %d SAN names, want %d: %v", len(names), len(want), names)
	}
	for _, n := range names {
		if !want[n] {
			t.Errorf("unexpected SAN name %q", n)
		}
	}
}

// TestLoadCert_LowercasesSANs covers RFC 6066 §3 case-insensitivity from the
// loading side: SANs extracted from the cert must be normalized to lowercase
// so they match a lowercased incoming ServerName.
func TestLoadCert_LowercasesSANs(t *testing.T) {
	certPath, keyPath := writeTestCert(t, "mixedcase", "DNS.Example.COM")

	_, names, err := loadCert(certPath, keyPath)
	if err != nil {
		t.Fatalf("loadCert: %v", err)
	}
	if len(names) != 1 || names[0] != "dns.example.com" {
		t.Fatalf("SAN not lowercased: got %v, want [dns.example.com]", names)
	}
}

// TestLoadCert_NoSANs_Errors: a cert with no SAN DNS names can never be
// selected by GetCertificate's SNI lookup (only reachable via fallback), which
// almost certainly indicates a misconfigured cert. loadCert should reject it
// rather than silently produce an unreachable byName entry.
func TestLoadCert_NoSANs_Errors(t *testing.T) {
	certPath, keyPath := writeNoSANCert(t)
	if _, _, err := loadCert(certPath, keyPath); err == nil {
		t.Fatal("expected error for cert with no SAN DNS names, got nil")
	}
}

func TestLoadCert_MissingCertFile(t *testing.T) {
	_, keyPath := writeTestCert(t, "primary", "dns.example.com")
	if _, _, err := loadCert("/nonexistent/cert.pem", keyPath); err == nil {
		t.Fatal("expected error for missing cert file, got nil")
	}
}

func TestLoadCert_MissingKeyFile(t *testing.T) {
	certPath, _ := writeTestCert(t, "primary", "dns.example.com")
	if _, _, err := loadCert(certPath, "/nonexistent/key.pem"); err == nil {
		t.Fatal("expected error for missing key file, got nil")
	}
}

func TestLoadCert_MismatchedKey(t *testing.T) {
	certPath, _ := writeTestCert(t, "primary", "dns.example.com")
	_, otherKeyPath := writeTestCert(t, "secondary", "dns.internal.example")
	if _, _, err := loadCert(certPath, otherKeyPath); err == nil {
		t.Fatal("expected error for cert/key mismatch, got nil")
	}
}

// --- buildCertStore: multi-cert assembly + first-loaded fallback -----------

// TestBuildCertStore_EndToEnd loads two real certs and confirms the resulting
// store: (a) routes each ADN to the matching cert, (b) falls back to the
// FIRST-loaded cert (design doc step 2) for unmatched/absent SNI — this is
// the behavior the verified-DDR caveat in docs/sni-tls-plugin.md depends on
// being deterministic (first pair wins), not "whichever loaded last".
func TestBuildCertStore_EndToEnd(t *testing.T) {
	primaryCert, primaryKey := writeTestCert(t, "primary", "dns.example.com")
	secondaryCert, secondaryKey := writeTestCert(t, "secondary", "dns.internal.example")

	store, err := buildCertStore([][2]string{
		{primaryCert, primaryKey},
		{secondaryCert, secondaryKey},
	})
	if err != nil {
		t.Fatalf("buildCertStore: %v", err)
	}

	got, err := store.GetCertificate(&tls.ClientHelloInfo{ServerName: "dns.example.com"})
	if err != nil || got != store.byName["dns.example.com"] {
		t.Fatalf("primary lookup wrong: got=%v err=%v", got, err)
	}
	got, err = store.GetCertificate(&tls.ClientHelloInfo{ServerName: "dns.internal.example"})
	if err != nil || got != store.byName["dns.internal.example"] {
		t.Fatalf("secondary lookup wrong: got=%v err=%v", got, err)
	}

	// Fallback must be the FIRST pair's cert (primary), not secondary.
	fallbackGot, _ := store.GetCertificate(&tls.ClientHelloInfo{ServerName: ""})
	if fallbackGot != store.byName["dns.example.com"] {
		t.Fatal("fallback must be the first-loaded cert (primary), got a different cert")
	}
	if store.fallback != store.byName["dns.example.com"] {
		t.Fatal("store.fallback must reference the first pair's cert")
	}
}

// TestBuildCertStore_PropagatesLoadError covers the all-missing case: every
// configured pair fails to load (files don't exist), which is fatal — a
// Corefile listing certs that never materialize should fail loudly, not
// silently produce a store with no fallback and no certs.
func TestBuildCertStore_PropagatesLoadError(t *testing.T) {
	_, err := buildCertStore([][2]string{{"/nonexistent/cert.pem", "/nonexistent/key.pem"}})
	if err == nil || !strings.Contains(err.Error(), "sni_tls") {
		t.Fatalf("expected wrapped sni_tls error, got %v", err)
	}
}

// TestBuildCertStore_TolerantOfMissingSecondCert covers design doc step 5's
// "partial cert set is fine" requirement: a deployment may gate each cert
// independently, copying whichever of the two cert sources (primary, secondary)
// exists, independently — a secondary cert renewal failure must not take down
// the primary listener. This means sni_tls's own Setup() must tolerate a
// Corefile that names a secondary cert/key pair whose files are absent because
// the gate never copied them, and still come up serving primary-only.
func TestBuildCertStore_TolerantOfMissingSecondCert(t *testing.T) {
	primaryCert, primaryKey := writeTestCert(t, "primary", "dns.example.com")

	store, err := buildCertStore([][2]string{
		{primaryCert, primaryKey},
		{"/etc/coredns/tls/secondary.crt", "/etc/coredns/tls/secondary.key"}, // never copied by the gate
	})
	if err != nil {
		t.Fatalf("buildCertStore must tolerate one missing pair when another loads: %v", err)
	}
	if store.fallback == nil {
		t.Fatal("fallback must be set from the successfully-loaded primary cert")
	}
	got, err := store.GetCertificate(&tls.ClientHelloInfo{ServerName: "dns.example.com"})
	if err != nil || got != store.fallback {
		t.Fatalf("primary must still resolve when secondary's files are absent: got=%v err=%v", got, err)
	}
	if _, ok := store.byName["dns.internal.example"]; ok {
		t.Fatal("secondary must not appear in byName when its files never loaded")
	}
}

// TestBuildCertStore_TolerantOfMissingFirstCert is the mirror case: if the
// FIRST-listed pair is the one whose files are absent, the second (loaded)
// pair must still become the fallback — the "first successfully loaded"
// pair, not literally the first list entry regardless of load outcome.
func TestBuildCertStore_TolerantOfMissingFirstCert(t *testing.T) {
	secondaryCert, secondaryKey := writeTestCert(t, "secondary", "dns.internal.example")

	store, err := buildCertStore([][2]string{
		{"/etc/coredns/tls/primary.crt", "/etc/coredns/tls/primary.key"}, // never copied
		{secondaryCert, secondaryKey},
	})
	if err != nil {
		t.Fatalf("buildCertStore must tolerate the first pair missing when a later one loads: %v", err)
	}
	if store.fallback != store.byName["dns.internal.example"] {
		t.Fatal("fallback must be the first SUCCESSFULLY loaded cert (secondary), not nil")
	}
}

// TestBuildCertStore_Empty: setup() already rejects zero pairs before calling
// buildCertStore (c.ArgErr() if no `sni_tls` lines appear at all), so an
// empty slice reaching buildCertStore directly is a valid input with nothing
// to load — not an error, just a store with no fallback.
func TestBuildCertStore_Empty(t *testing.T) {
	store, err := buildCertStore(nil)
	if err != nil {
		t.Fatalf("buildCertStore(nil): %v", err)
	}
	if store.fallback != nil {
		t.Fatal("empty pairs must produce a nil fallback, not a zero-value cert")
	}
}

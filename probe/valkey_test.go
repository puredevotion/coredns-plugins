package probe

import (
	"net/netip"
	"os"
	"testing"
	"time"
)

// Integration tests against a real Valkey. Skipped unless PROBE_VALKEY_ADDR is
// set, so the default `go test` run needs no external service — but they are
// real protocol round-trips when it is, because the thing most likely to be
// wrong here is the encoding surviving a trip through the store, and a fake
// client would test the fake.
//
//	valkey-server --port 6399 &
//	PROBE_VALKEY_ADDR=127.0.0.1:6399 go test ./...
func valkeyStoreForTest(t *testing.T, maxPerToken int) *ValkeyStore {
	t.Helper()
	addr := os.Getenv("PROBE_VALKEY_ADDR")
	if addr == "" {
		t.Skip("PROBE_VALKEY_ADDR not set; skipping Valkey integration test")
	}
	s, err := NewValkeyStore(ValkeyConfig{
		Addrs:       []string{addr},
		TTL:         time.Minute,
		Timeout:     2 * time.Second, // generous: this is a test, not the serving path
		MaxPerToken: maxPerToken,
	})
	if err != nil {
		t.Fatalf("NewValkeyStore(%s): %v", addr, err)
	}
	t.Cleanup(s.Close)
	return s
}

// uniqueToken keeps parallel or repeated runs from colliding in a shared Valkey,
// and keeps each test's assertions about counts meaningful.
func uniqueToken(t *testing.T) string {
	t.Helper()
	// Hex, 8-32 chars, per the grammar. Nanosecond time is enough here.
	const hexDigits = "0123456789abcdef"
	n := time.Now().UnixNano()
	b := make([]byte, 16)
	for i := range b {
		b[i] = hexDigits[n&0xf]
		n >>= 4
		if n == 0 {
			n = time.Now().UnixNano()
		}
	}
	return string(b)
}

func sampleObservation(token string) Observation {
	return Observation{
		Token:          token,
		At:             time.Now().UTC().Truncate(time.Second),
		ResolverAddr:   netip.MustParseAddr("192.0.2.53"),
		ResolverPrefix: netip.MustParsePrefix("192.0.2.0/24"),
		Transport:      TransportUDP,
		Qtype:          "TXT",
		Mods:           "badsig",
		DO:             true,
		EDNS:           true,
		UDPSize:        1232,
		Cookie:         true,
		CaseRandomized: true,
	}
}

func TestValkeyRoundTrip(t *testing.T) {
	s := valkeyStoreForTest(t, 8)
	token := uniqueToken(t)

	want := sampleObservation(token)
	got, err := s.Record(want)
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	if got.Seen != 1 {
		t.Errorf("Seen = %d, want 1", got.Seen)
	}

	back, err := s.Lookup(token)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if len(back) != 1 {
		t.Fatalf("got %d observations, want 1", len(back))
	}

	// The fields most likely to break in transit are the ones with custom text
	// encodings — an address or prefix that comes back wrong would silently
	// misreport whose resolver we saw.
	b := back[0]
	if b.ResolverAddr != want.ResolverAddr {
		t.Errorf("ResolverAddr = %v, want %v", b.ResolverAddr, want.ResolverAddr)
	}
	if b.ResolverPrefix != want.ResolverPrefix {
		t.Errorf("ResolverPrefix = %v, want %v", b.ResolverPrefix, want.ResolverPrefix)
	}
	if !b.At.Equal(want.At) {
		t.Errorf("At = %v, want %v", b.At, want.At)
	}
	if b.Transport != want.Transport || b.Qtype != want.Qtype || b.Mods != want.Mods {
		t.Errorf("transport/qtype/mods round-tripped as %q/%q/%q", b.Transport, b.Qtype, b.Mods)
	}
	if !b.DO || !b.EDNS || !b.Cookie || !b.CaseRandomized || b.UDPSize != 1232 {
		t.Errorf("boolean/size fields round-tripped wrong: %+v", b)
	}
	if b.Seen != 1 {
		t.Errorf("stored Seen = %d, want 1", b.Seen)
	}
}

func TestValkeySeenIncrements(t *testing.T) {
	s := valkeyStoreForTest(t, 8)
	token := uniqueToken(t)

	for i := 1; i <= 3; i++ {
		got, err := s.Record(sampleObservation(token))
		if err != nil {
			t.Fatalf("Record %d: %v", i, err)
		}
		if got.Seen != i {
			t.Errorf("Record %d returned Seen = %d, want %d", i, got.Seen, i)
		}
	}

	n, err := s.SeenCount(token)
	if err != nil {
		t.Fatalf("SeenCount: %v", err)
	}
	if n != 3 {
		t.Errorf("SeenCount = %d, want 3", n)
	}
}

// TestValkeyCapKeepsCountTruthful is the reason the counter is a separate key
// from the list: detail is capped so one resolver cannot grow a token without
// limit, but "we saw this 20 times" must stay reportable past the cap, because
// that is itself the interesting finding.
func TestValkeyCapKeepsCountTruthful(t *testing.T) {
	const cap = 3
	s := valkeyStoreForTest(t, cap)
	token := uniqueToken(t)

	const total = 10
	for i := 0; i < total; i++ {
		if _, err := s.Record(sampleObservation(token)); err != nil {
			t.Fatalf("Record %d: %v", i, err)
		}
	}

	back, err := s.Lookup(token)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if len(back) != cap {
		t.Errorf("retained %d observations, want the cap of %d", len(back), cap)
	}

	n, err := s.SeenCount(token)
	if err != nil {
		t.Fatalf("SeenCount: %v", err)
	}
	if n != total {
		t.Errorf("SeenCount = %d, want %d — the count must survive the detail cap", n, total)
	}
}

func TestValkeyLookupUnknownTokenIsEmptyNotError(t *testing.T) {
	// The web tier will ask about tokens that never produced a query (a visitor
	// whose resolver failed to reach us at all, which is itself a finding). That
	// must read as "nothing seen", not as a backend error.
	s := valkeyStoreForTest(t, 8)
	obs, err := s.Lookup(uniqueToken(t))
	if err != nil {
		t.Fatalf("Lookup of an unknown token errored: %v", err)
	}
	if len(obs) != 0 {
		t.Errorf("got %d observations for an unknown token", len(obs))
	}
	n, err := s.SeenCount(uniqueToken(t))
	if err != nil {
		t.Fatalf("SeenCount of an unknown token errored: %v", err)
	}
	if n != 0 {
		t.Errorf("SeenCount = %d for an unknown token, want 0", n)
	}
}

// TestValkeyReportRoundTrip is the RFC 9567 half of the seam. Same reason the
// observation round-trip is here: the thing most likely to be wrong is the JSON
// surviving the store, and the web tier decodes these bytes with no shared code.
func TestValkeyReportRoundTrip(t *testing.T) {
	s := valkeyStoreForTest(t, 8)
	token := uniqueToken(t)

	want := ReportRecord{
		At:             time.Now().UTC().Truncate(time.Second),
		Token:          token,
		Qtype:          1,
		QtypeName:      "A",
		Qname:          "_expiredsig." + token + ".check.example.com.",
		EDE:            7,
		EDEText:        "Signature Expired",
		ReporterAddr:   netip.MustParseAddr("192.0.2.53"),
		ReporterPrefix: netip.MustParsePrefix("192.0.2.0/24"),
		Transport:      TransportUDP,
	}
	if err := s.RecordReport(want); err != nil {
		t.Fatalf("RecordReport: %v", err)
	}

	back, err := s.LookupReports(token)
	if err != nil {
		t.Fatalf("LookupReports: %v", err)
	}
	if len(back) != 1 {
		t.Fatalf("got %d reports, want 1", len(back))
	}
	got := back[0]
	if got.Qname != want.Qname || got.EDE != want.EDE || got.Qtype != want.Qtype {
		t.Errorf("report round-tripped as %+v, want %+v", got, want)
	}
	if got.ReporterAddr != want.ReporterAddr || got.ReporterPrefix != want.ReporterPrefix {
		t.Errorf("reporter round-tripped as %s/%s, want %s/%s",
			got.ReporterAddr, got.ReporterPrefix, want.ReporterAddr, want.ReporterPrefix)
	}
	if !got.At.Equal(want.At) {
		t.Errorf("At = %s, want %s", got.At, want.At)
	}
}

// TestValkeyReportCapKeepsNewest. LTRIM keeps the tail, which is deliberate: a
// report arriving now is about a failure happening now, and the entries a flood
// contributes are the ones worth losing first.
func TestValkeyReportCapKeepsNewest(t *testing.T) {
	const limit = 3
	s := valkeyStoreForTest(t, limit)
	token := uniqueToken(t)

	const total = limit + 4
	for i := uint16(0); i < total; i++ {
		if err := s.RecordReport(ReportRecord{Token: token, EDE: i}); err != nil {
			t.Fatalf("RecordReport %d: %v", i, err)
		}
	}
	back, err := s.LookupReports(token)
	if err != nil {
		t.Fatalf("LookupReports: %v", err)
	}
	if len(back) != limit {
		t.Fatalf("retained %d reports, want the cap of %d", len(back), limit)
	}
	// EDE was set to the loop index, so the survivors identify which end was
	// trimmed without needing timestamps.
	if back[0].EDE != total-limit || back[len(back)-1].EDE != total-1 {
		t.Errorf("retained EDEs %d..%d, want the newest %d entries",
			back[0].EDE, back[len(back)-1].EDE, limit)
	}
}

// TestValkeyUnattributedReportsAreSeparate. The unattributed list must not land
// in a token's key space — a visitor reading their own report would otherwise
// see every stranger's.
func TestValkeyUnattributedReportsAreSeparate(t *testing.T) {
	s := valkeyStoreForTest(t, 8)
	token := uniqueToken(t)

	if err := s.RecordReport(ReportRecord{Token: token, EDE: 6}); err != nil {
		t.Fatalf("RecordReport attributed: %v", err)
	}
	if err := s.RecordReport(ReportRecord{EDE: 10}); err != nil {
		t.Fatalf("RecordReport unattributed: %v", err)
	}

	mine, err := s.LookupReports(token)
	if err != nil {
		t.Fatalf("LookupReports: %v", err)
	}
	if len(mine) != 1 || mine[0].EDE != 6 {
		t.Errorf("token list = %+v, want exactly the attributed report", mine)
	}
}

// TestReportKeyNamespacing needs no server: the unattributed list shares a key
// prefix with every token, so the only thing keeping them apart is that a token
// is lowercase hex and "unattributed" is not.
func TestReportKeyNamespacing(t *testing.T) {
	if reportKey("") == reportKey("deadbeef") {
		t.Fatal("the unattributed key collides with a real token's key")
	}
	for _, token := range []string{"deadbeef", "0123456789abcdef"} {
		if !parseTokenOK(token) {
			t.Fatalf("test setup: %q is not a valid token", token)
		}
		if reportKey(token) == reportKey("") {
			t.Errorf("token %q maps onto the unattributed key", token)
		}
	}
	// The literal must stay unreachable through the token grammar.
	if parseTokenOK("unattributed") {
		t.Error("\"unattributed\" parses as a token, so a visitor could be issued the shared key")
	}
}

func parseTokenOK(s string) bool {
	_, ok := parseToken(s)
	return ok
}

// TestValkeyStoreSatisfiesStore keeps the plugin wiring honest: ServeDNS only
// ever talks to the interface, so this is what guarantees the Valkey
// implementation is substitutable for MemStore.
func TestValkeyStoreSatisfiesStore(t *testing.T) {
	var _ Store = (*ValkeyStore)(nil)
	var _ Store = (*MemStore)(nil)
}

func TestNewValkeyStoreRejectsBadConfig(t *testing.T) {
	if _, err := NewValkeyStore(ValkeyConfig{}); err == nil {
		t.Error("NewValkeyStore accepted an empty address list")
	}
	if _, err := NewValkeyStore(ValkeyConfig{
		Addrs:  []string{"127.0.0.1:1"},
		CAFile: "/nonexistent/ca.pem",
	}); err == nil {
		t.Error("NewValkeyStore accepted a missing CA file")
	}
}

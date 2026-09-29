package advertiser

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/mdlayher/ndp"
	"github.com/puredevotion/coredns-plugins/radnr/internal/config"
	"golang.org/x/net/ipv6"
)

// fakeConn is an injected ndp transport for unit tests — no real socket.
type fakeConn struct {
	rsCh    chan struct{}
	sendErr error
	sent    []sent
	closed  bool
}

type sent struct {
	msg ndp.Message
	to  netip.Addr
}

func (f *fakeConn) WriteTo(m ndp.Message, _ *ipv6.ControlMessage, dst netip.Addr) error {
	if f.sendErr != nil {
		return f.sendErr
	}
	f.sent = append(f.sent, sent{msg: m, to: dst})
	return nil
}

func (f *fakeConn) ReadFrom() (ndp.Message, *ipv6.ControlMessage, netip.Addr, error) {
	<-f.rsCh // Block until test injects an RS or Close unblocks it.
	if f.closed {
		return nil, nil, netip.Addr{}, errors.New("fakeConn: closed")
	}
	return &ndp.RouterSolicitation{}, nil, netip.MustParseAddr("fe80::99"), nil
}

func (f *fakeConn) Close() error {
	if !f.closed {
		f.closed = true
		close(f.rsCh)
	}
	return nil
}

func baseCfg() config.Config {
	return config.Config{
		Interface: "eth0",
		ADN:       "dns.example.com", //nolint:misspell // ADN: RFC 9463 Authentication Domain Name, not a typo for AND
		Addrs:     []string{"fde3:6ad1:6501::240"},
		ALPN:      []string{"dot", "doq"},
		Port:      853,
		DohPath:   "/dns-query{?dns}",
	}
}

// expectRunDone asserts that a completed Advertiser.Run either succeeded or
// stopped because its context ended — the only outcomes these tests expect —
// and fails the (synchronous) test otherwise.
func expectRunDone(t *testing.T, err error) {
	t.Helper()
	if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Run: unexpected error: %v", err)
	}
}

// expectRunDoneAsync is expectRunDone for use from a background goroutine,
// where t.Fatalf is unsafe.
func expectRunDoneAsync(t *testing.T, err error) {
	t.Helper()
	if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Run: unexpected error: %v", err)
	}
}

func TestBuildRA_SafetyShape(t *testing.T) {
	c := baseCfg()
	ra, err := BuildRA(&c)
	if err != nil {
		t.Fatalf("BuildRA: %v", err)
	}
	if ra.RouterLifetime != 0 {
		t.Fatalf("RouterLifetime must be 0, got %v", ra.RouterLifetime)
	}
	if ra.ManagedConfiguration || ra.OtherConfiguration {
		t.Fatalf("M/O flags must be false (don't trigger DHCPv6)")
	}
	// MUST NOT contain a PrefixInformation option.
	for _, o := range ra.Options {
		if _, ok := o.(*ndp.PrefixInformation); ok {
			t.Fatalf("RA must not contain PrefixInformation (would disrupt SLAAC)")
		}
	}
	// MUST contain a RawOption with Type 144 (DNR).
	var hasDNR bool
	for _, o := range ra.Options {
		if ro, ok := o.(*ndp.RawOption); ok && ro.Type == 144 {
			hasDNR = true
		}
	}
	if !hasDNR {
		t.Fatalf("RA must contain the DNR option (RawOption type 144)")
	}
}

func TestBuildRA_RDNSSWhenConfigured(t *testing.T) {
	c := baseCfg()
	c.AdvertiseRDNSS = true
	ra, err := BuildRA(&c)
	if err != nil {
		t.Fatalf("BuildRA: %v", err)
	}
	var hasRDNSS bool
	for _, o := range ra.Options {
		if _, ok := o.(*ndp.RecursiveDNSServer); ok {
			hasRDNSS = true
		}
	}
	if !hasRDNSS {
		t.Fatalf("RDNSS option expected when AdvertiseRDNSS=true")
	}
}

func TestBuildRA_NoRDNSSByDefault(t *testing.T) {
	c := baseCfg()
	ra, err := BuildRA(&c)
	if err != nil {
		t.Fatalf("BuildRA: %v", err)
	}
	for _, o := range ra.Options {
		if _, ok := o.(*ndp.RecursiveDNSServer); ok {
			t.Fatalf("RDNSS must not be present unless explicitly enabled")
		}
	}
}

func TestBuildRA_InvalidConfig(t *testing.T) {
	c := baseCfg()
	c.ADN = "" //nolint:misspell // ADN: RFC 9463 Authentication Domain Name, not a typo for AND
	if _, err := BuildRA(&c); err == nil {
		t.Fatalf("BuildRA must reject invalid config")
	}
}

func TestAdvertise_DryRun_NeverSends(t *testing.T) {
	c := baseCfg()
	c.DryRun = true
	fc := &fakeConn{rsCh: make(chan struct{})}
	a := &Advertiser{Conn: fc, Cfg: c, Interval: time.Millisecond}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	expectRunDone(t, a.Run(ctx))
	if len(fc.sent) != 0 {
		t.Fatalf("dry-run must not transmit, sent %d", len(fc.sent))
	}
}

func TestAdvertise_MulticastDestination(t *testing.T) {
	fc := &fakeConn{rsCh: make(chan struct{})}
	a := &Advertiser{Conn: fc, Cfg: baseCfg(), Interval: time.Millisecond}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	expectRunDone(t, a.Run(ctx))
	if len(fc.sent) == 0 {
		t.Fatalf("expected at least one periodic RA")
	}
	if fc.sent[0].to != netip.MustParseAddr("ff02::1") {
		t.Fatalf("multicast dest = %v, want ff02::1", fc.sent[0].to)
	}
}

func TestAdvertise_UnicastDestination(t *testing.T) {
	c := baseCfg()
	c.UnicastTarget = "fe80::99"
	fc := &fakeConn{rsCh: make(chan struct{})}
	a := &Advertiser{Conn: fc, Cfg: c, Interval: time.Millisecond}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	expectRunDone(t, a.Run(ctx))
	if len(fc.sent) == 0 || fc.sent[0].to != netip.MustParseAddr("fe80::99") {
		t.Fatalf("unicast dest wrong: %+v", fc.sent)
	}
}

func TestAdvertise_SendErrorDoesNotCrash(t *testing.T) {
	fc := &fakeConn{rsCh: make(chan struct{}), sendErr: errors.New("boom")}
	a := &Advertiser{Conn: fc, Cfg: baseCfg(), Interval: time.Millisecond}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Millisecond)
	defer cancel()
	if err := a.Run(ctx); err != nil && !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("send errors should not abort the loop, got %v", err)
	}
}

func TestAdvertise_ContextCancelStops(t *testing.T) {
	fc := &fakeConn{rsCh: make(chan struct{})}
	a := &Advertiser{Conn: fc, Cfg: baseCfg(), Interval: time.Hour} // Long, so only ctx ends it.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	expectRunDone(t, a.Run(ctx))
	if time.Since(start) > time.Second {
		t.Fatalf("Run should return promptly on ctx cancel")
	}
}

// TestAdvertise_ContextCancelClosesConn verifies Run closes the Conn on
// shutdown so a blocked ReadFrom (as a real ndp.Conn would have) unblocks and
// the RS-reader goroutine doesn't leak.
func TestAdvertise_ContextCancelClosesConn(t *testing.T) {
	fc := &fakeConn{rsCh: make(chan struct{})}
	a := &Advertiser{Conn: fc, Cfg: baseCfg(), Interval: time.Hour}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	expectRunDone(t, a.Run(ctx))
	if !fc.closed {
		t.Fatalf("Run must close the Conn on ctx cancellation")
	}
}

// withShrunkRateLimit shrinks the package's minDelayBetweenRAs for the
// duration of a test, restoring it afterward — real value is 3s (too slow to
// wait out in a unit test).
func withShrunkRateLimit(t *testing.T, d time.Duration) {
	t.Helper()
	orig := minDelayBetweenRAs
	minDelayBetweenRAs = d
	t.Cleanup(func() { minDelayBetweenRAs = orig })
}

// TestAdvertise_RouterSolicitationTriggersRA covers RFC 4861 §6.2.6: on
// receiving a valid Router Solicitation (after the rate-limit window has
// elapsed), the advertiser must send a solicited RA promptly, not wait for
// the next periodic tick.
func TestAdvertise_RouterSolicitationTriggersRA(t *testing.T) {
	withShrunkRateLimit(t, 20*time.Millisecond)
	fc := &fakeConn{rsCh: make(chan struct{}, 1)}
	a := &Advertiser{Conn: fc, Cfg: baseCfg(), Interval: time.Hour} // Long periodic interval.
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	done := make(chan struct{})
	go func() { expectRunDoneAsync(t, a.Run(ctx)); close(done) }()

	time.Sleep(30 * time.Millisecond) // Past the initial send + shrunk rate-limit window.
	fc.rsCh <- struct{}{}             // Inject one RS.
	time.Sleep(50 * time.Millisecond) // Let it be processed.

	<-done
	if len(fc.sent) < 2 {
		t.Fatalf("expected initial RA + solicited RA, got %d sends", len(fc.sent))
	}
}

// TestAdvertise_RouterSolicitationRateLimited covers RFC 4861 §6.2.6's
// MIN_DELAY_BETWEEN_RAS: a solicitation arriving within minDelayBetweenRAs of
// the previous RA must not trigger an immediate extra send.
func TestAdvertise_RouterSolicitationRateLimited(t *testing.T) {
	withShrunkRateLimit(t, time.Hour) // Effectively never elapses within the test.
	fc := &fakeConn{rsCh: make(chan struct{}, 4)}
	a := &Advertiser{Conn: fc, Cfg: baseCfg(), Interval: time.Hour}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	done := make(chan struct{})
	go func() { expectRunDoneAsync(t, a.Run(ctx)); close(done) }()

	time.Sleep(5 * time.Millisecond) // After the initial send.
	// Flood several RSes well within the (hour-long) rate-limit window.
	for range 3 {
		fc.rsCh <- struct{}{}
		time.Sleep(5 * time.Millisecond)
	}

	<-done
	if len(fc.sent) != 1 {
		t.Fatalf("rate limiting failed: expected exactly 1 RA (initial), got %d", len(fc.sent))
	}
}

// TestNextInterval_WithinRFCBounds covers RFC 4861 §6.2.1: the actual
// interval between unsolicited RAs must be a uniform random value in
// [MinRtrAdvInterval, MaxRtrAdvInterval), not a fixed period.
func TestNextInterval_WithinRFCBounds(t *testing.T) {
	a := &Advertiser{Interval: 30 * time.Second}
	minInterval := a.Interval / 3
	seen := map[time.Duration]bool{}
	for range 200 {
		d := a.nextInterval()
		if d < minInterval || d >= a.Interval {
			t.Fatalf("nextInterval() = %v, want in [%v, %v)", d, minInterval, a.Interval)
		}
		seen[d] = true
	}
	if len(seen) < 2 {
		t.Fatalf("nextInterval() never varied across 200 calls — not randomised")
	}
}

// TestNextInterval_FloorsAtMinDelay covers the RFC's absolute minimum: even
// for a small configured Interval, Min must not go below minDelayBetweenRAs.
func TestNextInterval_FloorsAtMinDelay(t *testing.T) {
	a := &Advertiser{Interval: 4 * time.Second} // Interval/3 < minDelayBetweenRAs.
	for range 50 {
		if d := a.nextInterval(); d < minDelayBetweenRAs && d != a.Interval {
			t.Fatalf("nextInterval() = %v, want >= %v (or == Interval when Min>=Max)", d, minDelayBetweenRAs)
		}
	}
}

//nolint:misspell // ADN throughout this file: RFC 9463 Authentication Domain Name, not a typo for AND
package radnr

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/puredevotion/coredns-plugins/radnr/internal/advertiser"
	"github.com/puredevotion/coredns-plugins/radnr/internal/config"
)

func TestName(t *testing.T) {
	r := &RADNR{}
	if r.Name() != pluginName {
		t.Fatalf("Name = %q, want %s", r.Name(), pluginName)
	}
}

// fakeRunner records lifecycle calls; lets us test OnStartup/OnShutdown without
// a real ICMPv6 socket. Stopped is a channel (closed on Run return) to avoid a
// data race between the runner goroutine and the test.
type fakeRunner struct {
	started chan struct{}
	stopped chan struct{}
	runErr  error
}

func newFakeRunner() *fakeRunner {
	return &fakeRunner{started: make(chan struct{}), stopped: make(chan struct{})}
}

func (f *fakeRunner) Run(ctx context.Context) error {
	close(f.started)
	<-ctx.Done()
	close(f.stopped)
	return f.runErr
}

func TestOnStartup_LaunchesRunner(t *testing.T) {
	fr := newFakeRunner()
	r := &RADNR{
		Cfg:    validCfg(),
		runner: fr,
	}
	if err := r.OnStartup(); err != nil {
		t.Fatalf("OnStartup: %v", err)
	}
	select {
	case <-fr.started:
		// Good — runner goroutine launched.
	case <-time.After(time.Second):
		t.Fatal("runner did not start")
	}
	if err := r.OnShutdown(); err != nil {
		t.Fatalf("OnShutdown: %v", err)
	}
	select {
	case <-fr.stopped:
		// Good — runner observed cancellation.
	case <-time.After(time.Second):
		t.Fatal("runner was not stopped on shutdown")
	}
}

// ctxRunner records the context of every Run call, so a test can tell
// whether an earlier advertiser was cancelled.
type ctxRunner struct{ ctxs chan context.Context }

func (c *ctxRunner) Run(ctx context.Context) error {
	c.ctxs <- ctx
	<-ctx.Done()
	return nil
}

// TestOnStartup_RestartFailedWithoutRestart is what caddy does when a plugin
// registered before radnr fails its OnRestart: radnr's OnRestart never runs,
// its OnRestartFailed (OnStartup) does. The advertiser already running must
// be stopped, not orphaned beside a second one.
func TestOnStartup_RestartFailedWithoutRestart(t *testing.T) {
	cr := &ctxRunner{ctxs: make(chan context.Context, 2)}
	r := &RADNR{Cfg: validCfg(), runner: cr}

	if err := r.OnStartup(); err != nil {
		t.Fatalf("OnStartup: %v", err)
	}
	first := <-cr.ctxs
	if err := r.OnStartup(); err != nil { // OnRestartFailed, no OnRestart before it.
		t.Fatalf("OnStartup (restart-failed): %v", err)
	}
	second := <-cr.ctxs

	select {
	case <-first.Done():
	case <-time.After(time.Second):
		t.Fatal("first advertiser still running after OnStartup started a second")
	}
	if err := r.OnShutdown(); err != nil {
		t.Fatalf("OnShutdown: %v", err)
	}
	select {
	case <-second.Done():
	case <-time.After(time.Second):
		t.Fatal("second advertiser not stopped by OnShutdown")
	}
}

// TestOnStartup_ReclaimsDroppedInstance is a reload that fails after the new
// instance's OnStartup already ran (a later plugin's OnStartup errors, or a
// listener cannot bind). Caddy discards the new instance without calling
// any of its shutdown hooks and runs the old one's OnRestartFailed. That
// must stop the discarded instance's advertiser, which would otherwise keep
// sending RAs from a Corefile that never took effect.
func TestOnStartup_ReclaimsDroppedInstance(t *testing.T) {
	oldRunner := &ctxRunner{ctxs: make(chan context.Context, 2)}
	newRunner := &ctxRunner{ctxs: make(chan context.Context, 1)}
	oldInst := &RADNR{Cfg: validCfg(), runner: oldRunner, owner: new(int)}
	newInst := &RADNR{Cfg: validCfg(), runner: newRunner, owner: new(int)}
	t.Cleanup(func() { shutdownAll(t, oldInst, newInst) })

	if err := oldInst.OnStartup(); err != nil { // First startup.
		t.Fatalf("OnStartup: %v", err)
	}
	<-oldRunner.ctxs
	if err := oldInst.OnShutdown(); err != nil { // Old instance's OnRestart.
		t.Fatalf("OnShutdown: %v", err)
	}
	if err := newInst.OnStartup(); err != nil { // New instance's OnStartup...
		t.Fatalf("new OnStartup: %v", err)
	}
	dropped := <-newRunner.ctxs
	// ...then the reload fails and caddy drops newInst silently.
	if err := oldInst.OnStartup(); err != nil { // Old instance's OnRestartFailed.
		t.Fatalf("OnStartup (restart-failed): %v", err)
	}
	resumed := <-oldRunner.ctxs

	select {
	case <-dropped.Done():
	case <-time.After(time.Second):
		t.Fatal("the dropped instance's advertiser is still running")
	}
	if resumed.Err() != nil {
		t.Fatal("the resumed advertiser was stopped")
	}
}

func shutdownAll(t *testing.T, rs ...*RADNR) {
	t.Helper()
	for _, r := range rs {
		if err := r.OnShutdown(); err != nil {
			t.Errorf("OnShutdown: %v", err)
		}
	}
}

// TestOnStartup_SameInstanceBlocksCoexist: several radnr blocks in one
// Corefile belong to one instance, and starting one must not stop another.
func TestOnStartup_SameInstanceBlocksCoexist(t *testing.T) {
	owner := new(int)
	runA := &ctxRunner{ctxs: make(chan context.Context, 1)}
	runB := &ctxRunner{ctxs: make(chan context.Context, 1)}
	a := &RADNR{Cfg: validCfg(), runner: runA, owner: owner}
	b := &RADNR{Cfg: validCfg(), runner: runB, owner: owner}
	t.Cleanup(func() { shutdownAll(t, a, b) })

	if err := a.OnStartup(); err != nil {
		t.Fatalf("a.OnStartup: %v", err)
	}
	ctxA := <-runA.ctxs
	if err := b.OnStartup(); err != nil {
		t.Fatalf("b.OnStartup: %v", err)
	}
	<-runB.ctxs
	if ctxA.Err() != nil {
		t.Fatal("starting a second block of the same instance stopped the first")
	}
}

func TestOnStartup_InvalidConfig(t *testing.T) {
	r := &RADNR{Cfg: config.Config{}} // Empty, invalid.
	if err := r.OnStartup(); err == nil {
		t.Fatal("OnStartup must reject invalid config")
	}
}

func TestOnShutdown_BeforeStartup_NoPanic(t *testing.T) {
	r := &RADNR{Cfg: validCfg()}
	if err := r.OnShutdown(); err != nil {
		t.Fatalf("OnShutdown before startup should be a no-op, got: %v", err)
	}
}

func TestOnStartup_RunnerErrorLogged(t *testing.T) {
	fr := newFakeRunner()
	fr.runErr = errors.New("boom")
	r := &RADNR{Cfg: validCfg(), runner: fr}
	if err := r.OnStartup(); err != nil {
		t.Fatalf("OnStartup: %v", err)
	}
	<-fr.started
	if err := r.OnShutdown(); err != nil {
		t.Fatalf("OnShutdown: %v", err)
	}
}

func validCfg() config.Config {
	return config.Config{
		Interface: "eth0",
		ADN:       "dns.example.com",
		Addrs:     []string{"fde3:6ad1:6501::240"},
		ALPN:      []string{"dot", "doq"},
		Port:      853,
	}
}

func TestOnStartup_DryRunUsesNopConn(t *testing.T) {
	// Dry-run + no injected runner exercises the real dial() (nopConn) path and
	// the real advertiser, without opening a socket or transmitting.
	cfg := validCfg()
	cfg.DryRun = true
	cfg.Interface = "lo"
	r := &RADNR{Cfg: cfg}
	if err := r.OnStartup(); err != nil {
		t.Fatalf("dry-run OnStartup: %v", err)
	}
	defer func() {
		if err := r.OnShutdown(); err != nil {
			t.Errorf("OnShutdown: %v", err)
		}
	}()
	time.Sleep(20 * time.Millisecond) // Let the advertiser loop run once.
}

func TestDial_DryRun(t *testing.T) {
	c, err := dial(&config.Config{DryRun: true})
	if err != nil {
		t.Fatalf("dial dry-run: %v", err)
	}
	if c == nil {
		t.Fatal("dial dry-run returned nil conn")
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestDial_RealPath_Injected(t *testing.T) {
	// Inject a fake listener to exercise dial's non-dry-run branch without a
	// real socket: success path then error path.
	orig := listenFn
	defer func() { listenFn = orig }()

	cfg := validCfg()
	cfg.DryRun = false

	listenFn = func(string) (advertiser.Conn, error) { return nopConn{}, nil }
	c, err := dial(&cfg)
	if err != nil || c == nil {
		t.Fatalf("dial via injected listener: c=%v err=%v", c, err)
	}

	listenFn = func(string) (advertiser.Conn, error) { return nil, errBoom }
	if _, err := dial(&cfg); err == nil {
		t.Fatal("dial must propagate listener error")
	}
}

var errBoom = errors.New("boom")

func TestNopConn_Methods(t *testing.T) {
	var c nopConn
	if err := c.WriteTo(nil, nil, netip.MustParseAddr("ff02::1")); err != nil {
		t.Fatalf("nopConn.WriteTo: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("nopConn.Close: %v", err)
	}
	// ReadFrom blocks forever by design; verify that in a goroutine that we cancel.
	done := make(chan struct{})
	go func() {
		_, _, _, _ = c.ReadFrom() //nolint:errcheck // nopConn.ReadFrom blocks forever by design; this call never returns, so there is no error to check.
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("nopConn.ReadFrom should block, not return")
	case <-time.After(30 * time.Millisecond):
		// expected: still blocking
	}
}

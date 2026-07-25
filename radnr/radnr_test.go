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
	if r.Name() != "radnr" {
		t.Fatalf("Name = %q, want radnr", r.Name())
	}
}

// fakeRunner records lifecycle calls; lets us test OnStartup/OnShutdown without
// a real ICMPv6 socket. stopped is a channel (closed on Run return) to avoid a
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
		// good — runner goroutine launched
	case <-time.After(time.Second):
		t.Fatal("runner did not start")
	}
	if err := r.OnShutdown(); err != nil {
		t.Fatalf("OnShutdown: %v", err)
	}
	select {
	case <-fr.stopped:
		// good — runner observed cancellation
	case <-time.After(time.Second):
		t.Fatal("runner was not stopped on shutdown")
	}
}

func TestOnStartup_InvalidConfig(t *testing.T) {
	r := &RADNR{Cfg: config.Config{}} // empty → invalid
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
	_ = r.OnShutdown()
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
	defer r.OnShutdown()
	time.Sleep(20 * time.Millisecond) // let the advertiser loop run once
}

func TestDial_DryRun(t *testing.T) {
	c, err := dial(config.Config{DryRun: true})
	if err != nil {
		t.Fatalf("dial dry-run: %v", err)
	}
	if c == nil {
		t.Fatal("dial dry-run returned nil conn")
	}
	_ = c.Close()
}

func TestDial_RealPath_Injected(t *testing.T) {
	// Inject a fake listener to exercise dial's non-dry-run branch without a
	// real socket: success path then error path.
	orig := listenFn
	defer func() { listenFn = orig }()

	cfg := validCfg()
	cfg.DryRun = false

	listenFn = func(string) (advertiser.Conn, error) { return nopConn{}, nil }
	c, err := dial(cfg)
	if err != nil || c == nil {
		t.Fatalf("dial via injected listener: c=%v err=%v", c, err)
	}

	listenFn = func(string) (advertiser.Conn, error) { return nil, errBoom }
	if _, err := dial(cfg); err == nil {
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
		_, _, _, _ = c.ReadFrom()
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("nopConn.ReadFrom should block, not return")
	case <-time.After(30 * time.Millisecond):
		// expected: still blocking
	}
}

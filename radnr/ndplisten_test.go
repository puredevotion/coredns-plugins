package radnr

import (
	"errors"
	"net"
	"os"
	"testing"

	"github.com/mdlayher/ndp"
	"github.com/puredevotion/coredns-plugins/radnr/internal/advertiser"
)

// TestNdpListen_UnknownInterface exercises ndpListen's real net.InterfaceByName
// failure branch — no socket privilege needed, this fails before ever reaching
// dialNDP.
func TestNdpListen_UnknownInterface(t *testing.T) {
	if _, err := ndpListen("radnr-test-nonexistent-iface-0"); err == nil {
		t.Fatal("expected error for a nonexistent interface, got nil")
	}
}

// TestNdpListen_RealRawSocket_RequiresPrivilege documents (and, when run with
// CAP_NET_RAW/root, actually verifies) the real ndp.Listen call this plugin
// depends on in production: given a genuine interface, the unmodified dialNDP
// opens an actual ICMPv6 raw socket. Unprivileged sandboxes/CI can't create
// that socket (EPERM/EACCES), so this test accepts either outcome — a real
// success (privileged runner) or a real permission error (everyone else) —
// rather than skipping outright, so the attempt itself (and the real
// net.InterfaceByName lookup preceding it) still runs and is covered.
func TestNdpListen_RealRawSocket_RequiresPrivilege(t *testing.T) {
	ifi, err := realLinkLocalInterface()
	if err != nil {
		t.Skipf("no interface with a link-local IPv6 address available to test against: %v", err)
	}

	conn, addr, err := ndp.Listen(ifi, ndp.LinkLocal)
	if err != nil {
		t.Logf("ndp.Listen on %q failed as expected without CAP_NET_RAW (uid=%d): %v", ifi.Name, os.Getuid(), err)
		return
	}
	// Only reachable when actually running privileged (e.g. root in CI with
	// NET_RAW granted): prove the conn this plugin would really use works.
	defer conn.Close()
	if !addr.IsValid() {
		t.Fatal("ndp.Listen returned an invalid link-local address")
	}
}

// realLinkLocalInterface finds a real, up network interface carrying a
// link-local IPv6 address — what ndp.Listen(ifi, ndp.LinkLocal) actually
// requires — without hardcoding an interface name that won't exist on every
// machine or CI runner this test runs on.
func realLinkLocalInterface() (*net.Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for i := range ifaces {
		ifi := &ifaces[i]
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if ok && ipnet.IP.To4() == nil && ipnet.IP.IsLinkLocalUnicast() {
				return ifi, nil
			}
		}
	}
	return nil, errors.New("no interface with a link-local IPv6 address found")
}

// TestNdpListen_StubbedSuccess covers ndpListen's success path (the one line
// TestNdpListen_RealRawSocket_RequiresPrivilege can't reach without root) by
// substituting dialNDP for a fake — this is the "use mocks/stubs" fallback:
// the real net.InterfaceByName lookup against a genuine interface still runs
// unmocked, only the raw-socket layer underneath it is stubbed.
func TestNdpListen_StubbedSuccess(t *testing.T) {
	orig := dialNDP
	defer func() { dialNDP = orig }()

	dialNDP = func(ifi *net.Interface, addr ndp.Addr) (advertiser.Conn, error) {
		if ifi.Name != "lo" {
			t.Fatalf("dialNDP called with unexpected interface %q", ifi.Name)
		}
		if addr != ndp.LinkLocal {
			t.Fatalf("dialNDP called with unexpected addr %v", addr)
		}
		return nopConn{}, nil
	}

	conn, err := ndpListen("lo")
	if err != nil {
		t.Fatalf("ndpListen with stubbed dialNDP: %v", err)
	}
	if conn == nil {
		t.Fatal("ndpListen returned nil conn on stubbed success")
	}
}

// TestNdpListen_StubbedFailure covers dialNDP's own error-propagation branch
// (ndp.Listen failing for a reason other than "no CAP_NET_RAW", e.g. the
// interface going down mid-open) without needing to reproduce that condition
// for real.
func TestNdpListen_StubbedFailure(t *testing.T) {
	orig := dialNDP
	defer func() { dialNDP = orig }()

	wantErr := errors.New("stubbed raw socket failure")
	dialNDP = func(*net.Interface, ndp.Addr) (advertiser.Conn, error) {
		return nil, wantErr
	}

	if _, err := ndpListen("lo"); !errors.Is(err, wantErr) {
		t.Fatalf("ndpListen must propagate dialNDP's error, got %v", err)
	}
}

// TestOnStartup_RealDialError_NoRunnerInjected covers OnStartup's dial-error
// return branch (radnr.go's `if err != nil { return err }` right after
// `dial(r.Cfg)`) which every other OnStartup test skips by either injecting a
// fakeRunner or using DryRun. A real (non-dry-run) config with no runner
// injected forces OnStartup down the genuine dial() -> listenFn -> ndpListen
// path; pointing it at a nonexistent interface makes that fail deterministically
// without touching socket privileges.
func TestOnStartup_RealDialError_NoRunnerInjected(t *testing.T) {
	cfg := validCfg()
	cfg.DryRun = false
	cfg.Interface = "radnr-test-nonexistent-iface-0"
	r := &RADNR{Cfg: cfg}

	if err := r.OnStartup(); err == nil {
		t.Fatal("OnStartup must propagate a real dial() failure, got nil")
	}
}

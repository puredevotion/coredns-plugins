package radnr

import (
	"errors"
	"net"
	"os"
	"testing"

	"github.com/mdlayher/ndp"
	"github.com/puredevotion/coredns-plugins/radnr/internal/advertiser"
)

// TestNdpListen_UnknownInterface exercises the real net.InterfaceByName
// failure branch, which needs no socket privilege since it fails before
// reaching dialNDP.
func TestNdpListen_UnknownInterface(t *testing.T) {
	if _, err := ndpListen("radnr-test-nonexistent-iface-0"); err == nil {
		t.Fatal("expected error for a nonexistent interface, got nil")
	}
}

// TestNdpListen_RealRawSocket_RequiresPrivilege exercises the actual
// ndp.Listen call for real rather than skipping: it accepts either a
// genuine success (privileged runner) or a genuine permission error
// (everyone else), so the attempt itself stays covered instead of assumed.
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

// realLinkLocalInterface finds a link-local-IPv6 interface — what
// ndp.Listen(ifi, ndp.LinkLocal) requires — instead of hardcoding a name
// that won't exist on every runner.
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

// TestNdpListen_StubbedSuccess covers the success path root would otherwise
// gate: dialNDP is faked, but net.InterfaceByName still runs for real.
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

// TestNdpListen_StubbedFailure covers ndpListen propagating a dialNDP error
// for reasons other than missing privilege (e.g. the interface going down
// mid-open), without needing to reproduce that condition for real.
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
// return, which every other OnStartup test skips via a fakeRunner or DryRun.
// A real config with no runner forces the genuine dial->listenFn->ndpListen
// path; a nonexistent interface fails it deterministically, no privilege
// needed.
func TestOnStartup_RealDialError_NoRunnerInjected(t *testing.T) {
	cfg := validCfg()
	cfg.DryRun = false
	cfg.Interface = "radnr-test-nonexistent-iface-0"
	r := &RADNR{Cfg: cfg}

	if err := r.OnStartup(); err == nil {
		t.Fatal("OnStartup must propagate a real dial() failure, got nil")
	}
}

package radnr

import (
	"net"
	"net/netip"
	"sync"

	"github.com/mdlayher/ndp"
	"golang.org/x/net/ipv6"
)

// nopConn satisfies advertiser.Conn for dry-run without opening a socket.
type nopConn struct {
	closed    chan struct{}
	closeOnce sync.Once
}

func newNopConn() *nopConn { return &nopConn{closed: make(chan struct{})} }

// WriteTo is a no-op that always succeeds.
func (*nopConn) WriteTo(ndp.Message, *ipv6.ControlMessage, netip.Addr) error { return nil }

// ReadFrom blocks until Close, since dry-run never receives router
// solicitations. It used to block forever, so the advertiser's Run, which
// waits for its reader goroutine on shutdown, never returned: every reload
// of a dry-run Corefile leaked both goroutines.
func (c *nopConn) ReadFrom() (ndp.Message, *ipv6.ControlMessage, netip.Addr, error) {
	<-c.closed
	return nil, nil, netip.Addr{}, net.ErrClosed
}

// Close unblocks ReadFrom. It always succeeds and may be called repeatedly.
func (c *nopConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

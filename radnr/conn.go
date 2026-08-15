package radnr

import (
	"net/netip"

	"github.com/mdlayher/ndp"
	"golang.org/x/net/ipv6"
)

// nopConn satisfies advertiser.Conn for dry-run without opening a socket.
type nopConn struct{}

// WriteTo is a no-op that always succeeds.
func (nopConn) WriteTo(ndp.Message, *ipv6.ControlMessage, netip.Addr) error { return nil }

// ReadFrom blocks forever, since dry-run never receives router solicitations.
func (nopConn) ReadFrom() (ndp.Message, *ipv6.ControlMessage, netip.Addr, error) {
	select {}
}

// Close is a no-op that always succeeds.
func (nopConn) Close() error { return nil }

package radnr

import (
	"net/netip"

	"github.com/mdlayher/ndp"
	"golang.org/x/net/ipv6"
)

// nopConn satisfies advertiser.Conn for dry-run without opening a socket.
type nopConn struct{}

func (nopConn) WriteTo(ndp.Message, *ipv6.ControlMessage, netip.Addr) error { return nil }
func (nopConn) ReadFrom() (ndp.Message, *ipv6.ControlMessage, netip.Addr, error) {
	select {}
}
func (nopConn) Close() error { return nil }

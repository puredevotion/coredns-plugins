// Package radnr is a CoreDNS plugin that advertises an encrypted DNS resolver
// to the LAN via IPv6 Router Advertisements carrying the RFC 9463 DNR option
// (and optionally RFC 8106 RDNSS).
//
// Unlike most plugins it does NOT handle DNS queries — like the health and
// metrics plugins it is a listener-only plugin that runs a background goroutine
// from OnStartup and shuts it down on OnShutdown/OnReload. It deliberately does
// not register a DNS handler (no AddPlugin in setup).
//
// SAFETY: a second RA sender can disrupt LAN IPv6. The plugin defaults to a
// non-default-router RA (RouterLifetime=0) and refuses to advertise prefixes;
// see internal/config for the enforced invariants.
//
//nolint:misspell // adn/ADN throughout this file: RFC 9463 Authentication Domain Name, not a typo for and/AND
package radnr

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"

	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/mdlayher/ndp"
	"golang.org/x/net/ipv6"

	"github.com/puredevotion/coredns-plugins/radnr/internal/advertiser"
	"github.com/puredevotion/coredns-plugins/radnr/internal/config"
)

// pluginName is the CoreDNS plugin name, used for both registration and logging.
const pluginName = "radnr"

var log = clog.NewWithPlugin(pluginName)

// runner is the advertisement loop; abstracted so tests inject a fake without
// opening an ICMPv6 socket.
type runner interface {
	Run(ctx context.Context) error
}

// RADNR is the plugin instance. It holds the validated config and manages the
// lifecycle of the background advertiser.
type RADNR struct {
	// Runner is set in tests; when nil, OnStartup builds a real advertiser.
	runner runner

	// The owner field is the caddy instance this RADNR was set up for (its
	// server-type context), compared by identity; see advertisers.
	owner any

	running *advertiserHandle

	Cfg config.Config
}

// advertiserHandle is one running advertiser, and the instance that
// started it.
type advertiserHandle struct {
	owner  any
	cancel context.CancelFunc
}

// advertisers holds every advertiser this process has started and not yet
// stopped. It exists because caddy can drop an instance without calling any
// of its shutdown hooks: when a reload fails after the new instance's
// OnStartup has already run (a later plugin's OnStartup errors, or a
// listener cannot bind), the new instance is discarded and the old one gets
// OnRestartFailed. Its advertiser would then keep sending RAs from a
// Corefile that never took effect, with nothing left that could stop it.
//
// So every OnStartup first stops the advertisers of every OTHER instance.
// At most one caddy instance is live, so that is always safe: on a
// successful reload the old instance's advertisers were already stopped by
// its OnRestart, and on a failed one this is what reclaims the discarded
// instance's. Advertisers of the same instance (several radnr blocks in one
// Corefile) are left alone. See verification/tla/PluginLifecycle.tla.
var (
	advertisersMu sync.Mutex
	advertisers   = map[*advertiserHandle]struct{}{}
)

// Name implements the CoreDNS plugin interface.
func (r *RADNR) Name() string { return pluginName }

// OnStartup validates the config, builds the advertiser (unless a runner was
// injected for tests), and launches the advertisement loop in a goroutine.
func (r *RADNR) OnStartup() error {
	if err := r.Cfg.Validate(); err != nil {
		return fmt.Errorf("validate config: %w", err)
	}

	run := r.runner
	if run == nil {
		conn, err := dial(&r.Cfg)
		if err != nil {
			return err
		}
		run = &advertiser.Advertiser{Conn: conn, Cfg: r.Cfg, Interval: advInterval}
	}

	// This RADNR's own advertiser may already be running too: when another
	// plugin's OnRestart fails, caddy runs every plugin's OnRestartFailed —
	// this — including ones whose OnRestart (OnShutdown) never ran. Both it
	// and any other instance's are stopped only now, once the replacement's
	// socket is open, so a failed dial leaves the old one advertising.
	ctx, cancel := context.WithCancel(context.Background())
	r.adopt(cancel)

	go func() {
		if err := run.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			log.Errorf("advertiser stopped: %v", err)
		}
	}()
	log.Infof("started: adn=%s iface=%s dry-run=%v unicast=%q",
		r.Cfg.ADN, r.Cfg.Interface, r.Cfg.DryRun, r.Cfg.UnicastTarget)
	return nil
}

// adopt registers cancel as r's running advertiser, stopping r's previous
// one and every advertiser some other caddy instance left running.
func (r *RADNR) adopt(cancel context.CancelFunc) {
	advertisersMu.Lock()
	defer advertisersMu.Unlock()
	for h := range advertisers {
		if h == r.running || h.owner != r.owner {
			h.cancel()
			delete(advertisers, h)
		}
	}
	r.running = &advertiserHandle{owner: r.owner, cancel: cancel}
	advertisers[r.running] = struct{}{}
}

// OnShutdown stops the advertisement loop. Safe to call if never started.
func (r *RADNR) OnShutdown() error {
	advertisersMu.Lock()
	defer advertisersMu.Unlock()
	if r.running != nil {
		r.running.cancel()
		delete(advertisers, r.running)
		r.running = nil
	}
	return nil
}

// listenFn opens a real ndp transport on the named interface. It is a package
// var so tests can inject a fake and exercise dial() without a real socket.
var listenFn = ndpListen

// dialNDP is its own package var, same seam as listenFn, because opening the
// raw ICMPv6 socket needs CAP_NET_RAW/root: tests fake this one call and
// still exercise ndpListen's real net.InterfaceByName lookup around it.
var dialNDP = func(ifi *net.Interface, addr ndp.Addr) (advertiser.Conn, error) {
	c, _, err := ndp.Listen(ifi, addr)
	if err != nil {
		return nil, fmt.Errorf("ndp listen: %w", err)
	}
	if err := becomeRouter(c); err != nil {
		if cerr := c.Close(); cerr != nil {
			log.Warningf("close ndp conn: %v", cerr)
		}
		return nil, err
	}
	return &routerConn{Conn: c, mtu: ifi.MTU}, nil
}

// allRouters is the all-routers link-local multicast address (RFC 4291
// §2.7.1), where hosts send Router Solicitations (RFC 4861 §6.3.7).
var allRouters = netip.MustParseAddr("ff02::2")

// routerSocket is the part of *ndp.Conn becomeRouter configures.
type routerSocket interface {
	JoinGroup(group netip.Addr) error
	SetControlMessage(cf ipv6.ControlFlags, on bool) error
}

// becomeRouter makes an ndp socket hear what a router must. RFC 4861
// §6.2.2: "A router MUST join the all-routers multicast address on an
// advertising interface." Without it RSes reach this socket only if the
// kernel happens to have joined ff02::2 already, as Linux does when
// forwarding is on. It also asks for each packet's hop limit, which §6.1.1
// validation needs.
func becomeRouter(c routerSocket) error {
	if err := c.JoinGroup(allRouters); err != nil {
		return fmt.Errorf("join all-routers group %s: %w", allRouters, err)
	}
	if err := c.SetControlMessage(ipv6.FlagHopLimit, true); err != nil {
		return fmt.Errorf("enable hop limit control messages: %w", err)
	}
	return nil
}

// routerConn reads NDP messages like ndp.Conn.ReadFrom, but also drops a
// message whose ICMP Code is not 0, which ndp.ParseMessage does not check
// and RFC 4861 §6.1.1 requires of a Router Solicitation.
type routerConn struct {
	*ndp.Conn
	mtu int
}

// ReadFrom returns the next well-formed NDP message with ICMP Code 0.
func (c *routerConn) ReadFrom() (ndp.Message, *ipv6.ControlMessage, netip.Addr, error) {
	b := make([]byte, max(c.mtu, minIPv6MTU))
	for {
		n, cm, from, err := c.ReadRaw(b)
		if err != nil {
			return nil, nil, netip.Addr{}, fmt.Errorf("ndp read: %w", err)
		}
		if m, ok := parseNDP(b[:n]); ok {
			return m, cm, from, nil
		}
	}
}

// minIPv6MTU is RFC 8200 §5's minimum link MTU, the smallest read buffer
// that holds any packet the link can carry.
const minIPv6MTU = 1280

// parseNDP parses one ICMPv6 message, refusing a non-zero ICMP Code (octet
// 1, RFC 4443 §2.1) as well as everything ndp.ParseMessage refuses.
func parseNDP(b []byte) (ndp.Message, bool) {
	if len(b) < 2 || b[1] != 0 {
		return nil, false
	}
	m, err := ndp.ParseMessage(b)
	if err != nil {
		return nil, false
	}
	return m, true
}

// ndpListen opens a real ndp transport on the named interface.
func ndpListen(name string) (advertiser.Conn, error) {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return nil, fmt.Errorf("lookup interface %q: %w", name, err)
	}
	return dialNDP(ifi, ndp.LinkLocal)
}

// dial returns a no-op conn for dry-run, otherwise opens a real ndp transport.
func dial(cfg *config.Config) (advertiser.Conn, error) {
	if cfg.DryRun {
		return newNopConn(), nil
	}
	return listenFn(cfg.Interface)
}

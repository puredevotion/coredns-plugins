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
package radnr

import (
	"context"
	"net"

	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/mdlayher/ndp"

	"github.com/puredevotion/coredns-plugins/radnr/internal/advertiser"
	"github.com/puredevotion/coredns-plugins/radnr/internal/config"
)

var log = clog.NewWithPlugin("radnr")

// runner is the advertisement loop; abstracted so tests inject a fake without
// opening an ICMPv6 socket.
type runner interface {
	Run(ctx context.Context) error
}

// RADNR is the plugin instance. It holds the validated config and manages the
// lifecycle of the background advertiser.
type RADNR struct {
	Cfg config.Config

	// runner is set in tests; when nil, OnStartup builds a real advertiser.
	runner runner

	cancel context.CancelFunc
}

// Name implements the CoreDNS plugin interface.
func (r *RADNR) Name() string { return "radnr" }

// OnStartup validates the config, builds the advertiser (unless a runner was
// injected for tests), and launches the advertisement loop in a goroutine.
func (r *RADNR) OnStartup() error {
	if err := r.Cfg.Validate(); err != nil {
		return err
	}

	run := r.runner
	if run == nil {
		conn, err := dial(r.Cfg)
		if err != nil {
			return err
		}
		run = &advertiser.Advertiser{Conn: conn, Cfg: r.Cfg, Interval: advInterval}
	}

	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel

	go func() {
		if err := run.Run(ctx); err != nil && err != context.Canceled {
			log.Errorf("advertiser stopped: %v", err)
		}
	}()
	log.Infof("started: adn=%s iface=%s dry-run=%v unicast=%q",
		r.Cfg.ADN, r.Cfg.Interface, r.Cfg.DryRun, r.Cfg.UnicastTarget)
	return nil
}

// OnShutdown stops the advertisement loop. Safe to call if never started.
func (r *RADNR) OnShutdown() error {
	if r.cancel != nil {
		r.cancel()
		r.cancel = nil
	}
	return nil
}

// listenFn opens a real ndp transport on the named interface. It is a package
// var so tests can inject a fake and exercise dial() without a real socket.
var listenFn = ndpListen

// dialNDP opens the actual ICMPv6 raw socket via ndp.Listen. Factored out of
// ndpListen into its own package var (same seam pattern as listenFn) because
// opening a raw ICMPv6 socket requires CAP_NET_RAW/root — unavailable in an
// unprivileged sandbox/CI — so tests substitute a fake here to cover
// ndpListen's success path for real, while still exercising the genuine
// net.InterfaceByName lookup around it.
var dialNDP = func(ifi *net.Interface, addr ndp.Addr) (advertiser.Conn, error) {
	c, _, err := ndp.Listen(ifi, addr)
	if err != nil {
		return nil, err
	}
	return c, nil
}

func ndpListen(name string) (advertiser.Conn, error) {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	return dialNDP(ifi, ndp.LinkLocal)
}

// dial returns a no-op conn for dry-run, otherwise opens a real ndp transport.
func dial(cfg config.Config) (advertiser.Conn, error) {
	if cfg.DryRun {
		return nopConn{}, nil
	}
	return listenFn(cfg.Interface)
}

// Package advertiser builds RFC 9463 DNR-bearing Router Advertisements and
// sends them on a single interface. It is deliberately conservative: the RA is
// not a default router (RouterLifetime=0), never carries PrefixInformation, and
// supports a dry-run mode and a unicast-to-one-client mode for safe spikes.
package advertiser

import (
	"context"
	"log"
	"math/rand" // nosemgrep: go.lang.security.audit.crypto.math-random-used -- RFC 4861 timing jitter (nextInterval), not a security-sensitive value
	"net/netip"
	"time"

	"github.com/mdlayher/ndp"
	"github.com/puredevotion/coredns-plugins/radnr/internal/config"
	"github.com/puredevotion/coredns-plugins/radnr/pkg/dnr"
	"github.com/puredevotion/coredns-plugins/radnr/pkg/svcparams"
	"golang.org/x/net/ipv6"
)

var allNodes = netip.MustParseAddr("ff02::1")

// minDelayBetweenRAs is RFC 4861 §6.2.6's MIN_DELAY_BETWEEN_RAS: a solicited RA
// must not be sent less than this long after the previous RA (solicited or
// unsolicited) on the same interface. A package var (not a const) so tests can
// shrink it instead of waiting out the real 3s.
var minDelayBetweenRAs = 3 * time.Second

// Conn is the subset of *ndp.Conn the advertiser needs; injectable for tests.
type Conn interface {
	WriteTo(m ndp.Message, cm *ipv6.ControlMessage, dst netip.Addr) error
	ReadFrom() (ndp.Message, *ipv6.ControlMessage, netip.Addr, error)
	Close() error
}

// Advertiser periodically emits RAs and answers Router Solicitations.
type Advertiser struct {
	Conn     Conn
	Cfg      config.Config
	Interval time.Duration
}

// BuildRA constructs the Router Advertisement for the given config.
func BuildRA(c config.Config) (*ndp.RouterAdvertisement, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}

	sp, err := svcparams.Encode(svcparams.Params{
		ALPN:    c.ALPN,
		Port:    c.Port,
		DohPath: c.DohPath,
	})
	if err != nil {
		return nil, err
	}

	var addrs []netip.Addr
	for _, a := range c.Addrs {
		addrs = append(addrs, netip.MustParseAddr(a))
	}

	raw, err := dnr.EncryptedDNS{
		ServicePriority: 1,
		Lifetime:        3600,
		ADN:             c.ADN,
		Addrs:           addrs,
		SvcParams:       sp,
	}.Marshal()
	if err != nil {
		return nil, err
	}

	ra := &ndp.RouterAdvertisement{
		CurrentHopLimit:      0,
		ManagedConfiguration: false,
		OtherConfiguration:   false,
		RouterLifetime:       time.Duration(c.RouterLifetime) * time.Second,
		Options: []ndp.Option{
			&ndp.RawOption{
				Type:   dnr.OptionType,
				Length: raw[1],  // units of 8 octets, as Marshal computed
				Value:  raw[2:], // option body (everything after Type+Length)
			},
		},
	}

	if c.AdvertiseRDNSS {
		ra.Options = append(ra.Options, &ndp.RecursiveDNSServer{
			Lifetime: time.Hour,
			Servers:  addrs,
		})
	}
	return ra, nil
}

// nextInterval picks a randomized periodic-RA delay per RFC 4861 §6.2.1: the
// actual interval MUST be a uniform random value between MinRtrAdvInterval and
// MaxRtrAdvInterval, not a fixed period, so multiple advertisers on a link
// don't stay synchronized. a.Interval is treated as MaxRtrAdvInterval; Min is
// derived using the RFC's default ratio (Min = 0.33*Max), floored at 3s (the
// RFC's absolute minimum for MinRtrAdvInterval).
func (a *Advertiser) nextInterval() time.Duration {
	max := a.Interval
	min := max / 3
	if min < minDelayBetweenRAs {
		min = minDelayBetweenRAs
	}
	if min >= max {
		return max
	}
	//nolint:gosec // G404: RFC 4861 timing jitter, not a security-sensitive value; crypto/rand is the wrong tool here, not a safer one.
	return min + time.Duration(rand.Int63n(int64(max-min)))
}

// Run advertises until ctx is cancelled: periodically (at a randomized
// interval per RFC 4861 §6.2.1) and solicited (in response to a Router
// Solicitation per §6.2.6, rate-limited to at most one send per
// minDelayBetweenRAs regardless of trigger). Send errors are logged, not
// fatal. Reads for Router Solicitations run inline in this goroutine — RAs are
// too latency-insensitive here to need a separate reader goroutine.
func (a *Advertiser) Run(ctx context.Context) error {
	ra, err := BuildRA(a.Cfg)
	if err != nil {
		return err
	}

	dst := allNodes
	if a.Cfg.UnicastTarget != "" {
		dst = netip.MustParseAddr(a.Cfg.UnicastTarget)
	}

	var lastSent time.Time
	send := func() {
		lastSent = time.Now()
		if a.Cfg.DryRun {
			log.Printf("ra-dnr: [dry-run] would send RA to %s (ADN=%s)", dst, a.Cfg.ADN)
			return
		}
		if err := a.Conn.WriteTo(ra, nil, dst); err != nil {
			log.Printf("ra-dnr: send error (continuing): %v", err)
		}
	}

	select {
	case <-ctx.Done():
		_ = a.Conn.Close()
		return ctx.Err()
	default:
	}
	send() // initial advertisement

	rs := make(chan netip.Addr)
	rsDone := make(chan struct{})
	go func() {
		defer close(rsDone)
		for {
			m, _, from, err := a.Conn.ReadFrom()
			if err != nil {
				return // conn closed or ctx cancelled elsewhere
			}
			if _, ok := m.(*ndp.RouterSolicitation); !ok {
				continue
			}
			select {
			case rs <- from:
			case <-ctx.Done():
				return
			}
		}
	}()

	t := time.NewTimer(a.nextInterval())
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			_ = a.Conn.Close() // unblock the RS-reader goroutine's ReadFrom
			<-rsDone
			return ctx.Err()
		case <-t.C:
			send()
			t.Reset(a.nextInterval())
		case from := <-rs:
			if since := time.Since(lastSent); since < minDelayBetweenRAs {
				log.Printf("ra-dnr: RS from %s rate-limited (%v since last RA)", from, since)
				continue
			}
			log.Printf("ra-dnr: solicited RA for RS from %s", from)
			send()
		}
	}
}

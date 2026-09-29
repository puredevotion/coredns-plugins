// Package advertiser builds RFC 9463 DNR-bearing Router Advertisements and
// sends them on a single interface. It is deliberately conservative: the RA is
// not a default router (RouterLifetime=0), never carries PrefixInformation, and
// supports a dry-run mode and a unicast-to-one-client mode for safe spikes.
package advertiser

import (
	"context"
	"fmt"
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

// defaultLifetime is the DNR option Lifetime field, in seconds, advertised
// alongside the encrypted-DNS resolver information.
const defaultLifetime = 3600

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
func BuildRA(c *config.Config) (*ndp.RouterAdvertisement, error) {
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}

	sp, err := svcparams.Encode(svcparams.Params{
		ALPN:    c.ALPN,
		Port:    c.Port,
		DohPath: c.DohPath,
	})
	if err != nil {
		return nil, fmt.Errorf("encode svcparams: %w", err)
	}

	var addrs []netip.Addr
	for _, a := range c.Addrs {
		addrs = append(addrs, netip.MustParseAddr(a))
	}

	raw, err := dnr.EncryptedDNS{
		ServicePriority: 1,
		Lifetime:        defaultLifetime,
		ADN:             c.ADN, //nolint:misspell // ADN: RFC 9463 Authentication Domain Name, not a typo for AND
		Addrs:           addrs,
		SvcParams:       sp,
	}.Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshal encrypted-dns option: %w", err)
	}

	ra := &ndp.RouterAdvertisement{
		CurrentHopLimit:      0,
		ManagedConfiguration: false,
		OtherConfiguration:   false,
		RouterLifetime:       time.Duration(c.RouterLifetime) * time.Second,
		Options: []ndp.Option{
			&ndp.RawOption{
				Type:   dnr.OptionType,
				Length: raw[1],  // Units of 8 octets, as Marshal computed.
				Value:  raw[2:], // Option body (everything after Type+Length).
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

// minIntervalRatioDivisor implements RFC 4861 §6.2.1's default ratio for
// deriving MinRtrAdvInterval from MaxRtrAdvInterval (Min = 0.33*Max).
const minIntervalRatioDivisor = 3

// nextInterval picks a randomised periodic-RA delay per RFC 4861 §6.2.1: the
// actual interval MUST be a uniform random value between MinRtrAdvInterval and
// MaxRtrAdvInterval, not a fixed period, so multiple advertisers on a link
// don't stay synchronised; a.Interval is treated as MaxRtrAdvInterval, and Min
// is derived using the RFC's default ratio, floored at 3s (the RFC's
// absolute minimum for MinRtrAdvInterval).
func (a *Advertiser) nextInterval() time.Duration {
	maxInterval := a.Interval
	minInterval := max(maxInterval/minIntervalRatioDivisor, minDelayBetweenRAs)
	if minInterval >= maxInterval {
		return maxInterval
	}
	//nolint:gosec // G404: RFC 4861 timing jitter, not a security-sensitive value; crypto/rand is the wrong tool here, not a safer one.
	return minInterval + time.Duration(rand.Int63n(int64(maxInterval-minInterval)))
}

// readSolicitations runs the inline Router-Solicitation reader loop: it reads
// from a.Conn until the connection is closed or ctx is cancelled, forwarding
// each Router Solicitation's source address on rs, and closes rsDone on exit.
func (a *Advertiser) readSolicitations(ctx context.Context, rs chan<- netip.Addr, rsDone chan<- struct{}) {
	defer close(rsDone)
	for {
		m, _, from, err := a.Conn.ReadFrom()
		if err != nil {
			return // Conn closed or ctx cancelled elsewhere.
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
}

// Run advertises until ctx is cancelled: periodically (at a randomised
// interval per RFC 4861 §6.2.1) and solicited (in response to a Router
// Solicitation per §6.2.6, rate-limited to at most one send per
// minDelayBetweenRAs regardless of trigger). Send errors are logged, not
// fatal. Reads for Router Solicitations run inline in this goroutine — RAs are
// too latency-insensitive here to need a separate reader goroutine.
func (a *Advertiser) Run(ctx context.Context) error {
	ra, err := BuildRA(&a.Cfg)
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
			log.Printf("ra-dnr: [dry-run] would send RA to %s (ADN=%s)", dst, a.Cfg.ADN) //nolint:misspell // ADN: RFC 9463 Authentication Domain Name, not a typo for AND
			return
		}
		if err := a.Conn.WriteTo(ra, nil, dst); err != nil {
			log.Printf("ra-dnr: send error (continuing): %v", err)
		}
	}

	select {
	case <-ctx.Done():
		if err := a.Conn.Close(); err != nil {
			log.Printf("ra-dnr: close conn: %v", err)
		}
		return fmt.Errorf("advertiser run: %w", ctx.Err())
	default:
	}
	send() // Initial advertisement.

	rs := make(chan netip.Addr)
	rsDone := make(chan struct{})
	go a.readSolicitations(ctx, rs, rsDone)

	t := time.NewTimer(a.nextInterval())
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			if err := a.Conn.Close(); err != nil { // Unblock the RS-reader goroutine's ReadFrom.
				log.Printf("ra-dnr: close conn: %v", err)
			}
			<-rsDone
			return fmt.Errorf("advertiser run: %w", ctx.Err())
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

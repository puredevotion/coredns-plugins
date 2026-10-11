package cookie

import (
	"context"
	"encoding/hex"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/metadata"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
)

const pluginName = "cookie"

// secretSince is when the generating secret was installed, Unix seconds, for
// the secret_age_seconds gauge. Process-wide: the last setup wins.
var secretSince atomic.Int64

// mode is what to do with a UDP request that carried a COOKIE option without
// a valid server cookie (RFC 7873 §5.2.3 and §5.2.4).
type mode int

const (
	// ModePermissive serves it, with a fresh cookie so the client can
	// bootstrap (§5.2.3 option 3).
	modePermissive mode = iota
	// ModeEnforce answers BADCOOKIE with a fresh cookie (option 2). The reply
	// is the query plus an OPT RR: it amplifies nothing.
	modeEnforce
)

func (m mode) String() string {
	if m == modeEnforce {
		return "enforce"
	}
	return "permissive"
}

type config struct {
	verifyOnly [][16]byte
	mode       mode
	secret     [16]byte
}

// status is the outcome of classifying one request.
type status string

const (
	statusNone          status = caseNoCookie
	statusMalformed     status = caseMalformed
	statusClientOnly    status = caseClientOnly
	statusInvalidServer status = caseInvalidServer
	statusValid         status = caseValid
	statusValidPrevious status = caseValidPrevious
)

func (s status) validated() bool { return s == statusValid || s == statusValidPrevious }

// Cookie implements DNS Cookies (RFC 7873, RFC 9018) for the server side.
type Cookie struct {
	Next plugin.Handler
	now  func() time.Time
	keys secrets
	mode mode
}

func newCookie(cfg config) *Cookie {
	return &Cookie{
		mode: cfg.mode,
		keys: secrets{generate: cfg.secret, verifyOnly: cfg.verifyOnly},
		now:  time.Now,
	}
}

// Name implements plugin.Handler.
func (c *Cookie) Name() string { return pluginName }

// inspected is what one request's COOKIE option comes to.
type inspected struct {
	ip     netip.Addr
	status status
	client [clientCookieLen]byte
}

// inspect classifies the request's COOKIE option. Only the first COOKIE option
// is considered (RFC 7873 §5.2: "In all cases of multiple COOKIE options in a
// request, only the first (the one closest to the DNS header) is considered.
// All others are ignored.").
func (c *Cookie) inspect(state *request.Request) inspected {
	opt := state.Req.IsEdns0()
	if opt == nil {
		return inspected{status: statusNone}
	}
	var raw *dns.EDNS0_COOKIE
	for _, o := range opt.Option {
		if ck, ok := o.(*dns.EDNS0_COOKIE); ok {
			raw = ck
			break
		}
	}
	if raw == nil {
		return inspected{status: statusNone}
	}

	data, err := hex.DecodeString(raw.Cookie)
	if err != nil {
		return inspected{status: statusMalformed}
	}
	cl := classify(len(data))
	if cl == classMalformed {
		return inspected{status: statusMalformed}
	}

	var in inspected
	copy(in.client[:], data[:clientCookieLen])
	in.ip = clientAddr(state)
	if cl == classClientOnly {
		in.status = statusClientOnly
		return in
	}
	if !in.ip.IsValid() {
		// No usable source address to verify against: not validated.
		in.status = statusInvalidServer
		return in
	}
	in.status = c.keys.check(in.client, data[clientCookieLen:], in.ip, c.timestamp())
	return in
}

// timestamp is the current time as a 32-bit Unix timestamp. Reduced modulo
// 2^32 on purpose: that is the field's width (RFC 9018 §4.3) and every
// comparison is in serial arithmetic.
func (c *Cookie) timestamp() uint32 {
	return uint32(c.now().Unix()) //nolint:gosec // G115: modulo 2^32 is the specified timestamp width
}

// clientAddr is the request's source address, zone stripped and an
// IPv4-mapped IPv6 address unmapped to IPv4, so a dual-stack listener hashes
// the same bytes however the client arrived.
func clientAddr(state *request.Request) netip.Addr {
	ip, err := netip.ParseAddr(state.IP())
	if err != nil {
		return netip.Addr{}
	}
	return ip.WithZone("").Unmap()
}

// ServeDNS implements plugin.Handler.
func (c *Cookie) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}
	in := c.inspect(&state)
	requests.WithLabelValues(string(in.status)).Inc()

	if in.status == statusNone {
		// RFC 7873 §5.2.1: "the server responds to the request as if the
		// server doesn't implement the COOKIE option" (§5.2.1).
		return plugin.NextOrFailure(c.Name(), c.Next, ctx, w, r) //nolint:wrapcheck // chain errors pass through
	}
	if in.status == statusMalformed {
		formerrs.Inc()
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeFormatError)
		return dns.RcodeSuccess, w.WriteMsg(m) //nolint:wrapcheck // response already written; the error is the writer's
	}

	cw := &cookieWriter{ResponseWriter: w, option: c.option(in)}
	if opt := r.IsEdns0(); opt != nil {
		cw.udpSize, cw.do = opt.UDPSize(), opt.Do()
	}

	// §5.2.3 and §5.2.4 on UDP, enforce mode: BADCOOKIE. Over TCP (and any
	// transport that is not plain UDP) "the server SHOULD take the
	// authentication provided by the use of TCP into account and SHOULD choose
	// (3)", and answering BADCOOKIE there risks "an indefinite loop of
	// retries".
	if !in.status.validated() && c.mode == modeEnforce && state.Proto() == "udp" {
		badCookies.Inc()
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeBadCookie)
		return dns.RcodeSuccess, cw.WriteMsg(m)
	}

	return plugin.NextOrFailure(c.Name(), c.Next, ctx, cw, r) //nolint:wrapcheck // chain errors pass through
}

// option is the COOKIE option for the response: the request's client cookie and
// a freshly generated server cookie under the generating secret. Always fresh:
// RFC 9018 §4.3 asks for a new one if the received cookie is over half an hour
// old, RFC 7873 §7.1 for a new one if the old secret was used, and a new one
// every time satisfies both and removes the branch.
func (c *Cookie) option(in inspected) *dns.EDNS0_COOKIE {
	server := serverCookie(c.keys.generate, in.client, c.timestamp(), in.ip)
	data := make([]byte, 0, verifyOptionLen)
	data = append(data, in.client[:]...)
	data = append(data, server[:]...)
	return &dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: hex.EncodeToString(data)}
}

// cookieWriter puts the response cookie on every message written through it.
type cookieWriter struct {
	dns.ResponseWriter
	option  *dns.EDNS0_COOKIE
	udpSize uint16
	do      bool
}

// WriteMsg sets the response's single COOKIE option to ours. Any COOKIE option
// already there is dropped first: CoreDNS up to v1.14.6 copies the request's
// into the response unvalidated (request/edns0.go), and a response must carry
// one, not that echo and ours.
func (w *cookieWriter) WriteMsg(m *dns.Msg) error {
	opt := m.IsEdns0()
	if opt == nil {
		m.SetEdns0(w.udpSize, w.do)
		opt = m.IsEdns0()
	}
	kept := make([]dns.EDNS0, 0, len(opt.Option)+1)
	for _, o := range opt.Option {
		if _, isCookie := o.(*dns.EDNS0_COOKIE); !isCookie {
			kept = append(kept, o)
		}
	}
	kept = append(kept, w.option)
	opt.Option = kept
	return w.ResponseWriter.WriteMsg(m) //nolint:wrapcheck // the underlying writer's error
}

// Metadata implements metadata.Provider: the request's cookie case, as
// cookie/status, for plugins and expressions that act on it.
func (c *Cookie) Metadata(ctx context.Context, state request.Request) context.Context { //nolint:gocritic // hugeParam: the signature is fixed by metadata.Provider
	s := c.inspect(&state).status
	metadata.SetValueFunc(ctx, pluginName+"/status", func() string { return string(s) })
	return ctx
}

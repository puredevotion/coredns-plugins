package cookie

import (
	"bytes"
	"context"
	"encoding/hex"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/miekg/dns"
	dto "github.com/prometheus/client_model/go"
)

const (
	secretA  = "e5e973e5a6b2a43f48e7dc849e37bfcf" //nolint:gosec // G101: RFC 9018 Appendix A test secret
	secretB  = "445536bcd2513298075a5d379663c962" //nolint:gosec // G101: RFC 9018 Appendix A test secret
	clientIP = "198.51.100.100"
)

var epoch = time.Unix(1_700_000_000, 0)

// recordingWriter keeps what the plugin wrote and reports a chosen peer. The
// transport CoreDNS reports (state.Proto) comes from the type of RemoteAddr.
type recordingWriter struct {
	dns.ResponseWriter
	remote net.Addr
	msg    *dns.Msg
}

func (w *recordingWriter) WriteMsg(m *dns.Msg) error { w.msg = m; return nil }
func (w *recordingWriter) RemoteAddr() net.Addr      { return w.remote }

func udpFrom(ip string) net.Addr { return &net.UDPAddr{IP: net.ParseIP(ip), Port: 4711} }
func tcpFrom(ip string) net.Addr { return &net.TCPAddr{IP: net.ParseIP(ip), Port: 4711} }

// downstream is the rest of the chain. It records whether it ran and answers
// with an A record. With echoCookie set it behaves as CoreDNS up to v1.14.6
// does, copying the request's COOKIE option into the response unvalidated
// (request/edns0.go supportedOptions). With nsid set it adds an unrelated
// option that must survive.
type downstream struct {
	called     int
	echoCookie bool
	nsid       bool
}

func (d *downstream) Name() string { return "downstream" }

func (d *downstream) ServeDNS(_ context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	d.called++
	m := new(dns.Msg)
	m.SetReply(r)
	m.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   net.ParseIP("192.0.2.1"),
	}}
	if o := r.IsEdns0(); o != nil {
		out := new(dns.OPT)
		out.Hdr.Name = "."
		out.Hdr.Rrtype = dns.TypeOPT
		out.SetUDPSize(o.UDPSize())
		for _, opt := range o.Option {
			if c, ok := opt.(*dns.EDNS0_COOKIE); ok && d.echoCookie {
				out.Option = append(out.Option, c)
			}
		}
		if d.nsid {
			out.Option = append(out.Option, &dns.EDNS0_NSID{Code: dns.EDNS0NSID, Nsid: "6e73"})
		}
		m.Extra = append(m.Extra, out)
	}
	return 0, w.WriteMsg(m) //nolint:wrapcheck // test double
}

var _ plugin.Handler = (*downstream)(nil)

// newPlugin builds a Cookie with the fixed clock `*now`.
func newPlugin(t *testing.T, m mode, gen string, verifyOnly ...string) (*Cookie, *downstream, *time.Time) {
	t.Helper()
	now := epoch
	cfg := config{mode: m, secret: key16(t, gen)}
	for _, v := range verifyOnly {
		cfg.verifyOnly = append(cfg.verifyOnly, key16(t, v))
	}
	next := &downstream{}
	c := newCookie(cfg)
	c.Next = next
	c.now = func() time.Time { return now }
	return c, next, &now
}

// query builds a request for example.org. A with the given COOKIE option data
// (nil = no COOKIE option, and noOPT drops the OPT RR altogether).
func query(cookieData []byte, noOPT bool) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion("example.org.", dns.TypeA)
	if noOPT {
		return m
	}
	m.SetEdns0(1232, true)
	if cookieData != nil {
		o := m.IsEdns0()
		o.Option = append(o.Option, &dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: hex.EncodeToString(cookieData)})
	}
	return m
}

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }

// serve runs one request through the plugin and returns the response as a
// client would see it: packed and unpacked, so an extended RCODE that did not
// survive the wire shows up as the wrong code.
func serve(t *testing.T, c *Cookie, r *dns.Msg, remote net.Addr) *dns.Msg {
	t.Helper()
	w := &recordingWriter{remote: remote}
	if _, err := c.ServeDNS(context.Background(), w, r); err != nil {
		t.Fatalf("ServeDNS: %v", err)
	}
	if w.msg == nil {
		t.Fatal("nothing was written")
	}
	wire, err := w.msg.Pack()
	if err != nil {
		t.Fatalf("response does not pack: %v", err)
	}
	out := new(dns.Msg)
	if err := out.Unpack(wire); err != nil {
		t.Fatalf("response does not unpack: %v", err)
	}
	return out
}

// cookies returns every COOKIE option in m's OPT, as raw bytes.
func cookies(t *testing.T, m *dns.Msg) [][]byte {
	t.Helper()
	var out [][]byte
	if o := m.IsEdns0(); o != nil {
		for _, opt := range o.Option {
			if c, ok := opt.(*dns.EDNS0_COOKIE); ok {
				b, err := hex.DecodeString(c.Cookie)
				if err != nil {
					t.Fatalf("cookie option is not hex: %v", err)
				}
				out = append(out, b)
			}
		}
	}
	return out
}

// onlyCookie asserts exactly one COOKIE option and returns it.
func onlyCookie(t *testing.T, m *dns.Msg) []byte {
	t.Helper()
	cs := cookies(t, m)
	if len(cs) != 1 {
		t.Fatalf("response has %d COOKIE options, want exactly 1", len(cs))
	}
	return cs[0]
}

// clientOnly returns the 8-byte option a client without a server cookie sends.
func clientOnly(t *testing.T) []byte {
	t.Helper()
	return mustHex(t, clientC)
}

// withServer returns the 24-byte option for a client that holds `server`.
func withServer(t *testing.T, server []byte) []byte {
	t.Helper()
	return append(mustHex(t, clientC), server...)
}

func mint(t *testing.T, secret string, ts uint32, ip string) []byte {
	t.Helper()
	c := serverCookie(key16(t, secret), client8(t, clientC), ts, mustAddr(ip))
	return c[:]
}

func unix32(tm time.Time) uint32 { return uint32(tm.Unix()) } //nolint:gosec // G115: modulo 2^32 is the timestamp width

// assertFresh checks the response cookie echoes the client cookie, is a
// 16-byte version-1 server cookie made under `secret` at `now` for `ip`, and
// so verifies. RFC 7873 §5.2.3: "it SHALL generate its own COOKIE option
// containing both the Client Cookie copied from the request and a Server
// Cookie it has generated".
func assertFresh(t *testing.T, resp *dns.Msg, secret string, now time.Time, ip string) {
	t.Helper()
	got := onlyCookie(t, resp)
	if len(got) != 24 {
		t.Fatalf("response cookie is %d bytes, want 24 (8 client + 16 server)", len(got))
	}
	if hex.EncodeToString(got[:8]) != clientC {
		t.Errorf("client cookie not echoed: got %x", got[:8])
	}
	want := mint(t, secret, unix32(now), ip)
	if hex.EncodeToString(got[8:]) != hex.EncodeToString(want) {
		t.Errorf("server cookie = %x, want a fresh one under the generating secret %x", got[8:], want)
	}
}

// 1. RFC 7873 §5.2.1: "If there is no OPT record or no COOKIE option present
// in the request, then the server responds to the request as if the server
// doesn't implement the COOKIE option" (§5.2.1).
func TestNoCookiePassesThrough(t *testing.T) {
	for _, tc := range []struct {
		r    *dns.Msg
		name string
	}{
		{name: "no OPT", r: query(nil, true)},
		{name: "OPT without COOKIE", r: query(nil, false)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, m := range []mode{modePermissive, modeEnforce} {
				c, next, _ := newPlugin(t, m, secretA)
				resp := serve(t, c, tc.r, udpFrom(clientIP))
				if next.called != 1 {
					t.Fatalf("mode %v: downstream called %d times, want 1", m, next.called)
				}
				if resp.Rcode != dns.RcodeSuccess {
					t.Errorf("mode %v: rcode %s", m, dns.RcodeToString[resp.Rcode])
				}
				if n := len(cookies(t, resp)); n != 0 {
					t.Errorf("mode %v: %d COOKIE options in the response, want none", m, n)
				}
			}
		})
	}
}

// 2. RFC 7873 §5.2.2: lengths other than 8 and 16..40 "then FORMERR is
// generated".
func TestMalformedIsFormerr(t *testing.T) {
	for _, n := range []int{0, 1, 7, 9, 15, 41, 64} {
		c, next, _ := newPlugin(t, modePermissive, secretA)
		resp := serve(t, c, query(make([]byte, n), false), udpFrom(clientIP))
		if resp.Rcode != dns.RcodeFormatError {
			t.Errorf("len %d: rcode %s, want FORMERR", n, dns.RcodeToString[resp.Rcode])
		}
		if next.called != 0 {
			t.Errorf("len %d: downstream ran for a malformed request", n)
		}
	}
}

// 3. Client cookie only, permissive: served, with a fresh cookie so the client
// can bootstrap (§5.2.3 option 3).
func TestClientOnlyPermissive(t *testing.T) {
	c, next, now := newPlugin(t, modePermissive, secretA)
	resp := serve(t, c, query(clientOnly(t), false), udpFrom(clientIP))
	if next.called != 1 || resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
		t.Fatalf("not served: called=%d rcode=%s answers=%d", next.called, dns.RcodeToString[resp.Rcode], len(resp.Answer))
	}
	assertFresh(t, resp, secretA, *now, clientIP)
}

// 4. Client cookie only, enforce, UDP: BADCOOKIE (extended RCODE 23) carrying
// a cookie, and the question section intact. It must survive Pack/Unpack: 23
// does not fit the header's four RCODE bits.
func TestClientOnlyEnforceUDP(t *testing.T) {
	c, next, now := newPlugin(t, modeEnforce, secretA)
	req := query(clientOnly(t), false)
	resp := serve(t, c, req, udpFrom(clientIP))
	if resp.Rcode != dns.RcodeBadCookie {
		t.Fatalf("rcode = %d (%s), want BADCOOKIE (23)", resp.Rcode, dns.RcodeToString[resp.Rcode])
	}
	if next.called != 0 {
		t.Error("downstream ran for a request answered BADCOOKIE")
	}
	if len(resp.Answer) != 0 {
		t.Error("a BADCOOKIE response carries an answer")
	}
	if !resp.Response || resp.Id != req.Id || len(resp.Question) != 1 || resp.Question[0].Name != "example.org." {
		t.Errorf("not a proper reply to the query: %+v", resp)
	}
	assertFresh(t, resp, secretA, *now, clientIP)
}

// 5. RFC 7873 §5.2.3: "If the request was received over TCP, the server
// SHOULD take the authentication provided by the use of TCP into account and
// SHOULD choose (3)", because (2) risks "an indefinite loop of retries".
func TestEnforceNeverBadCookieOverTCP(t *testing.T) {
	for _, cookie := range [][]byte{clientOnly(t), withServer(t, make([]byte, 16)), withServer(t, mint(t, secretB, 1, clientIP))} {
		c, next, now := newPlugin(t, modeEnforce, secretA)
		resp := serve(t, c, query(cookie, false), tcpFrom(clientIP))
		if resp.Rcode != dns.RcodeSuccess || next.called != 1 {
			t.Errorf("TCP: rcode %s called=%d, want a normal answer", dns.RcodeToString[resp.Rcode], next.called)
		}
		assertFresh(t, resp, secretA, *now, clientIP)
	}
}

// 6. RFC 7873 §5.2.4: an invalid server cookie is processed "as if the invalid
// Server Cookie was not present", whatever made it invalid.
func TestInvalidServerCookie(t *testing.T) {
	good := func(now time.Time) []byte { return mint(t, secretA, unix32(now), clientIP) }
	tests := []struct {
		name   string
		server func(now time.Time) []byte
		from   string
	}{
		{"wrong secret", func(now time.Time) []byte { return mint(t, secretB, unix32(now), clientIP) }, clientIP},
		{"other client address", good, "198.51.100.101"},
		{"too old", func(now time.Time) []byte { return mint(t, secretA, unix32(now)-3601, clientIP) }, clientIP},
		{"too far in the future", func(now time.Time) []byte { return mint(t, secretA, unix32(now)+301, clientIP) }, clientIP},
		{"truncated to 8 bytes", func(now time.Time) []byte { return good(now)[:8] }, clientIP},
		{"17 bytes", func(now time.Time) []byte { return append(good(now), 0) }, clientIP},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// permissive: served, with a fresh cookie for the real source.
			c, next, now := newPlugin(t, modePermissive, secretA)
			resp := serve(t, c, query(withServer(t, tc.server(*now)), false), udpFrom(tc.from))
			if resp.Rcode != dns.RcodeSuccess || next.called != 1 {
				t.Errorf("permissive: rcode %s called=%d", dns.RcodeToString[resp.Rcode], next.called)
			}
			assertFresh(t, resp, secretA, *now, tc.from)

			// Enforce over UDP: BADCOOKIE.
			c, next, now = newPlugin(t, modeEnforce, secretA)
			resp = serve(t, c, query(withServer(t, tc.server(*now)), false), udpFrom(tc.from))
			if resp.Rcode != dns.RcodeBadCookie || next.called != 0 {
				t.Errorf("enforce: rcode %s called=%d, want BADCOOKIE", dns.RcodeToString[resp.Rcode], next.called)
			}
		})
	}
}

// 7. RFC 7873 §5.2.5: a valid server cookie is served in both modes, with a
// COOKIE option in the response (here, always a fresh one: see the design
// doc).
func TestValidCookieServed(t *testing.T) {
	for _, m := range []mode{modePermissive, modeEnforce} {
		c, next, now := newPlugin(t, m, secretA)
		old := mint(t, secretA, unix32(*now)-1800, clientIP) // 30 min old: valid.
		resp := serve(t, c, query(withServer(t, old), false), udpFrom(clientIP))
		if resp.Rcode != dns.RcodeSuccess || next.called != 1 || len(resp.Answer) != 1 {
			t.Fatalf("mode %v: not served: rcode=%s called=%d", m, dns.RcodeToString[resp.Rcode], next.called)
		}
		assertFresh(t, resp, secretA, *now, clientIP)
	}
}

// 8. RFC 7873 §7.1: a cookie made under the previous secret "are treated as a
// correct Server Cookie during that time. When a server responds to a request
// containing an old Server Cookie that the server is treating as correct, the
// server MUST include a new Server Cookie in its response" (§7.1).
func TestPreviousSecretAcceptedAndRefreshed(t *testing.T) {
	c, next, now := newPlugin(t, modeEnforce, secretB, secretA) // Generating B, verify-only A.
	old := mint(t, secretA, unix32(*now), clientIP)
	resp := serve(t, c, query(withServer(t, old), false), udpFrom(clientIP))
	if resp.Rcode != dns.RcodeSuccess || next.called != 1 {
		t.Fatalf("a cookie under the verify-only secret was refused: rcode=%s", dns.RcodeToString[resp.Rcode])
	}
	assertFresh(t, resp, secretB, *now, clientIP) // New cookie, under B.
}

// 9. RFC 9018 §5, the three stages, across a set of three servers: "All
// servers in an anycast set must be able to verify the Server Cookies
// constructed by all other servers in that anycast set at all times" (§5).
func TestRolloutStages(t *testing.T) {
	type server struct {
		gen    string
		verify []string
	}
	stages := []struct {
		name    string
		servers []server
		// The secrets in use by generators, which every server must accept.
		mustAccept []string
		mustReject []string
	}{
		{"steady", []server{{secretA, nil}, {secretA, nil}, {secretA, nil}}, []string{secretA}, []string{secretB}},
		{"stage 1: all learn B, keep generating with A", []server{{secretA, []string{secretB}}, {secretA, []string{secretB}}, {secretA, []string{secretB}}}, []string{secretA, secretB}, nil},
		{"stage 2: generate with B, A still verifies", []server{{secretB, []string{secretA}}, {secretB, []string{secretA}}, {secretB, []string{secretA}}}, []string{secretA, secretB}, nil},
		{"stage 3: A forgotten", []server{{secretB, nil}, {secretB, nil}, {secretB, nil}}, []string{secretB}, []string{secretA}},
	}
	for _, st := range stages {
		t.Run(st.name, func(t *testing.T) {
			for i, srv := range st.servers {
				c, _, now := newPlugin(t, modeEnforce, srv.gen, srv.verify...)
				for _, secret := range st.mustAccept {
					expectRcode(t, c, *now, secret, dns.RcodeSuccess, "server %d refused a cookie made under %s…", i, secret[:4])
				}
				for _, secret := range st.mustReject {
					expectRcode(t, c, *now, secret, dns.RcodeBadCookie, "server %d accepted a cookie made under the forgotten or unknown secret %s…", i, secret[:4])
				}
			}
		})
	}
}

// expectRcode sends c a request carrying a cookie made under `secret` for the
// test client and reports msg if the rcode is not want.
func expectRcode(t *testing.T, c *Cookie, now time.Time, secret string, want int, msg string, args ...any) {
	t.Helper()
	resp := serve(t, c, query(withServer(t, mint(t, secret, unix32(now), clientIP)), false), udpFrom(clientIP))
	if resp.Rcode != want {
		t.Errorf(msg, args...)
	}
}

// 10. RFC 7873 §5.2: "In all cases of multiple COOKIE options in a request,
// only the first (the one closest to the DNS header) is considered" (§5.2).
func TestOnlyFirstCookieConsidered(t *testing.T) {
	c, _, now := newPlugin(t, modePermissive, secretA)
	valid := withServer(t, mint(t, secretA, unix32(*now), clientIP))
	malformed := []byte{1, 2, 3}
	add := func(r *dns.Msg, b []byte) {
		o := r.IsEdns0()
		o.Option = append(o.Option, &dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: hex.EncodeToString(b)})
	}

	r := query(malformed, false)
	add(r, valid)
	if resp := serve(t, c, r, udpFrom(clientIP)); resp.Rcode != dns.RcodeFormatError {
		t.Errorf("malformed-then-valid: rcode %s, want FORMERR from the first option", dns.RcodeToString[resp.Rcode])
	}

	c, _, now = newPlugin(t, modePermissive, secretA)
	r = query(valid, false)
	add(r, malformed)
	resp := serve(t, c, r, udpFrom(clientIP))
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("valid-then-malformed: rcode %s, want served", dns.RcodeToString[resp.Rcode])
	}
	assertFresh(t, resp, secretA, *now, clientIP)
}

// 11. CoreDNS up to v1.14.6 copies the request's COOKIE option into the
// response unvalidated. The response must still carry exactly one COOKIE
// option, ours, not the echo and not both; other options survive.
func TestEchoedCookieIsReplaced(t *testing.T) {
	c, next, now := newPlugin(t, modePermissive, secretA)
	next.echoCookie, next.nsid = true, true
	resp := serve(t, c, query(clientOnly(t), false), udpFrom(clientIP))
	assertFresh(t, resp, secretA, *now, clientIP)
	var nsid bool
	for _, opt := range resp.IsEdns0().Option {
		if _, ok := opt.(*dns.EDNS0_NSID); ok {
			nsid = true
		}
	}
	if !nsid {
		t.Error("the NSID option another plugin added was dropped")
	}
}

// A downstream response with no OPT at all (a plugin that builds its own
// message) still gets the cookie, because the request had an OPT.
func TestResponseWithoutOPTGetsCookie(t *testing.T) {
	c, _, now := newPlugin(t, modePermissive, secretA)
	resp := serve(t, c, query(clientOnly(t), false), udpFrom(clientIP))
	assertFresh(t, resp, secretA, *now, clientIP)
}

// 12. The client address is taken from the connection, IPv4-mapped IPv6 as
// IPv4, so the cookie a dual-stack listener issues is the same one it checks.
func TestIPv4MappedRemote(t *testing.T) {
	c, _, now := newPlugin(t, modeEnforce, secretA)
	mapped := &net.UDPAddr{IP: net.ParseIP("::ffff:" + clientIP), Port: 4711}
	resp := serve(t, c, query(clientOnly(t), false), mapped)
	assertFresh(t, resp, secretA, *now, clientIP) // Hashed as the 4-byte address.
	srv := onlyCookie(t, resp)[8:]
	resp = serve(t, c, query(withServer(t, srv), false), udpFrom(clientIP))
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("a cookie issued to the mapped form was refused for the plain form: %s", dns.RcodeToString[resp.Rcode])
	}
}

// 13. RFC 7873 §5.3 from the client's side against an enforcing server: the
// first request gets BADCOOKIE with a cookie, the retry carrying it is served,
// and after the server's secret changes (a restart with a random secret) the
// client is bounced once more and recovers the same way.
func TestBootstrap(t *testing.T) {
	c, _, now := newPlugin(t, modeEnforce, secretA)

	resp := serve(t, c, query(clientOnly(t), false), udpFrom(clientIP))
	if resp.Rcode != dns.RcodeBadCookie {
		t.Fatalf("first request: %s, want BADCOOKIE", dns.RcodeToString[resp.Rcode])
	}
	learned := onlyCookie(t, resp)
	resp = serve(t, c, query(learned, false), udpFrom(clientIP))
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("retry with the learned cookie: %s, want served", dns.RcodeToString[resp.Rcode])
	}

	// The server restarts with another secret and the same clock.
	c2, _, _ := newPlugin(t, modeEnforce, secretB)
	c2.now = func() time.Time { return *now }
	resp = serve(t, c2, query(learned, false), udpFrom(clientIP))
	if resp.Rcode != dns.RcodeBadCookie {
		t.Fatalf("after the secret changed: %s, want BADCOOKIE", dns.RcodeToString[resp.Rcode])
	}
	relearned := onlyCookie(t, resp)
	if resp = serve(t, c2, query(relearned, false), udpFrom(clientIP)); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("second retry: %s, want served", dns.RcodeToString[resp.Rcode])
	}

	// Over TCP the same client is never bounced (the §5.3 fallback).
	if resp = serve(t, c2, query(learned, false), tcpFrom(clientIP)); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("TCP: %s, want served", dns.RcodeToString[resp.Rcode])
	}
}

// 14. Counters, one per case (RFC 7873 §7.2 "RECOMMENDED that implementations
// include counters of the occurrences of the various types of requests and
// responses").
func TestCounters(t *testing.T) {
	read := func(label string) float64 {
		var m dto.Metric
		if err := requests.WithLabelValues(label).Write(&m); err != nil {
			t.Fatal(err)
		}
		return m.GetCounter().GetValue()
	}
	var badcookie dto.Metric
	before := map[string]float64{}
	labels := []string{caseNoCookie, caseMalformed, caseClientOnly, caseInvalidServer, caseValid, caseValidPrevious}
	for _, l := range labels {
		before[l] = read(l)
	}
	if err := badCookies.Write(&badcookie); err != nil {
		t.Fatal(err)
	}
	bad0 := badcookie.GetCounter().GetValue()

	c, _, now := newPlugin(t, modeEnforce, secretB, secretA)
	serve(t, c, query(nil, true), udpFrom(clientIP))                                                      // No cookie.
	serve(t, c, query([]byte{1, 2, 3}, false), udpFrom(clientIP))                                         // Malformed.
	serve(t, c, query(clientOnly(t), false), udpFrom(clientIP))                                           // Client only, BADCOOKIE.
	serve(t, c, query(withServer(t, make([]byte, 16)), false), udpFrom(clientIP))                         // Invalid server cookie.
	serve(t, c, query(withServer(t, mint(t, secretB, unix32(*now), clientIP)), false), udpFrom(clientIP)) // Valid.
	serve(t, c, query(withServer(t, mint(t, secretA, unix32(*now), clientIP)), false), udpFrom(clientIP)) // Valid, previous secret.

	for _, l := range labels {
		if got := read(l) - before[l]; got != 1 {
			t.Errorf("counter %q moved by %v, want 1", l, got)
		}
	}
	if err := badCookies.Write(&badcookie); err != nil {
		t.Fatal(err)
	}
	if got := badcookie.GetCounter().GetValue() - bad0; got != 2 {
		t.Errorf("BADCOOKIE responses moved by %v, want 2 (client-only and invalid)", got)
	}
}

// FuzzServeDNS: arbitrary COOKIE option bytes, either transport, either mode,
// never panic, never produce a response with other than 0 or 1 COOKIE options,
// and never return BADCOOKIE over TCP.
func FuzzServeDNS(f *testing.F) {
	f.Add([]byte{}, true, true)
	f.Add(mustHex(f, clientC), true, false)
	f.Add(append(mustHex(f, clientC), make([]byte, 16)...), false, true)
	f.Add(make([]byte, 40), true, true)
	f.Add(make([]byte, 41), true, false)
	f.Fuzz(func(t *testing.T, data []byte, enforce, tcp bool) {
		m := modePermissive
		if enforce {
			m = modeEnforce
		}
		c, _, _ := newPlugin(t, m, secretA)
		remote := udpFrom(clientIP)
		if tcp {
			remote = tcpFrom(clientIP)
		}
		resp := serve(t, c, query(data, false), remote)
		got := cookies(t, resp)
		if len(got) > 1 {
			t.Fatalf("%d COOKIE options in the response", len(got))
		}
		if tcp && resp.Rcode == dns.RcodeBadCookie {
			t.Fatal("BADCOOKIE over TCP")
		}

		// RFC 7873 §5.2.2: a COOKIE option of any length other than 8 or
		// 16..40 is FORMERR, and carries no cookie of ours.
		if classify(len(data)) == classMalformed {
			if resp.Rcode != dns.RcodeFormatError || len(got) != 0 {
				t.Fatalf("%d-byte option: rcode %s with %d cookies, want FORMERR and none",
					len(data), dns.RcodeToString[resp.Rcode], len(got))
			}
			return
		}
		// Anything well-formed gets exactly one cookie back: the client's
		// own 8 bytes plus a server cookie that verifies under the generating
		// secret at the current time (RFC 7873 §5.2.3-5.2.5, RFC 9018 §4.3).
		if len(got) != 1 || len(got[0]) != verifyOptionLen || !bytes.Equal(got[0][:clientCookieLen], data[:clientCookieLen]) {
			t.Fatalf("response cookie % x for request % x", got, data)
		}
		var client [clientCookieLen]byte
		copy(client[:], data)
		if !verify(key16(t, secretA), client, got[0][clientCookieLen:], mustAddr(clientIP), c.timestamp()) {
			t.Fatalf("response server cookie % x does not verify", got[0])
		}
	})
}

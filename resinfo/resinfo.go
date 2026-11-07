// Package resinfo publishes a resolver's capabilities as an RFC 9606 RESINFO
// record (RR type 261) at the resolver's own name.
package resinfo

import (
	"context"
	"strings"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/metrics"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
)

const pluginName = "resinfo"

// ResInfo answers RESINFO queries for its configured names and passes every
// other query on.
type ResInfo struct {
	Next plugin.Handler
	// The resolver's names: lowercase, fully qualified, distinct.
	names []string
	// The canonical RDATA (Info.Strings) in miekg/dns's presentation
	// escaping (see escapeTXT), shared read-only by every response: miekg/dns
	// only reads it when packing.
	txt []string
	ttl uint32
}

// The handler, from validated parts: names must already be
// canonical (see parseName) and info valid; setup guarantees both.
func newResInfo(names []string, info Info, ttl uint32) *ResInfo {
	txt := info.Strings()
	for i := range txt {
		txt[i] = escapeTXT(txt[i])
	}
	return &ResInfo{names: names, txt: txt, ttl: ttl}
}

// escapeTXT turns a raw character-string into the form miekg/dns keeps in
// TXT-like fields: its packer reads '\' as an escape, so a literal backslash
// must be doubled, and its unpacker writes '"' as '\"', so that is escaped
// too, making a published string equal to what a client's unpacker shows.
// Valid values are printable US-ASCII (validatePair), so no \DDD is needed.
func escapeTXT(s string) string {
	if !strings.ContainsAny(s, `\"`) {
		return s
	}
	var b strings.Builder
	for i := range len(s) {
		if s[i] == '\\' || s[i] == '"' {
			b.WriteByte('\\')
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// Name implements plugin.Handler.
func (*ResInfo) Name() string { return pluginName }

// answers reports whether the plugin answers req itself: a standard QUERY
// with one question, QTYPE RESINFO, QCLASS IN, for one of the configured
// names compared ASCII-case-insensitively (RFC 4343 §3). Everything else,
// including other types at a configured name and RESINFO for any other
// name, is passed on. Resinfo.lean's `handle` models this function.
func (r *ResInfo) answers(req *dns.Msg) bool {
	if req.Opcode != dns.OpcodeQuery || len(req.Question) != 1 {
		return false
	}
	q := req.Question[0]
	if q.Qtype != dns.TypeRESINFO || q.Qclass != dns.ClassINET {
		return false
	}
	for _, n := range r.names {
		if equalFoldASCII(q.Name, n) {
			return true
		}
	}
	return false
}

// ServeDNS implements plugin.Handler.
func (r *ResInfo) ServeDNS(ctx context.Context, w dns.ResponseWriter, req *dns.Msg) (int, error) {
	if !r.answers(req) {
		return plugin.NextOrFailure(r.Name(), r.Next, ctx, w, req) //nolint:wrapcheck // the next plugin's error, passed through as CoreDNS expects
	}
	state := request.Request{W: w, Req: req}
	m := r.reply(req)
	state.SizeAndDo(m)
	m = state.Scrub(m)
	if err := w.WriteMsg(m); err != nil {
		return dns.RcodeServerFailure, plugin.Error(pluginName, err) //nolint:wrapcheck // plugin.Error is CoreDNS's own error convention
	}
	responses.WithLabelValues(metrics.WithServer(ctx)).Inc()
	return dns.RcodeSuccess, nil
}

// reply builds the answer: NOERROR, AA set (RFC 9606 §3: a client "MUST
// discard the response if the AA flag in the response is set to 0"), and an
// RRset of exactly one RESINFO record (§3: "the RRset MUST have exactly one
// record"), owned by the query name exactly as the client spelled it.
func (r *ResInfo) reply(req *dns.Msg) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(req)
	m.Authoritative = true
	m.Answer = []dns.RR{&dns.RESINFO{
		Hdr: dns.RR_Header{
			Name:   req.Question[0].Name,
			Rrtype: dns.TypeRESINFO,
			Class:  dns.ClassINET,
			Ttl:    r.ttl,
		},
		Txt: r.txt,
	}}
	return m
}

// equalFoldASCII compares two names folding A-Z onto a-z only (RFC 4343 §3),
// never Unicode, and without allocating.
func equalFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range len(a) {
		if lowerASCII(a[i]) != lowerASCII(b[i]) {
			return false
		}
	}
	return true
}

func lowerASCII(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}

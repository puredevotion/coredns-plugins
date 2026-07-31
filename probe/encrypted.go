package probe

import (
	"crypto/tls"

	"github.com/miekg/dns"
)

// RFC 9539 — Unilateral Opportunistic Deployment of Encrypted
// Recursive-to-Authoritative DNS (Experimental).
//
// RFC 9539 has recursive resolvers simply TRY encrypted transport to
// authoritative servers — no signalling, no negotiation, no coordination with the
// zone operator. A resolver opportunistically opens DoT on port 853; if it works,
// the query is private from a passive observer, and if it does not, the resolver
// falls back to cleartext.
//
// That design makes adoption almost unmeasured, because the only party who can
// see an attempt is the authoritative server being probed — and very few
// authoritatives both accept encrypted transport and publish what reaches them.
// This zone can be one of them.
//
// What this file fixes, which is a real gap and not a new feature: transportOf
// previously derived the transport from CoreDNS's request.Proto(), which
// distinguishes only UDP from TCP by inspecting the remote address type. It
// cannot see TLS at all. So TransportTLS and TransportQUIC existed as constants
// and were never once produced, while Observation.Transport's own documentation
// claimed a resolver "falling back from DoT to Do53" would be visible in the
// change. It would not have been. Every encrypted query was recorded as plain
// TCP.
//
// The fix is dns.ConnectionStater, which miekg/dns implements on its response
// writer precisely so a handler can reach the TLS state of the connection
// underneath.

// TLSInfo is what the handshake revealed, for queries that arrived encrypted.
//
// Recorded because it is the part of RFC 9539 with consequences beyond a boolean:
// which version and cipher a resolver negotiates says how current its TLS stack
// is, and the negotiated key-exchange group is directly relevant to the
// post-quantum question — a DoT handshake is where oversized PQ certificates hurt
// first.
type TLSInfo struct {
	// Version is the negotiated TLS version, e.g. "TLS 1.3".
	Version string `json:"version,omitempty"`
	// CipherSuite is the negotiated suite's registered name.
	CipherSuite string `json:"cipher_suite,omitempty"`
	// NamedGroup is the negotiated key-exchange group, empty when the connection
	// did not use one (or the Go version in use does not report it).
	NamedGroup string `json:"named_group,omitempty"`
	// ServerName is the SNI the resolver sent, empty when it sent none.
	//
	// Empty is the EXPECTED case under RFC 9539 §4.2, not a defect: a resolver
	// probing opportunistically has no name to authenticate and nothing to gain
	// from SNI. A resolver that DOES send one is doing something more deliberate
	// than opportunistic probing, which is why this is worth recording.
	ServerName string `json:"server_name,omitempty"`
	// DidResume means the resolver presented a session ticket, i.e. it has talked
	// to us encrypted before and kept state. Under an opportunistic model that is
	// the signal that a resolver is persisting its success rather than re-probing
	// each time.
	DidResume bool `json:"did_resume,omitempty"`
}

// transportFrom determines how a query actually arrived.
//
// Order matters. The TLS check comes FIRST because an encrypted query is also a
// TCP query as far as the remote address is concerned, so asking CoreDNS's
// Proto() first would answer "tcp" and be believed.
func transportFrom(w dns.ResponseWriter, proto string) (Transport, *TLSInfo) {
	if cs := connectionState(w); cs != nil {
		info := &TLSInfo{
			Version:     tls.VersionName(cs.Version),
			CipherSuite: tls.CipherSuiteName(cs.CipherSuite),
			ServerName:  cs.ServerName,
			DidResume:   cs.DidResume,
		}
		if cs.CurveID != 0 {
			info.NamedGroup = cs.CurveID.String()
		}
		// DoH and DoQ both run over TLS, and both announce themselves through
		// ALPN. Distinguished here rather than collapsed into "tls", because
		// which encrypted transport a resolver chose is the interesting part —
		// RFC 9539 itself is about DoT, so a DoQ attempt is a different and
		// rarer finding.
		switch cs.NegotiatedProtocol {
		case "h2", "http/1.1":
			return TransportHTTP, info
		case "doq":
			return TransportQUIC, info
		default:
			return TransportTLS, info
		}
	}

	switch proto {
	case "tcp":
		return TransportTCP, nil
	default:
		return TransportUDP, nil
	}
}

// connectionState reaches the TLS state under the response writer.
//
// CoreDNS wraps the writer it hands a plugin, so this walks the wrappers rather
// than assuming the outermost one implements the interface. Returning nil means
// "not encrypted" — which must not be confused with "encrypted but we could not
// tell", so the walk is bounded and deterministic rather than best-effort.
func connectionState(w dns.ResponseWriter) *tls.ConnectionState {
	type unwrapper interface{ Unwrap() dns.ResponseWriter }

	// A handful of wrappers at most; the bound stops a pathological chain rather
	// than expressing a real depth.
	for i := 0; i < 8 && w != nil; i++ {
		if cs, ok := w.(dns.ConnectionStater); ok {
			if state := cs.ConnectionState(); state != nil {
				return state
			}
			// The writer knows about TLS and says there is none. That is an
			// authoritative "cleartext", so stop rather than unwrapping further
			// and possibly finding a stale inner connection.
			return nil
		}
		u, ok := w.(unwrapper)
		if !ok {
			return nil
		}
		w = u.Unwrap()
	}
	return nil
}

// Encrypted reports whether the query arrived over an encrypted transport. This
// is the RFC 9539 measurement in one bit; TLSInfo carries the detail.
func (o Observation) Encrypted() bool {
	switch o.Transport {
	case TransportTLS, TransportQUIC, TransportHTTP:
		return true
	default:
		return false
	}
}

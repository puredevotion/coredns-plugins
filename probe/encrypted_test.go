package probe

import (
	"crypto/tls"
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// plainWriter is a ResponseWriter with no TLS knowledge at all — the common case
// for Do53.
type plainWriter struct {
	dns.ResponseWriter
	addr net.Addr
}

func (p *plainWriter) RemoteAddr() net.Addr { return p.addr }

// tlsWriter implements dns.ConnectionStater, as miekg/dns's own response writer
// does for an encrypted connection.
type tlsWriter struct {
	dns.ResponseWriter
	addr  net.Addr
	state *tls.ConnectionState
}

func (t *tlsWriter) RemoteAddr() net.Addr                  { return t.addr }
func (t *tlsWriter) ConnectionState() *tls.ConnectionState { return t.state }

// wrappingWriter models CoreDNS wrapping the writer it hands a plugin. It knows
// nothing about TLS itself and exposes the inner writer via Unwrap.
type wrappingWriter struct {
	dns.ResponseWriter
	inner dns.ResponseWriter
}

func (w *wrappingWriter) Unwrap() dns.ResponseWriter { return w.inner }
func (w *wrappingWriter) RemoteAddr() net.Addr       { return w.inner.RemoteAddr() }

func tcpAddr() net.Addr { return &net.TCPAddr{IP: net.ParseIP("192.0.2.53"), Port: 853} }
func udpAddr() net.Addr { return &net.UDPAddr{IP: net.ParseIP("192.0.2.53"), Port: 53} }

func tls13State(alpn string) *tls.ConnectionState {
	return &tls.ConnectionState{
		Version:            tls.VersionTLS13,
		CipherSuite:        tls.TLS_AES_128_GCM_SHA256,
		NegotiatedProtocol: alpn,
		CurveID:            tls.X25519,
	}
}

// TestTransportFromDetectsEncryption is the gap this closes. CoreDNS's
// request.Proto() distinguishes only UDP from TCP by remote-address type, so
// before this every DoT query was recorded as plain TCP — while
// Observation.Transport's documentation claimed a DoT-to-Do53 fallback would be
// visible. It would not have been.
func TestTransportFromDetectsEncryption(t *testing.T) {
	for _, tc := range []struct {
		name      string
		w         dns.ResponseWriter
		proto     string
		want      Transport
		wantTLS   bool
		encrypted bool
	}{
		{
			name: "plain udp", w: &plainWriter{addr: udpAddr()}, proto: "udp",
			want: TransportUDP, encrypted: false,
		},
		{
			name: "plain tcp", w: &plainWriter{addr: tcpAddr()}, proto: "tcp",
			want: TransportTCP, encrypted: false,
		},
		{
			// The whole point: TCP by address, TLS by connection state. The TLS
			// check must win, or Proto() answers "tcp" and is believed.
			name: "DoT", w: &tlsWriter{addr: tcpAddr(), state: tls13State("dot")}, proto: "tcp",
			want: TransportTLS, wantTLS: true, encrypted: true,
		},
		{
			name: "DoQ via ALPN", w: &tlsWriter{addr: udpAddr(), state: tls13State("doq")}, proto: "udp",
			want: TransportQUIC, wantTLS: true, encrypted: true,
		},
		{
			name: "DoH via ALPN h2", w: &tlsWriter{addr: tcpAddr(), state: tls13State("h2")}, proto: "tcp",
			want: TransportHTTP, wantTLS: true, encrypted: true,
		},
		{
			// No ALPN at all is the expected RFC 9539 case — an opportunistic
			// prober has no name to authenticate and nothing to negotiate.
			name: "DoT with no ALPN", w: &tlsWriter{addr: tcpAddr(), state: tls13State("")}, proto: "tcp",
			want: TransportTLS, wantTLS: true, encrypted: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, info := transportFrom(tc.w, tc.proto)
			if got != tc.want {
				t.Errorf("transport = %q, want %q", got, tc.want)
			}
			if (info != nil) != tc.wantTLS {
				t.Errorf("TLSInfo present = %v, want %v", info != nil, tc.wantTLS)
			}
			if enc := (Observation{Transport: got}).Encrypted(); enc != tc.encrypted {
				t.Errorf("Encrypted() = %v, want %v", enc, tc.encrypted)
			}
		})
	}
}

// TestConnectionStateWalksWrappers — CoreDNS hands a plugin a wrapped writer, so
// the TLS state usually is not on the outermost one. Failing to unwrap would
// record every encrypted query as cleartext, which is the exact bug this replaces.
func TestConnectionStateWalksWrappers(t *testing.T) {
	inner := &tlsWriter{addr: tcpAddr(), state: tls13State("dot")}
	wrapped := &wrappingWriter{inner: inner}
	doubleWrapped := &wrappingWriter{inner: wrapped}

	for _, tc := range []struct {
		name string
		w    dns.ResponseWriter
		want bool
	}{
		{"direct", inner, true},
		{"one wrapper", wrapped, true},
		{"two wrappers", doubleWrapped, true},
		{"no tls anywhere", &wrappingWriter{inner: &plainWriter{addr: tcpAddr()}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := connectionState(tc.w) != nil; got != tc.want {
				t.Errorf("connectionState found TLS = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestConnectionStateStopsAtAuthoritativeNo — a writer that implements
// ConnectionStater and returns nil is stating there is no TLS. Continuing to
// unwrap past that could surface a stale inner connection and report a cleartext
// query as encrypted, which is worse than missing one.
func TestConnectionStateStopsAtAuthoritativeNo(t *testing.T) {
	stale := &tlsWriter{addr: tcpAddr(), state: tls13State("dot")}
	// Outer says "TLS? no." Inner would say yes if we kept walking.
	outer := &struct {
		*tlsWriter
		inner dns.ResponseWriter
	}{
		tlsWriter: &tlsWriter{addr: tcpAddr(), state: nil},
		inner:     stale,
	}

	if connectionState(outer) != nil {
		t.Error("kept unwrapping past a writer that reported no TLS")
	}
}

// TestTLSInfoRecordsWhatMatters checks the fields, including the two whose
// EMPTINESS is meaningful rather than a defect.
func TestTLSInfoRecordsWhatMatters(t *testing.T) {
	st := tls13State("dot")
	st.ServerName = ""
	st.DidResume = false

	_, info := transportFrom(&tlsWriter{addr: tcpAddr(), state: st}, "tcp")
	if info == nil {
		t.Fatal("no TLSInfo for a TLS connection")
	}
	if !strings.Contains(info.Version, "1.3") {
		t.Errorf("Version = %q, want something naming TLS 1.3", info.Version)
	}
	if info.CipherSuite == "" {
		t.Error("CipherSuite empty")
	}
	// Relevant to the post-quantum question: a DoT handshake is where oversized
	// PQ certificates hurt first, so the negotiated group is worth having.
	if info.NamedGroup == "" {
		t.Error("NamedGroup empty for a connection with a CurveID set")
	}
	// Empty SNI is the EXPECTED RFC 9539 §4.2 case, not a bug: an opportunistic
	// prober has no name to authenticate.
	if info.ServerName != "" {
		t.Errorf("ServerName = %q, want empty", info.ServerName)
	}

	st2 := tls13State("dot")
	st2.DidResume = true
	st2.ServerName = "check.example.com"
	_, info2 := transportFrom(&tlsWriter{addr: tcpAddr(), state: st2}, "tcp")
	if !info2.DidResume {
		t.Error("DidResume not recorded")
	}
	if info2.ServerName != "check.example.com" {
		t.Errorf("ServerName = %q", info2.ServerName)
	}
}

// TestSummaryReportsEncryption keeps the in-band readout honest for a `dig` user,
// including that encrypted= is present for cleartext too — an absent field reads
// as "unknown", which is not what a plain UDP query means.
func TestSummaryReportsEncryption(t *testing.T) {
	plain := Observation{Transport: TransportUDP}
	if s := plain.Summary(); !strings.Contains(s, "encrypted=0") {
		t.Errorf("cleartext summary lacks encrypted=0: %s", s)
	}
	if s := plain.Summary(); strings.Contains(s, "tls=") {
		t.Errorf("cleartext summary carries tls=: %s", s)
	}

	enc := Observation{
		Transport: TransportTLS,
		TLS:       &TLSInfo{Version: "TLS 1.3", NamedGroup: "X25519", DidResume: true},
	}
	s := enc.Summary()
	for _, want := range []string{"encrypted=1", "tls=TLS1.3", "group=X25519", "resumed=1"} {
		if !strings.Contains(s, want) {
			t.Errorf("encrypted summary lacks %q: %s", want, s)
		}
	}
}

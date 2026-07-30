package probe

import (
	"testing"

	"github.com/coredns/caddy"
)

// TestDefaultBigSizeStaysDeliverable pins the measured constraint behind
// defaultBigSize. Above 1232 it demonstrates exceeding the flag-day cap; below
// ~1500 it still arrives over UDP. Raising this past the MTU would turn the
// amplification demonstration into an apparent outage.
func TestDefaultBigSizeStaysDeliverable(t *testing.T) {
	if defaultBigSize <= 1232 {
		t.Errorf("defaultBigSize = %d, must exceed the 1232-byte flag-day cap to demonstrate anything", defaultBigSize)
	}
	if defaultBigSize >= 1500 {
		t.Errorf("defaultBigSize = %d, must stay under the ~1500-byte MTU or the answer is silently dropped over UDP", defaultBigSize)
	}
}

func TestParseCorefile(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
		check   func(*testing.T, *Probe)
	}{
		{
			name:  "zone only, defaults applied",
			input: `probe check.example.com`,
			check: func(t *testing.T, p *Probe) {
				if p.Zone != "check.example.com." {
					t.Errorf("Zone = %q, want fully qualified", p.Zone)
				}
				if p.TTL != defaultTTL {
					t.Errorf("TTL = %d, want %d", p.TTL, defaultTTL)
				}
				if p.NSName != "ns.check.example.com." {
					t.Errorf("NSName = %q", p.NSName)
				}
				if p.Mbox != "hostmaster.check.example.com." {
					t.Errorf("Mbox = %q", p.Mbox)
				}
				if p.Signer != nil {
					t.Error("no key was configured, so Signer must be nil")
				}
				if p.Store == nil {
					t.Error("Store must never be nil after setup")
				}
			},
		},
		{
			name: "all knobs",
			input: `probe check.example.com {
				ttl 30
				ns dns.example.net
				mbox admin.example.net
				store_ttl 5m
				max_tokens 50
				max_per_token 4
				big_size 1300
			}`,
			check: func(t *testing.T, p *Probe) {
				if p.TTL != 30 {
					t.Errorf("TTL = %d, want 30", p.TTL)
				}
				if p.NSName != "dns.example.net." {
					t.Errorf("NSName = %q", p.NSName)
				}
				if p.BigSize != 1300 {
					t.Errorf("BigSize = %d, want 1300", p.BigSize)
				}
			},
		},
		{name: "missing zone", input: `probe`, wantErr: true},
		{name: "two zone args", input: `probe a.example.com b.example.com`, wantErr: true},
		{name: "unknown property", input: "probe check.example.com {\n\tbogus 1\n}", wantErr: true},
		{name: "non-numeric ttl", input: "probe check.example.com {\n\tttl abc\n}", wantErr: true},
		{name: "bad duration", input: "probe check.example.com {\n\tstore_ttl nope\n}", wantErr: true},
		{name: "negative duration", input: "probe check.example.com {\n\tstore_ttl -5m\n}", wantErr: true},
		// A modifier meant to demonstrate amplification must not double as an
		// unbounded memory knob.
		{name: "big_size too large", input: "probe check.example.com {\n\tbig_size 99999\n}", wantErr: true},
		{name: "big_size zero", input: "probe check.example.com {\n\tbig_size 0\n}", wantErr: true},
		{name: "missing key file", input: "probe check.example.com {\n\tkey /nonexistent/key\n}", wantErr: true},
		{
			name: "two probe blocks in one server block",
			// Silently letting the second win would be worse than refusing.
			input:   "probe a.example.com\nprobe b.example.com",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, err := parse(caddy.NewTestController("dns", tc.input))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parse(%q) succeeded, want an error", tc.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("parse(%q): %v", tc.input, err)
			}
			if tc.check != nil {
				tc.check(t, p)
			}
		})
	}
}

// TestParseRejectsKeyForWrongZone guards the failure mode LoadSigner's caller
// exists to catch: a key whose owner name is not this zone produces signatures
// every validator rejects, and the symptom is "the entire zone is bogus" with
// nothing logged anywhere.
func TestParseRejectsKeyForWrongZone(t *testing.T) {
	s := newTestSigner(t, 0) // key owns check.example.com.
	base := keyBasenameFor(t, s)

	_, err := parse(caddy.NewTestController("dns",
		"probe other.example.org {\n\tkey "+base+"\n}"))
	if err == nil {
		t.Fatal("parse accepted a key belonging to a different zone")
	}

	// The matching case must still work, so the check is not just rejecting
	// everything.
	if _, err := parse(caddy.NewTestController("dns",
		"probe check.example.com {\n\tkey "+base+"\n}")); err != nil {
		t.Errorf("parse rejected a correctly matched key: %v", err)
	}
}

// TestParseValkeyRequiresVerifiedTLS covers the store's transport policy. The
// fleet's Valkey has no authentication of its own, so the server certificate is
// the only thing distinguishing it from anything else answering on that address
// — and what crosses the link is observations about other people's networks.
// There is deliberately no bypass flag to test for.
func TestParseValkeyRequiresVerifiedTLS(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "valkey without a CA is refused",
			input:   "probe check.example.com {\n\tvalkey valkey.example.com:6379\n}",
			wantErr: true,
		},
		{
			name:    "valkey_ca without an address is refused",
			input:   "probe check.example.com {\n\tvalkey_ca /etc/ssl/ca.pem\n}",
			wantErr: true,
		},
		{
			name:    "valkey_timeout without an address is refused",
			input:   "probe check.example.com {\n\tvalkey_timeout 200ms\n}",
			wantErr: true,
		},
		{
			// No addresses at all is the in-process default, which needs no TLS.
			name:  "no valkey at all is fine",
			input: "probe check.example.com",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, err := parse(caddy.NewTestController("dns", tc.input))
			if tc.wantErr {
				if err == nil {
					t.Fatal("parse succeeded, want an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if _, ok := p.Store.(*MemStore); !ok {
				t.Errorf("Store is %T, want *MemStore when no valkey is configured", p.Store)
			}
		})
	}
}

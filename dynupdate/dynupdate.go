// Package dynupdate implements RFC 2136 Dynamic Updates in the Domain Name
// System, for one zone held in memory.
//
// It exists so cert-manager's built-in `rfc2136` DNS-01 solver can talk
// straight to a homelab-authored primary, instead of the `_acme-challenge`
// CNAME-delegation stopgap that requires an API-driven third party to author
// part of our zone.
//
// # Why this owns the zone rather than overlaying one
//
// The obvious shape — hold dynamically-added records in a side table and fall
// through to `file` for everything else — is quietly wrong in a way that only
// shows up in the deployment this plugin is for. CoreDNS's `transfer` plugin
// takes the FIRST Transferer that does not return ErrNotAuthoritative; it does
// not merge. A side table would therefore be invisible to AXFR, so a TXT record
// added by an ACME client would never reach the secondary that the public NS
// records actually point at, and DNS-01 would fail against a zone whose primary
// swore the record was there.
//
// So this plugin owns the zone. Reads, wildcards, delegation, NODATA proofs and
// AXFR all come from CoreDNS's own file.Zone rather than from a second, subtly
// different authoritative lookup written here.
//
// # How a change is applied
//
// The zone is kept as a flat []dns.RR. An UPDATE is applied to a COPY of that
// slice, and only if every prerequisite passed and the whole update section
// prescanned clean is a fresh file.Zone built from the result and swapped in
// under a write lock. RFC 2136 §3.4.2.1 requires the update be atomic — a
// reader must never observe half of it — and rebuilding is the cheapest way to
// get that without reimplementing the tree's delete semantics.
//
// Rebuilding is O(zone) per update. That is a deliberate trade: this plugin
// exists for ACME challenges and similar low-rate mutation, where correctness
// and atomicity are worth far more than update throughput. A zone taking
// thousands of updates per second wants a different design, and should say so
// loudly rather than discover it.
package dynupdate

import (
	"context"
	"sync"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/file"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/plugin/transfer"

	"github.com/miekg/dns"
)

var log = clog.NewWithPlugin(pluginName)

const pluginName = "dynupdate"

// DynUpdate serves one zone and accepts RFC 2136 UPDATE messages for it.
type DynUpdate struct {
	Next plugin.Handler

	// Zone is the canonical origin, always fully qualified and lower case.
	Zone string

	// Xfer, when the `transfer` plugin is configured in the same server
	// block, is used to send a NOTIFY after a change. Without it a secondary
	// only picks the change up at its next refresh, which for an ACME
	// challenge is indistinguishable from the update never happening.
	Xfer *transfer.Transfer

	// mutable, when non-nil, is the set of RR types this plugin will let an
	// UPDATE touch. nil means "no type policy" — RFC 2136's own rules still
	// apply. The point of an allowlist is that an UPDATE key which only needs
	// to publish TXT challenges should not also be able to repoint an A
	// record, and TSIG alone cannot express that.
	mutable map[uint16]bool

	mu   sync.RWMutex
	rrs  []dns.RR   // authoritative content; the source of truth
	view *file.File // rebuilt from rrs on every change, serves reads and AXFR
}

// ServeDNS routes UPDATE to the RFC 2136 machinery and everything else to the
// file view.
//
// CoreDNS's own server does not filter on opcode: it requires a question
// section, which an UPDATE's Zone section occupies, and a ClassINET qclass,
// which ZCLASS is. So an UPDATE reaches the plugin chain like any query, and a
// plugin that does not expect one will treat the Zone section as a question and
// answer nonsense.
func (d *DynUpdate) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	if r.Opcode == dns.OpcodeUpdate {
		return d.serveUpdate(w, r)
	}

	d.mu.RLock()
	view := d.view
	d.mu.RUnlock()

	return view.ServeDNS(ctx, w, r)
}

// Transfer implements transfer.Transferer so AXFR of this zone includes
// whatever the last UPDATE left behind. Without it the records this plugin
// exists to publish would be invisible to every secondary.
func (d *DynUpdate) Transfer(zone string, serial uint32) (<-chan []dns.RR, error) {
	d.mu.RLock()
	view := d.view
	d.mu.RUnlock()

	return view.Transfer(zone, serial)
}

// Name implements plugin.Handler.
func (d *DynUpdate) Name() string { return pluginName }

// build turns a flat record slice into the servable view. The returned view's
// Next is d.Next, so a name outside this zone still falls through the chain.
func (d *DynUpdate) build(rrs []dns.RR) (*file.File, error) {
	z := file.NewZone(d.Zone, "")
	for _, rr := range rrs {
		// Insert mutates the RR it is given (it lower-cases owner and target
		// names), so hand it a copy — d.rrs is shared with readers of the
		// previous view until the swap completes.
		if err := z.Insert(dns.Copy(rr)); err != nil {
			return nil, err
		}
	}

	return &file.File{
		Next: d.Next,
		Zones: file.Zones{
			Z:     map[string]*file.Zone{d.Zone: z},
			Names: []string{d.Zone},
		},
	}, nil
}

// swap installs a new record set. The caller must hold d.mu for writing.
func (d *DynUpdate) swap(rrs []dns.RR) error {
	view, err := d.build(rrs)
	if err != nil {
		return err
	}
	d.rrs, d.view = rrs, view
	return nil
}

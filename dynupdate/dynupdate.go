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
// under a write lock. RFC 2136 §3.7 requires the update be atomic — "a QUERY
// should not be able to retrieve RRsets which have been partially modified" —
// and §3.4.2.1 that a failure "undo all updates applied to the zone during
// this transaction". Rebuilding is the cheapest way to get both without
// reimplementing the tree's delete semantics.
//
// Rebuilding is O(zone) per update. That is a deliberate trade: this plugin
// exists for ACME challenges and similar low-rate mutation, where correctness
// and atomicity are worth far more than update throughput. A zone taking
// thousands of updates per second wants a different design, and should say so
// loudly rather than discover it.
//
//nolint:misspell // "Transferer" throughout this file names coredns's actual transfer.Transferer interface, not a typo
package dynupdate

import (
	"context"
	"fmt"
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
//
// Field order here is chosen for fieldalignment (pointer-shaped fields
// first), not for readability — see the comments on each field for what it
// does.
type DynUpdate struct {
	Next plugin.Handler

	// Xfer, when the `transfer` plugin is configured in the same server
	// block, is used to send a NOTIFY after a change. Without it a secondary
	// only picks the change up at its next refresh, which for an ACME
	// challenge is indistinguishable from the update never happening.
	Xfer *transfer.Transfer

	// The mutable field, when non-nil, is the set of RR types this plugin
	// will let an UPDATE touch. Nil means "no type policy" — RFC 2136's own
	// rules still apply. The point of an allowlist is that an UPDATE key
	// which only needs to publish TXT challenges should not also be able to
	// repoint an A record, and TSIG alone cannot express that.
	mutable map[uint16]bool

	view *file.File // Rebuilt from rrs on every change, serves reads and AXFR.

	// Zone is the canonical origin, always fully qualified and lower case.
	Zone string

	rrs []dns.RR // Authoritative content; the source of truth.

	mu sync.RWMutex
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

	rcode, err := view.ServeDNS(ctx, w, r)
	if err != nil {
		return rcode, fmt.Errorf("serve file view: %w", err)
	}
	return rcode, nil
}

// Transfer implements transfer.Transferer so AXFR of this zone includes
// whatever the last UPDATE left behind. Without it the records this plugin
// exists to publish would be invisible to every secondary.
func (d *DynUpdate) Transfer(zone string, serial uint32) (<-chan []dns.RR, error) {
	d.mu.RLock()
	view := d.view
	d.mu.RUnlock()

	ch, err := view.Transfer(zone, serial)
	if err != nil {
		return ch, fmt.Errorf("transfer %s: %w", zone, err)
	}
	return ch, nil
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
			return nil, fmt.Errorf("insert record into zone: %w", err)
		}
	}

	return &file.File{
		Next:  d.Next,
		Z:     map[string]*file.Zone{d.Zone: z},
		Names: []string{d.Zone},
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

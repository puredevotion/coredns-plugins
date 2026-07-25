# Design: SNI-dispatched multi-cert CoreDNS plugin (`sni_tls`)

Why the plugin exists, what was considered instead, and the syntax it settled on.

## Problem

An internal-only name (`dns.internal.example`) cannot share a certificate with a
public name (`dns.example.com`) on the same encrypted-DNS listener:

- A public ACME CA (Let's Encrypt et al.) cannot sign non-public names such as
  `.arpa` or `.internal` — no public TLD, so no challenge path exists.
- The internal name therefore needs a certificate from a private CA instead.
- CoreDNS's stock `tls` plugin loads exactly one cert/key pair into
  `tls.Config.Certificates` at Corefile-parse time — one cert per listener,
  no SNI-based selection. Two hostnames needing two different issuers can't
  share one `tls://` server block today.

The usual workaround is a second (or third) CoreDNS instance with its own
address, its own certificate, and its own copy of the zone data kept in lockstep
with the first. That carries a real ongoing cost: another deployment, another IP,
and a zone-sync surface that must be kept consistent on every DNS change. This
plugin exists to collapse those instances back into one.

## Chosen approach: external plugin + existing `reload` plugin

Two other options considered and rejected:

- **SAN cert (one cert, two names):** requires moving the public name to the
  private CA so one cert can carry both `dns.example.com` and
  `dns.internal.example` as SANs. Rejected — every client doing strict DoT to
  the public name would then need the private CA root installed, losing the
  zero-config public-trust path that is the whole reason for keeping that name
  on a public CA.
- **SNI L4 passthrough proxy** (nginx/envoy `stream{}` + `ssl_preread`) in
  front of two internal `tls://` listeners on the same pod. Viable, but
  adds a proxy sidecar and a second internal Corefile server block to
  maintain — roughly the same operational surface as the plugin route
  without reducing the CoreDNS-specific pieces.

External plugin wins because:
- No forking of `coredns/coredns` core — external plugins are CoreDNS's
  documented extension mechanism (a Go module pulled in via `plugin.cfg` +
  `go.mod replace`, not a source-tree fork). Upstream version bumps only
  require re-testing the plugin against the new `plugin.tls` interfaces,
  not rebasing a fork.
- Piggybacks on the **already-present `reload` plugin** for cert rotation
  instead of inventing a new SIGHUP sidecar (the pattern used for Kanidm's
  cert reload, see `project_cert_reload_incident` memory) — `reload` already
  polls the Corefile and gracefully re-execs the server instance in-process
  on change; if the plugin re-reads cert files from disk in its `Setup()`,
  a `reload`-triggered re-parse picks up rotated certs for free.
- A single CoreDNS instance stays the only resolver deployment — no second or
  third deployment's replica count, affinity, or zone-sync to reason about.

## Design

### Plugin: `sni_tls`

Replaces the stock `tls` directive inside a `tls://`/`https://`/`quic://`
server block. Same directive position, extended syntax:

```
tls://.:853 {
  sni_tls /etc/coredns/tls/primary.crt /etc/coredns/tls/primary.key
  sni_tls /etc/coredns/tls/secondary.crt   /etc/coredns/tls/secondary.key
  forward . 127.0.0.1:53
  cache 30
  errors
}
```

Multiple `sni_tls` lines accumulate cert/key pairs (parser appends, doesn't
overwrite) rather than one directive taking a list — keeps the Corefile
diff-friendly when adding a third hostname later (one new line, not editing
an existing line's argument list).

## Open questions / risks

- Whether CoreDNS's plugin ABI (`caddy`-derived `Setup(c *caddy.Controller)`)
  gives clean access to reload the same `tls.Config` object in place, or
  whether `reload` fully tears down and reconstructs the server instance
  (in which case "hot" cert reload was never actually free — needs reading
  `coredns/plugin/reload`'s source before assuming this works as described
  above).
- Go's `tls.Certificate.Leaf` population gotcha (step 1) is a common
  correctness bug in hand-rolled `GetCertificate` implementations — must
  parse SANs explicitly, don't rely on `Leaf` being non-nil.
- CoreDNS major version bumps could change the `tls` plugin's package
  layout enough that `sni_tls` (which likely embeds/reimplements parts of
  it) needs a compat pass — budget for that at each `image.tag` bump, not
  a huge lift but not zero either.

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

## Verified-DDR caveat and the `strict` option

By default, an SNI that matches no loaded cert (or no SNI at all) is served
the *first-loaded* cert as a fallback — matching the stock `tls` plugin's
SNI-agnostic single-cert behavior, so a single-cert deployment behaves
exactly as it did before this plugin existed.

That fallback becomes a real risk the moment an instance serves **more than
one cert** and also serves RFC 9462 §4.2 *verified* DNS Designated Resolver
(DDR) discovery for one of those names: verified discovery only holds if the
cert returned for the DDR-advertised VIP carries that VIP's IP address as a
SAN. A client that dials the right VIP but sends the wrong (or no) SNI — a
bug, a stale cache, a misbehaving library, or someone probing the listener —
would, under the default fallback, silently receive *some* cert. If that
happens to be a cert without the expected IP-SAN, "verified" discovery
completed against a cert that doesn't actually verify anything.

This isn't hypothetical for this repo: `coredns-radnr`'s `539a57a` image
rebuild was forced after this exact instance was found live serving a cert
for an SNI name not present in its own Corefile at all (root-caused to a
stale/cached vendored-source build layer, not a `sni_tls` logic bug — but the
failure mode observed was precisely "wrong cert served, no error surfaced").

`strict` closes this off. Set via a block-only `sni_tls` line (no cert/key
args):

```
tls://.:853 {
  sni_tls /etc/coredns/tls/primary.crt   /etc/coredns/tls/primary.key
  sni_tls /etc/coredns/tls/secondary.crt /etc/coredns/tls/secondary.key
  sni_tls {
    strict
  }
  forward . 127.0.0.1:53
  cache 30
  errors
}
```

With `strict` set, `GetCertificate` never falls back: an unmatched or absent
SNI returns an error instead of a cert, which makes Go's TLS server abort the
handshake. The client sees a failed connection, not a wrongly-verified one —
fail closed instead of fail silent. Exact and wildcard SNI matches are
unaffected; `strict` only removes the guess-on-miss path.

**Rule of thumb for this repo:** any instance serving more than one cert AND
any verified-DDR VIP must set `strict`. A single-cert instance has no reason
to (there's only ever one cert to serve regardless of SNI, so fallback vs.
strict makes no observable difference — but strict is harmless there too).

## Cert hot-reload (resolved)

The open question below about `reload`-plugin piggybacking was checked
against `coredns/plugin/reload`'s actual source: it SHA512-hashes the
*parsed Corefile*, not the cert files a directive references. A cert rotated
at the same on-disk path (the k8s Secret-volume symlink-swap pattern this
plugin's fallback-cert caveat already assumes) never changes that hash, so
`reload` never restarts the server and a re-`Setup()` never happens. The
"hot for free via `reload`" plan in the original design was wrong — needed
for the home.arpa + sevenwoods.nl dual-cert case, where the private-CA and
public-CA certs rotate independently and neither should require a manual
CoreDNS bounce.

Implemented instead (`reload.go`): a `liveStore` wraps the `certStore`
behind an `atomic.Pointer`, polled every 30s (fixed, not Corefile-configurable
— see the constant's doc comment for why). Each tick re-hashes the raw
cert/key file bytes; only on a changed hash does it rebuild via
`buildCertStore` and atomically swap. A rebuild failure (e.g. caught
mid-rotation, one file replaced but not the other) is logged and the
previous store is kept — a transient reload glitch must never blank out an
already-running TLS listener. Lifecycle (`OnStartup`/`OnShutdown`, wired to
`OnStartup`/`OnRestart`/`OnFinalShutdown`/`OnRestartFailed`) mirrors the
`radnr` plugin's convention in this repo rather than inventing a new shape.

## Open questions / risks

- Go's `tls.Certificate.Leaf` population gotcha (step 1) is a common
  correctness bug in hand-rolled `GetCertificate` implementations — must
  parse SANs explicitly, don't rely on `Leaf` being non-nil.
- CoreDNS major version bumps could change the `tls` plugin's package
  layout enough that `sni_tls` (which likely embeds/reimplements parts of
  it) needs a compat pass — budget for that at each `image.tag` bump, not
  a huge lift but not zero either.

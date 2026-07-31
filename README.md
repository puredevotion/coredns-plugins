# coredns-plugins

External CoreDNS plugins for encrypted-DNS discovery and multi-certificate TLS,
plus a Dagger pipeline that builds a CoreDNS binary with them compiled in.

| Plugin | What it does | Status |
|---|---|---|
| [`sni_tls`](sni_tls/) | Replaces the stock `tls` directive with SNI-based certificate selection, so one listener can serve several hostnames whose certs come from different issuers | Implemented, tested, **running in production** |
| [`radnr`](radnr/) | Advertises an encrypted DNS resolver on the LAN via the RFC 9463 DNR option in IPv6 Router Advertisements, plus optional RFC 8106 RDNSS | Wire/protocol layer complete and RFC-conformant; **running in production** |

Both plugins run in production in the author's homelab (as `coredns-radnr`,
serving real LAN DNS over DoT/DoH/DoQ). They have real-world mileage now, but
only in one deployment and one topology — treat "works here" accordingly.

The Dagger pipeline can also compile in **third-party** plugins that don't live
in this repo, pinned by module version. Currently: upstream's
[`coredns/rrl`](https://github.com/coredns/rrl) for response rate limiting —
adopted rather than reimplemented, with the verification results and three
operational traps written up in [`docs/rrl-plugin.md`](docs/rrl-plugin.md).

## Why these exist

**`sni_tls`** — CoreDNS's stock `tls` plugin loads exactly one cert/key pair per
listener, with no SNI-based selection. If you serve both a public name and an
internal-only name over DoT/DoH/DoQ, those two names need certificates from two
different issuers (a public ACME CA cannot sign `.arpa` or `.internal`), and the
stock plugin cannot put both on one `tls://` block. The usual workaround is a
second CoreDNS instance with its own address, cert, and copy of the zone data.
`sni_tls` collapses that back into one instance. Design rationale, rejected
alternatives, and the verified-DDR caveat: [`docs/sni-tls-plugin.md`](docs/sni-tls-plugin.md).

**`radnr`** — [RFC 9463] defines a DHCP/RA option that hands clients an encrypted
resolver's authentication domain name directly, so DoT/DoH/DoQ works with no
per-device configuration. Support exists client-side (systemd-resolved ≥ 256,
Windows 11) but router-side emitters are scarce. This plugin makes CoreDNS one.

[RFC 9463]: https://www.rfc-editor.org/rfc/rfc9463.html

## Building

Plugins are compiled *into* CoreDNS — there is no runtime plugin loading. Each
plugin is its own Go module so it can be developed and tested standalone, then
pulled into a CoreDNS build with a `go.mod replace` directive.

Test a plugin on its own:

```sh
cd sni_tls && go test -race ./...
cd radnr   && go test -race ./...
```

Build a CoreDNS binary with both compiled in, via Dagger (from `ci/`):

```sh
dagger call test-plugin   --source=.. --plugin-dir=sni_tls
dagger call lint-plugin   --source=.. --plugin-dir=sni_tls
dagger call build-coredns --source=.. --coredns-version=1.14.6
dagger call containerize  --source=.. --coredns-version=1.14.6 \
  export --path=./coredns-plugins.tar
```

`BuildCoredns` clones the pinned upstream CoreDNS tag, patches `plugin.cfg`
(`sni_tls` replaces stock `tls`; `radnr` is inserted next to `health`), runs
`go generate` to regenerate `zplugin.go`, and builds. `Containerize` wraps the
binary in a distroless base and returns an OCI tarball — it does not push. See
[`ci/main.go`](ci/main.go) for why pushing is left to the caller.

Two ordering constraints the pipeline encodes, both of which were real bugs:

- **`go generate` must run before `go mod tidy`.** Tidy-first sees nothing
  importing the replaced modules yet and strips the `replace` as unused.
- **`plugin.cfg` order is semantic**, not just registration order. It determines
  the order handlers run in; a plugin in the wrong slot can silently never see a
  query.

## Deploying

The container needs `CAP_NET_BIND_SERVICE` to bind port 53 as a non-root user
(the distroless base has no shell, so upstream's `setcap` approach isn't
available). On Kubernetes:

```yaml
securityContext:
  capabilities:
    add: ["NET_BIND_SERVICE"]
```

`radnr` additionally needs host networking and `CAP_NET_RAW` to send Router
Advertisements.

> **`radnr` puts a second RA sender on your LAN.** That can disrupt IPv6 for
> every device on the segment. It defaults to `RouterLifetime=0` (explicitly not
> a default router) and refuses to advertise prefixes, and it has a `dry-run`
> mode that logs what it would send and transmits nothing. Start there. Read
> [`radnr/README.md`](radnr/README.md) before running it live.

> **Do not deploy `sni_tls` with more than one certificate on an instance
> serving RFC 9462 verified DDR.** An unmatched-SNI client could be served a
> cert without the required IP-SAN, silently defeating verified discovery. The
> caveat is explained in [`docs/sni-tls-plugin.md`](docs/sni-tls-plugin.md).

## Testing

Both plugins are covered by unit tests, and `sni_tls` additionally has:

- a real loopback TLS 1.3 handshake asserting ML-KEM (post-quantum) negotiation
  (`pqc_test.go`)
- a fuzz target over SNI lookup (`fuzz_test.go`)
- partial-cert-set tests: one cert source being absent must not take the other
  listener down, since certs from different issuers rotate independently

`radnr` has byte-exact golden tests against the RFC 9463/9460/8415 encoding
rules, and covers Router Solicitation responses (RFC 4861 §6.2.6, rate-limited)
and interval jitter (§6.2.1).

Everything runs offline — `GOPROXY=off go test ./...` passes in both modules.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Licence

[MIT](LICENSE). CoreDNS itself is Apache-2.0; these plugins are separate works
compiled into it.

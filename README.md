# coredns-plugins

CoreDNS plugins for encrypted-DNS discovery and LAN-facing resolver behaviour.

> **Status: empty.** No plugin source has been committed yet. This repository
> exists so the plugins have a public home from their first commit rather than
> being extracted from a private tree later. Do not depend on this.

## Scope

Plugins here cover DNS behaviour that upstream CoreDNS doesn't provide, with an
emphasis on standards-based encrypted-DNS discovery:

- **DDR** (Discovery of Designated Resolvers, [RFC 9462]) — letting clients
  discover that a DoT/DoH/DoQ endpoint exists and upgrade to it automatically,
  including the verified-upgrade path where the designated resolver's
  certificate carries the resolver IP as a SAN.
- **DNR** (Discovery of Network-designated Resolvers, [RFC 9463]) — encrypted
  resolver configuration delivered via DHCP/RA rather than discovered by query.
- LAN resolver behaviour that assumes split-horizon and internal PKI: internal
  names served authoritatively, everything else forwarded over an encrypted
  upstream.

[RFC 9462]: https://www.rfc-editor.org/rfc/rfc9462.html
[RFC 9463]: https://www.rfc-editor.org/rfc/rfc9463.html

## How CoreDNS plugins work

Plugins are compiled *into* the CoreDNS binary — there is no runtime plugin
loading. Using one means adding it to `plugin.cfg` and building CoreDNS, so each
plugin here documents its own build and `Corefile` snippet.

Plugin ordering in `plugin.cfg` is semantically significant: it determines the
order handlers run in, not just registration. Getting it wrong produces plugins
that silently never see a query.

## Plugins

None committed yet. Each will get its own directory with a `README`, a
`setup_test.go`, and a worked `Corefile` example.

## Building

Standard CoreDNS out-of-tree plugin build: clone CoreDNS, add the plugin to
`plugin.cfg`, `go generate && go build`. Per-plugin instructions will live with
each plugin.

## Testing

Plugins are tested at three levels, because unit tests alone don't catch the
failures that matter in a resolver:

- unit tests against `plugin/test` harnesses, including `setup_test.go` for
  Corefile parsing — malformed config must fail loudly at startup, not degrade
  silently at query time
- integration tests issuing real queries against a built CoreDNS
- protocol conformance: responses checked against the relevant RFC, including
  the negative cases (malformed SVCB, absent designated resolver, failed
  certificate validation), since a broken upgrade path that fails *open* is
  worse than no upgrade path at all

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). This repository is the source of truth —
issues and pull requests here are the real thing, not a mirror of something
private.

## Licence

[MIT](LICENSE). CoreDNS itself is Apache-2.0; these plugins are separate works
compiled into it.

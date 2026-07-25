# Contributing

This repository is the source of truth. Issues and pull requests here are the
real thing, not a mirror of a private tree.

## Before you start

No plugin source has been committed yet. Opening an issue first is more useful
than sending a patch.

## Ground rules

**Hermetic builds.** The tree must build and test with no secrets, no network,
and no private DNS. No internal hostnames, private IP ranges, or real
certificates — including in test fixtures. Use RFC 5737 / RFC 3849 example
addresses and `example.com`.

**Fail closed, loudly.** A resolver that silently degrades is worse than one
that refuses to start. Malformed Corefile config must fail at startup, and a
failed encrypted-upgrade path must not quietly fall back to cleartext without
saying so.

**Standards, cited.** Behaviour implementing an RFC should cite the section it
implements, and deviations should say why. DDR/DNR both have subtle negative
cases where a plausible-looking implementation is wrong.

## Testing

Each plugin needs:

- unit tests via `plugin/test`
- a `setup_test.go` covering Corefile parsing, including malformed input
- integration tests against a built CoreDNS
- the RFC's negative cases: malformed SVCB, absent designated resolver, failed
  certificate validation

## Plugin layout

One directory per plugin, each with a `README`, a worked `Corefile` example, and
its `plugin.cfg` ordering requirement stated explicitly — ordering is
semantically significant and getting it wrong produces a plugin that never sees
a query.

## Licence

Contributions are under [MIT](LICENSE). By opening a PR you agree your work can
be distributed under those terms.

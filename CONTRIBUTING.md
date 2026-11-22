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

### Fuzzing

Code that parses or handles untrusted input (wire formats, query names,
certificate files, UPDATE messages) has a native Go fuzz target (`FuzzXxx` in
a `_test.go` file). A target must build fresh state per input and assert
invariants (round trips, atomicity, consistency), not just "does not panic".
CI runs each target briefly on every PR; `nightly.yml` runs longer campaigns
with a persisted fuzz cache.

A crasher is a regression test. When fuzzing (locally or from a CI artifact)
writes a failing input to `<module>/testdata/fuzz/<FuzzName>/<hash>`, fix the
bug and commit that file with the fix: `go test` replays every file under
`testdata/fuzz` as a plain unit test, so it then guards against the bug
returning. Do not delete or hand-edit crasher files.

Run a target locally from its module (or package) directory, for example
`go test -run=NONE -fuzz='^FuzzServeUpdate$' -fuzztime=30s .` (`-fuzz` accepts
one package at a time).

## Plugin layout

One directory per plugin, each with a `README`, a worked `Corefile` example, and
its `plugin.cfg` ordering requirement stated explicitly — ordering is
semantically significant and getting it wrong produces a plugin that never sees
a query.

## Versioning

Every merge to `main` that changes a plugin or the image build is a release
(`.github/workflows/release.yml`): `.github/scripts/next-version.sh` reads the
Conventional Commits since the last `vX.Y.Z` tag — `feat` bumps minor, `!` or a
`BREAKING CHANGE:` footer bumps major, anything else patch — tags the commit,
publishes `ghcr.io/puredevotion/coredns-plugins:X.Y.Z` and a GitHub Release with
generated notes, and points homelab's manifests at it. `CHANGELOG.md` is
historical up to v0.9.1.

## Licence

Contributions are under [MIT](LICENSE). By opening a PR you agree your work can
be distributed under those terms.

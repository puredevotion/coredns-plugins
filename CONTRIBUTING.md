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

Releases are managed by [release-please](https://github.com/googleapis/release-please),
which reads Conventional Commits (already this repo's style — `feat(...)`,
`fix(...)`, `chore(...)`) to maintain a standing "release" PR. Merging it tags
`vX.Y.Z`, cuts a GitHub Release, and updates `CHANGELOG.md`. Commit prefixes
matter for this: `fix:`/`fix(scope):` bumps patch, `feat:`/`feat(scope):`
bumps minor, and a `BREAKING CHANGE:` footer (or `!` after the type) bumps
major. A commit whose message doesn't follow this format is simply invisible
to release-please — it still merges, it just won't appear in the next
release's changelog entry.

Consumers (e.g. homelab's `flake.lock` pin) still pin by commit SHA, not by
tag — a real `vX.Y.Z` gives them something meaningful to check the changelog
against before advancing that pin, even though the pin mechanism itself
hasn't changed.

## Licence

Contributions are under [MIT](LICENSE). By opening a PR you agree your work can
be distributed under those terms.

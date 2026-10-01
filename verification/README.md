# Formal verification

TLA+ models of the parts of these plugins that are about **interleavings and
lifecycles**, checked with SANY, TLC and Apalache, and Lean 4 proofs about
the parts that are **pure functions** (codecs, matching rules, update
semantics).

```sh
verification/run.sh            # everything
verification/run.sh tla        # sany + tlc + apalache (java 21+; 17 is enough without apalache)
verification/run.sh sany       # parse and level-check every spec
verification/run.sh tlc        # explicit-state model checking
verification/run.sh apalache   # type checking, bounded model checking, inductive proofs
verification/run.sh lean       # Lean (lake on PATH, toolchain in lean/lean-toolchain)
```

`run.sh` fetches tla2tools.jar (1.8.0) and Apalache (0.62.3) at pinned,
checksummed versions; `TLA2TOOLS=` and `APALACHE=` point it at local copies.
CI runs all of it in the `formal-verification` job. The Lean proofs use core Lean
only, with no Mathlib, so they check offline from a bare toolchain.

## What a result here means, and what it doesn't

Each model is written by hand from the Go code it cites, step for step, and
abstracts everything the property doesn't depend on. The abstractions are
stated in each file's header. Nothing is extracted from or compiled against
the Go source, so the guarantee is about the model. Whether the model is
faithful is a matter of review. Each finding below was also reproduced
against the real code with a Go test, and those tests are now in the
plugins' test suites.

TLC checks are exhaustive but **bounded**: a fixed number of rotations,
restarts, updates or seconds, given in each `.cfg`. Apalache's inductive
proofs cover every reachable state of much larger instances (below). Lean
results hold for all inputs.

## TLA+ models (`tla/`)

Every `.cfg` starts with `\* expect: pass` or `\* expect: violated <Property>`,
and `run.sh` fails if TLC disagrees. Models of pre-fix behaviour (`Original`,
`TwoLoops`) stay in the suite with an expected violation. They show the
property is strong enough to catch the bug, and that the fixed variant
differs from the old one exactly where it should.

| Spec | Models | Properties |
|---|---|---|
| `SniTlsReload.tla` | `sni_tls` cert poller (`reload.go`) racing an operator rotating cert/key files non-atomically | never blanks the listener; never rolls back to an older cert; eventually serves what is on disk |
| `PluginLifecycle.tla` | caddy's `Restart` / `startWithListenerFds` driving the `OnStartup`/`OnRestart`/`OnRestartFailed`/`OnFinalShutdown` hooks of `sni_tls` and `radnr`, with another plugin's callbacks failing at each point | no orphaned goroutine; at most one per instance; at most one per process; nothing survives shutdown |
| `RadnrRA.tla` | `radnr` `Advertiser.Run` scheduling with its real constants (30s interval, 3s `MIN_DELAY_BETWEEN_RAS`), RS arriving at any second | RFC 4861 §6.2.6 rate limit across *all* triggers; every RS answered within the window |
| `DynUpdateAtomicity.tla` | `dynupdate` `serveUpdate` with records as shared heap cells, and a zone rebuild that can fail | a SERVFAIL'd UPDATE changes nothing; the records prerequisites see are the records served |

### Three checkers

- **SANY** (the TLA+ front end) parses and level-checks every spec.
- **TLC** explores each `.cfg`'s instance exhaustively, including the
  liveness property `EventuallyServesDisk` under the spec's fairness
  conditions.
- **Apalache** first type-checks every spec (each constant, variable and
  ambiguous operator is annotated). It then re-checks each TLC config
  symbolically, to TLC's reported state-graph depth for that instance, so
  the bounded search reaches every state TLC did. Each config's second
  line gives the bound and the properties. Apalache does not check
  fairness, so it sees only the safety part: `NoRollback` is checked in
  its step form `NoRollbackStep`, and the liveness-only config is skipped.
  The two deepest bounded runs (75 and 29 steps) are marked `slow` and run
  only with `APALACHE_SLOW=1`; the inductive proofs below cover the same
  properties.

### Inductive invariants (`tla/inductive/`, Apalache)

Each passing model has an `IndInv`. For each config, Apalache shows three
things: `Init` implies it, every `Next` step preserves it, and it implies
the model's safety properties. Together that is a proof for every reachable
state of the instance, at any depth. That makes instances checkable that
are far beyond what TLC can enumerate:

| Config | Instance | TLC's instance |
|---|---|---|
| `RadnrRA_Year` | a year of seconds (31,536,000), real radnr timing | 70 seconds |
| `SniTlsReload_ThreeLoopsSerialized` | three pollers under `reloadMu`, 50 rotations | two pollers, 3 rotations |
| `SniTlsReload_OneLoop` | one poller, no mutex, 50 rotations | 3 rotations |
| `PluginLifecycle_Registry_X{First,Last}` | 12 reloads | 3 |
| `DynUpdateAtomicity_DeepCopy` | 15 UPDATEs | 3 |

Each proof with a pre-fix counterpart has a **negative control**
(`expect: refuted`): the same invariant on the v0.4.1 variant
(`RadnrRA_Year_Original`, `SniTlsReload_ThreeLoopsNoMutex`,
`DynUpdateAtomicity_Original`) must *not* be provable. That shows the
invariant really depends on the fix, so the proof is not passing vacuously.

## Lean proofs (`lean/CorednsPlugins/`)

| File | Go | Proved |
|---|---|---|
| `Serial.lean` | `dynupdate` `serialGreater`, `bumpSerial` | exactly RFC 1982 §3.2; irreflexive, asymmetric, total except the undefined antipodes; `Serial++` always advances, including at 2³²−1; not transitive (and why that's safe here) |
| `Wildcard.lean` | `sni_tls` `wildcardOf`, `GetCertificate` | exact characterisation of which names a `*.d` key covers; never the apex `d`; never two labels deep (RFC 6125 §6.4.3); strict mode only returns SAN-matched certs; non-strict always returns one; exact match beats wildcard |
| `Dnr.lean` | `radnr/pkg/dnr` `Marshal`, `Unmarshal`, `encodeADN`, `decodeADN` | **`Unmarshal(Marshal(o)) = o`** for every option `Marshal` accepts (ADN minus one trailing dot); output is 8-octet aligned with a correct Length octet and fits it (RFC 4861 §4.6, RFC 9463 §6.1) |
| `DynUpdate.lean` | `dynupdate` `apply`, `applyAdd`, `applyDeleteRRset`, `applyDeleteRecord` | **every update section keeps a zone well-formed**: one SOA, at the apex; ≥1 apex NS; CNAME exclusivity; ≤1 CNAME per name. Plus counterexamples, by evaluation, for the v0.4.1 add rules |
| `Probe.lean` | `probe` `ParseQuery`, `parseToken`, `ParseKeyTagQuery`, `FormatKeyTagQuery` | `ParseQuery` is ASCII-case-insensitive (safe under 0x20 randomisation) for any modifier table; RFC 8145 key-tag labels round-trip for 1–16 tags |

Every theorem depends only on Lean's standard axioms (`propext`,
`Classical.choice`, `Quot.sound`). `run.sh lean` fails on any `sorry`.

## Findings

Fixed in this change. Each has a Go regression test that fails on the old
code:

1. **dynupdate: an UPDATE adding an SOA appended a second SOA instead of
   replacing it.** The view served the last SOA while `bumpSerial` advanced
   the first, so from then on the served serial never moved and secondaries
   never transferred another change. An ACME challenge published after that
   would never reach the public secondaries. An SOA for a name below the apex
   was also accepted and became the zone's SOA. (`DynUpdate.lean`
   `original_*`; `TestSOAAddReplacesAndSerialKeepsMoving`,
   `TestSOABelowApexIsIgnored`.)
2. **dynupdate: an UPDATE adding a CNAME where one existed left two CNAMEs**,
   where RFC 2136 §3.4.2.2 says to replace it.
   (`TestCNAMEAddReplacesExistingCNAME`.)
3. **dynupdate: a SERVFAIL'd UPDATE still changed the zone.** `apply` copies
   the slice but not the records. The TTL refresh and `soa.Serial++` wrote
   through to the live `d.rrs`, and a later successful UPDATE published them.
   (`DynUpdateAtomicity_Original.cfg`; `TestFailedRebuildLeavesZoneUntouched`.)
4. **sni_tls and radnr: `OnStartup` could orphan a running goroutine.** When
   a plugin registered earlier fails its `OnRestart`, caddy still runs
   `OnRestartFailed` for every plugin, including ours, whose `OnRestart`
   never ran. For radnr that left a second advertiser on the wire, holding
   its own raw socket, which no reload or shutdown would stop.
   (`PluginLifecycle_Original_XFirst.cfg`;
   `TestLiveStore_Lifecycle_RestartFailedWithoutRestart`,
   `TestOnStartup_RestartFailedWithoutRestart`.)
5. **sni_tls: two pollers on one store could pin an old certificate
   forever.** `current` and `digest` are separate atomic stores, so
   interleaved reloads could leave an old cert next to a digest that matches
   the disk, and no later poll would ever fix it. Now serialised by a mutex.
   (`SniTlsReload_TwoLoopsLiveness.cfg`.)
6. **radnr: the 3s RA rate limit only covered solicited RAs.** A periodic RA
   could follow a solicited one 1s later, against RFC 4861 §6.2.6's MUST.
   An RS inside the window was also dropped rather than answered when it
   closed. (`RadnrRA_OriginalGap.cfg`, `RadnrRA_Original.cfg`;
   `TestAdvertise_RateLimitCoversPeriodicRAs`,
   `TestAdvertise_RateLimitedRSIsDeferred`.)

Not fixed. Each needs a decision:

- **A reload that fails after the new instance's `OnStartup` ran leaks that
  instance's goroutine.** Examples: a later plugin's `OnStartup` errors, or
  the new Corefile's listen address is taken. caddy drops the instance
  without calling its shutdown hooks
  (`PluginLifecycle_Idempotent_*.cfg`, expected violation). For sni_tls the
  leak is a poller writing a store nobody serves. For radnr it is a second
  advertiser sending RAs from the *new*, never-activated config. The
  `registry` variant (a process-wide handover slot, so a newer `OnStartup`
  cancels whatever a dropped instance left behind) passes every invariant.
  It needs a key (per interface? per server block?) that is a design choice.
- **sni_tls: SNI `.example.com`, with an empty first label, selects the
  `*.example.com` cert, even in strict mode** (`Wildcard.lean`
  `empty_label_selects_wildcard`). It can't authenticate anything, since the
  client then fails to match the cert. But strict mode is meant to refuse
  every non-match.
- **radnr: `decodeADN` is looser than `encodeADN`.** It accepts a label
  containing a `.` octet, and ignores octets after the root label inside the
  ADN field, so distinct encodings decode to the same name
  (`Dnr.lean` `decodeADN_not_injective`, `decodeADN_ignores_trailing`).
  radnr only emits the option, so this matters only to anything reusing
  the decoder.

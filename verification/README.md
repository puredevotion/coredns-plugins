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

### Grounded in the RFC text

Every property is stated against the RFC it comes from, quoted verbatim in
the spec or proof that checks it, and the models were audited against the
RFC texts themselves, section by section: RFC 1035, 1982, 2136, 2181, 3007,
4034, 4343, 4861, 6066, 8106, 8145, 8415, 8945, 9460, 9461, 9462, 9463 and
9525 (which obsoletes 6125). Where the plugins cite a section, the citation
was checked too. What the audit found that this change does not fix is
listed at the end, under "Open findings".

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
| `PluginLifecycle.tla` | caddy's `Restart` / `startWithListenerFds` driving the `OnStartup`/`OnRestart`/`OnRestartFailed`/`OnFinalShutdown` hooks of `sni_tls` and `radnr`, with another plugin's callbacks failing at each point; variants for v0.4.1, an intermediate fix, and the process-wide registry they now use | no orphaned goroutine; at most one per instance; at most one per process; nothing survives shutdown |
| `RadnrRA.tla` | `radnr` `Advertiser.Run` scheduling with its real constants (30s interval, 3s `MIN_DELAY_BETWEEN_RAS`, 0.5s `MAX_RA_DELAY_TIME`) in half-second ticks, RSes at any instant, every random draw | RFC 4861 §6.2.6's three MUSTs: the rate limit across *all* triggers; every RS answered by the §6.2.6 deadline (its random delay, after the rate-limit window if inside one); unsolicited RAs never more often than MinRtrAdvInterval |
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
  The two deepest bounded runs (145 and 29 steps) are marked `slow` and run
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
| `RadnrRA_Year` | a year (63,072,000 half-second ticks), real radnr timing | 70 seconds |
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
| `Serial.lean` | `dynupdate` `serialGreater`, `bumpSerial` | exactly RFC 1982 §3.2; irreflexive, asymmetric, total except the undefined antipodes; the automatic increment always advances and never yields 0 (RFC 2136 §7.11), including at 2³²−1; not transitive (and why that's safe here) |
| `Wildcard.lean` | `sni_tls` `wildcardOf`, `GetCertificate` | exact characterisation of which names a `*.d` key covers: exactly one non-empty label (RFC 9525 §6.3, "can only match one label") — never the apex, never two labels deep, never an empty label; strict mode only returns SAN-matched certs and refuses `.d`; non-strict always returns one; exact match beats wildcard |
| `Dnr.lean` | `radnr/pkg/dnr` `Marshal`, `Unmarshal`, `encodeADN`, `decodeADN` | **`Unmarshal(Marshal(o)) = o`** for every option `Marshal` accepts (ADN minus one trailing dot); output is 8-octet aligned with a correct Length octet and fits it (RFC 4861 §4.6, RFC 9463 §6.1) |
| `DynUpdate.lean` | `dynupdate` `apply`, `applyAdd`, `applyDeleteRRset`, `applyDeleteRecord` | **every update section keeps a zone well-formed** under RFC 2136 §3.4.2.2–4's SOA, CNAME and apex rules: one SOA, at the apex; ≥1 apex NS; CNAME exclusivity; ≤1 CNAME per name. Plus counterexamples, by evaluation, for the v0.4.1 add rules. Not modelled (so not claimed): WKS, case-insensitive names inside RDATA, RRset TTL uniformity |
| `Probe.lean` | `probe` `ParseQuery`, `parseToken`, `ParseKeyTagQuery`, `FormatKeyTagQuery` | `ParseQuery` is ASCII-case-insensitive exactly as RFC 4343 §3 defines it (safe under 0x20 randomisation) for any modifier table; RFC 8145 §5.1 key-tag labels round-trip, sorted, for every tag list that fits a 63-octet label — 1 to 12 tags (RFC 1035 §2.3.4) |

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
6. **radnr: RA scheduling did not follow RFC 4861 §6.2.6.** v0.4.1 rate
   limited only solicited RAs, so a periodic RA could follow a solicited one
   a second later; answered an RS at once, where it "MUST be delayed by a
   random time between 0 and MAX_RA_DELAY_TIME seconds"; dropped an RS
   arriving inside the rate-limit window; and never reset the interval timer
   after a solicited RA, so the next unsolicited one could come sooner than
   MinRtrAdvInterval. Every RA now goes out on the interval timer, which a
   solicitation moves in by the §6.2.6 procedure. (`RadnrRA_Original*.cfg`;
   `TestAdvertise_RateLimitCoversPeriodicRAs`,
   `TestAdvertise_RateLimitedRSIsDeferred`, `TestSchedule_*`.)
7. **sni_tls and radnr: a reload that failed after the new instance's
   `OnStartup` ran leaked that instance's goroutine.** caddy drops such an
   instance (a later plugin's `OnStartup` errors, or a listener cannot bind)
   without calling its shutdown hooks. For radnr that was a second advertiser
   sending RAs from a Corefile that never took effect. Both plugins now keep
   a process-wide registry keyed by the caddy instance (its server-type
   context): every `OnStartup` stops whatever a *different* instance left
   running, so the old instance's `OnRestartFailed` reclaims it. Several
   radnr blocks in one Corefile are one instance and coexist.
   (`PluginLifecycle_Registry_*.cfg`, `inductive/PluginLifecycle_Registry_*`;
   `TestOnStartup_ReclaimsDroppedInstance`,
   `TestLiveStore_Lifecycle_ReclaimsDroppedInstance`.)
8. **sni_tls: SNI `.example.com` (empty first label) selected the
   `*.example.com` cert, even in strict mode.** RFC 9525 §6.3: a wildcard
   "can only match one label", and an empty string is not one.
   (`Wildcard.lean` `empty_label_no_wildcard`, `strict_refuses_empty_label`;
   `TestGetCertificate_Strict_EmptyLeftLabelIsNotAWildcardMatch`.)
9. **dynupdate: serial increments against RFC 2136.** An UPDATE that set the
   SOA itself was bumped once more on top (client sends 500, zone serves
   501), where §3.6 increments only "If the zone's SOA's SERIAL is not
   changed as a result of an update operation"; and the increment could
   wrap to 0, which §7.11 forbids. (`Serial.lean` `bump_ne_zero`;
   `TestSOAAddReplacesAndSerialKeepsMoving`, `TestSerialIncrementSkipsZero`.)

## Open findings

Reading the plugins against the RFC texts also turned up the following,
which this change documents but does not fix. Each is a behaviour change
that needs a decision.

**dynupdate**
- *Security:* `mutable TXT` can be bypassed. An ANY/ANY "delete all RRsets
  at a name" skips the type check (`update.go` prescan), so a key limited to
  TXT can delete a name's A/AAAA/MX records. RFC 3007 §3: permissions "MUST
  be enabled though configuration".
- The prescan's meta-type check misses TSIG, TKEY and the rest of
  128–255, and does not reject unknown types: §3.4.1.2 says "any other QUERY
  metatype, or any unrecognized type, then signal FORMERR". A class-IN TSIG
  RR in an update section would be added to the zone.
- RRset TTLs can end up mixed (RFC 2181 §5.2, "the TTLs of all RRs in an
  RRSet must be the same"); domain names inside RDATA are compared
  case-sensitively (RFC 2136 §1.1.2); a wrong ZCLASS gets FORMERR where
  §3.1.1 says NOTAUTH; WKS is not replaced (§1.1.5); and nothing is written
  to nonvolatile storage (§3.5), as the README now says.

**radnr**
- The advertiser never joins ff02::2. RFC 4861 §6.2.2: "A router MUST join
  the all-routers multicast address on an advertising interface". Hosts send
  RSes there, so unless the kernel already joined it (Linux does with
  forwarding enabled), the solicited path never sees an RS.
- Received RSes are not validated (§6.1.1, "The IP Hop Limit field has a
  value of 255"); the first three intervals are not capped at 16s (§6.2.4,
  SHOULD); an allowed default-router lifetime is not bounded to
  MaxRtrAdvInterval..9000s (§6.2.1); SvcParams presence rules are not
  enforced (RFC 9461 §5: with an HTTP alpn, "dohpath" MUST be present and
  contain `dns`; RFC 9463 §6.1: SvcParams "SHOULD include at least the
  "alpn" SvcParam"); no final RA with lifetime 0 on shutdown (RFC 4861
  §6.2.5, RFC 9463 §6.1); dry-run mode leaks a goroutine on every reload
  (not an RFC matter).
- The decoder is looser than the RFC: `decodeADN` accepts label lengths
  64–255 and compression pointers (RFC 8415 §10 "MUST NOT be stored in
  compressed form"), a label containing `.`, and trailing octets after the
  root label (`Dnr.lean` `decodeADN_not_injective`,
  `decodeADN_ignores_trailing`); and neither `Marshal` nor `Unmarshal`
  handles RFC 9463 ADN-only mode. radnr only emits full-mode options, so
  this matters only to anything reusing the codec.

**sni_tls**
- `strict` conflicts with DDR by IP (RFC 9462 §6.3: resolvers "will need to
  be configured to present the appropriate TLS certificate when no SNI is
  present"). The design doc no longer recommends `strict` for verified-DDR
  instances; serving a configured no-SNI default while still refusing
  unmatched SNI would fix it properly. Also, `loadCert` rejects a
  certificate with only IP-address SANs.
- SNI is lower-cased with Unicode `strings.ToLower`, so a non-ASCII SNI
  (KELVIN SIGN `K`) can fold onto an ASCII SAN, even in strict mode; RFC
  9525 §6.3 and RFC 4343 §3 fold ASCII only.
- Strict mode's refusal sends `internal_error`, not RFC 6066 §3's
  `unrecognized_name(112)`; returning `(nil, nil)` would make Go send 112.
- SANs RFC 9525 §6.3 says "MUST be ignored" (`f*.example.com`,
  `*.*.example.com`) are loaded as literal keys, and an SNI containing `*`
  can select them.

**probe**
- EDNS option 14 is recorded only on probe-token names, where RFC 8145 §4.2
  forbids it ("MUST NOT include the edns-key-tag option for non-DNSKEY
  queries"), and not on the apex DNSKEY queries where it legitimately
  appears; multiple option-14 instances keep only the last (§4.2.2.1 sends
  two lists in separate instances); Key Tag queries are counted whatever
  their QTYPE, where §5.1 defines them as "type NULL and of class IN".

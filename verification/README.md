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
| `Wildcard.lean` | `sni_tls` `wildcardOf`, `GetCertificate` | exact characterisation of which names a `*.d` key covers: exactly one non-empty label (RFC 9525 §6.3, "can only match one label") — never the apex, never two labels deep, never an empty label; to a client that sent SNI, strict mode only returns SAN-matched certs, whatever `no_sni` says, and refuses `.d`; `no_sni` affects only clients without SNI, which get exactly the configured policy's cert (RFC 9462 §6.3); non-strict always returns one; exact match beats wildcard; `asciiLower` folds two bytes together only if they are the cases of one ASCII letter, so no non-ASCII SNI folds onto an ASCII SAN (RFC 4343 §3) |
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

10. **dynupdate: `mutable` could be bypassed.** A "delete all RRsets from a
    name" (class ANY, type ANY; RFC 2136 §2.5.3) skipped the type check, so a
    key limited to `mutable TXT` could delete a name's A, AAAA and MX
    records. Under `mutable` it is now REFUSED. RFC 3007 §3: "Policy
    dictates the authorized actions that an authenticated principal can
    take." (`TestMutableRefusesDeleteAllRRsetsAtName`.)
11. **dynupdate: the prescan let meta-types and unknown types through.** RFC
    2136 §3.4.1.2 answers FORMERR for "any other QUERY metatype, or any
    unrecognized type". Only ANY, AXFR, IXFR, MAILA, MAILB and OPT were
    caught, so a class-IN TSIG or TKEY record in an update section was added
    to the zone. Now rejected: type 0, OPT, all of 128–255 (RFC 6895 §3.1,
    "Q and Meta-TYPEs"), and any type miekg/dns does not know.
    (`TestPrescanRejectsMetaAndUnknownTypes`.)
12. **radnr: the socket never joined ff02::2, and accepted any RS.** RFC 4861
    §6.2.2: "A router MUST join the all-routers multicast address on an
    advertising interface", which is where hosts send RSes; without it they
    were heard only if the kernel had joined for other reasons (Linux does
    with forwarding on). And §6.1.1's checks were not applied, so a
    forwarded RS (hop limit below 255) was answered. The socket now joins
    the group and reads the hop limit; an RS needs hop limit 255, ICMP Code
    0, and no source link-layer address option when sent from `::`.
    (`TestBecomeRouter_JoinsAllRoutersAndReadsHopLimit`,
    `TestAdvertise_ForwardedSolicitationIsIgnored`, `TestValidSolicitation`,
    `TestParseNDP_RejectsNonZeroCode`. The real socket path, `dialNDP`, runs
    in `TestNdpListen_RealRawSocket_RequiresPrivilege` where the runner has
    a link-local interface and `CAP_NET_RAW`.)
13. **radnr: dry-run leaked two goroutines per reload.** The dry-run conn's
    `ReadFrom` blocked forever and `Close` did nothing, so `Run`, which waits
    for its reader on shutdown, never returned. (Not an RFC matter.)
    (`TestDryRunAdvertiserStopsOnCancel`, `TestNopConn_Methods`.)
14. **sni_tls: three RFC defects in certificate selection.**
    - SNI was lower-cased with Unicode `strings.ToLower`, so SNI
      `\u212a.example.com` (KELVIN SIGN) folded onto `k.example.com` and
      selected its cert, strict mode included. RFC 9525 §6.3 and RFC 4343
      §3 fold ASCII only. (`Wildcard.lean` `fold_eq_iff`, `kelvin_not_k`;
      `TestGetCertificate_FoldsASCIIOnly`.)
    - Strict mode's refusal sent `internal_error(80)`, not RFC 6066 §3's
      `unrecognized_name(112)`. (`TestSetup_StrictRefusalSendsUnrecognizedName`,
      a real handshake over TLS 1.2 and 1.3.)
    - SANs RFC 9525 §6.3 says "MUST be ignored" (`f*.example.com`,
      `*.*.example.com`) were keyed as literal names, so an SNI spelling one
      out selected that cert. (`TestLoadCert_IgnoresInvalidWildcardSANs`.)
15. **probe: RFC 8145 signals recorded in the wrong places.** Option 14 was
    read only on probe names, where §4.2 forbids senders to put it, and
    never on the apex DNSKEY queries that §4.2 says carry it. Of several
    instances (§4.2.2.1 sends two lists "using separate instances") only
    the last was kept. A `_ta-` name was counted as a Key Tag query whatever
    its type, where §5.1 defines one as "type NULL and of class IN". Apex
    DNSKEY queries are now counted (`source="dnskey"`), every instance is
    kept, and only NULL/IN is counted. (`TestApexDNSKEYQueryCountsEDNSKeyTags`,
    `TestObserveKeepsEveryEDNSKeyTagInstance`, `TestKeyTagQueryCountedOnlyForNULL`.)
    The `_ta-` prefix now folds ASCII-only too; no non-ASCII character
    folds into `_ta-`, so that one changes no behaviour.
16. **sni_tls: strict mode could not serve DDR-by-IP clients.** RFC 9462
    §6.3: resolvers "that support discovery using IP addresses will need to
    be configured to present the appropriate TLS certificate when no SNI is
    present", and strict mode refused every ClientHello without SNI. The new
    `no_sni` option sets that case on its own: `refuse`, `fallback` (the
    first-loaded cert), or `cert <cert> <key>` (a cert for no-SNI clients
    alone, which may carry only IP-address SANs). With `strict`, an
    unmatched SNI is still refused under every policy. Unset, nothing
    changes. (`Wildcard.lean` `strict_only_matched`,
    `noSNI_irrelevant_with_sni`, `default_absent`, `noSNI_cert_absent`;
    `TestGetCertificate_NoSNIPolicies`,
    `TestSetup_StrictWithNoSNICert_Handshakes`,
    `TestSetup_StrictWithNoSNIFallback_Handshakes`,
    `TestLiveStore_NoSNICertHotReload`.)
17. **sni_tls: a refused client without SNI got the wrong alert over QUIC.**
    RFC 8446 §9.2: "Servers requiring this extension SHOULD respond to a
    ClientHello lacking a "server_name" extension by terminating the
    connection with a "missing_extension" alert". Over QUIC (DoQ, DoH3),
    crypto/tls hands the error `GetCertificate` returns to the QUIC stack,
    and quic-go sends the first `tls.AlertError` in it as CRYPTO_ERROR
    0x0100+alert (RFC 9001 §4.8). So the refusal there now returns an error
    wrapping `missing_extension(109)`; quic-go marks the connection by giving
    `ClientHelloInfo.Conn` a UDP local address. Over TCP the refusal stays
    `(nil, nil)`, because crypto/tls sends any other error as
    `internal_error`. (`TestSetup_QUICHandshakeAlerts`, real quic-go
    handshakes; `TestGetCertificate_NoSNIRefusalOverQUICIsMissingExtension`.)

## Open findings

Reading the plugins against the RFC texts also turned up the following,
which this change documents but does not fix. Each is a behaviour change
that needs a decision.

**dynupdate**
- RRset TTLs can end up mixed (RFC 2181 §5.2, "the TTLs of all RRs in an
  RRSet must be the same"); domain names inside RDATA are compared
  case-sensitively (RFC 2136 §1.1.2); a wrong ZCLASS gets FORMERR where
  §3.1.1 says NOTAUTH; WKS is not replaced (§1.1.5); and nothing is written
  to nonvolatile storage (§3.5), as the README now says.

**radnr**
- The first three intervals are not capped at 16s (RFC 4861 §6.2.4,
  SHOULD); an allowed default-router lifetime is not bounded to
  MaxRtrAdvInterval..9000s (§6.2.1); SvcParams presence rules are not
  enforced (RFC 9461 §5: with an HTTP alpn, "dohpath" MUST be present and
  contain `dns`; RFC 9463 §6.1: SvcParams "SHOULD include at least the
  "alpn" SvcParam"); no final RA with lifetime 0 on shutdown (RFC 4861
  §6.2.5, RFC 9463 §6.1).
- The decoder is looser than the RFC: `decodeADN` accepts label lengths
  64–255 and compression pointers (RFC 8415 §10 "MUST NOT be stored in
  compressed form"), a label containing `.`, and trailing octets after the
  root label (`Dnr.lean` `decodeADN_not_injective`,
  `decodeADN_ignores_trailing`); and neither `Marshal` nor `Unmarshal`
  handles RFC 9463 ADN-only mode. radnr only emits full-mode options, so
  this matters only to anything reusing the codec.

**sni_tls**
- Over TCP (DoT, DoH), a TLS 1.3 client that sends no SNI and is refused
  still gets `unrecognized_name`, not RFC 8446 §9.2's `missing_extension`.
  On the TCP path, crypto/tls (checked in go1.27.1, the 1.27 release notes
  and master) sends `unrecognized_name` for its own "no certificates"
  error and `internal_error` for any other `GetCertificate`,
  `GetConfigForClient` or `GetEncryptedClientHelloKeys` error. QUIC is
  fixed (finding 17).

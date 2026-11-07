# `geoscore`: answer with the endpoint that scores best on a live signal

Design record: what this plugin does, what it refuses to do, and the rules
the code, the Lean proofs and the TLA+ model are checked against. Each rule
has a number (R1 to R26). The code, tests and models cite these numbers, and
the table at the end says what checks each one.

## Problem

A name such as `www.example.com` has several equivalent endpoints: one per
region, provider or site. Which one a client should get changes over time,
following a signal measured outside DNS. The signal can be latency from the
vantage points that matter, the carbon intensity of the grid each site runs
on, the marginal cost of serving there, or plain health. CoreDNS can answer
a fixed RRset (`file`, `hosts`, `template`) or rotate one (`loadbalance`). It
has nothing that answers by a score computed somewhere else and refreshed
continuously.

`geoscore` fills that gap and nothing else. For one configured owner name it
answers A and AAAA with the addresses of one endpoint, chosen from a fixed,
validated candidate set by scores read from Valkey. It does not measure
anything, it does not know what a score means, and it does not look at the
client's address. A separate writer (a CronJob or daemon, **out of scope
here**) measures the signal, turns it into a score per endpoint and writes
the score map described below. The plugin and the writer share a key space
and nothing else, the same seam `probe` has with its web tier.

What it does not do:

- **No client-specific answers.** Every client gets an answer from the same
  candidate set and the same scores; there is no EDNS Client Subnet (RFC
  7871) or GeoIP lookup. "Geo" here means the endpoints are in different
  places, not that the answer depends on where the client is.
- **No health checking of its own.** `healthy` in the score map is the
  writer's verdict. The plugin's only defence against a dead or wrong writer
  is that a score older than `max-staleness` is ignored (R21).
- **No CNAME or SVCB/HTTPS synthesis.** Only A and AAAA at the configured
  name, plus an optional TXT rationale beside it (R23).

## Corefile

```
geoscore NAME {
    endpoint ID ADDRESS [ADDRESS...]     # repeatable: the candidate set, in tie-break order
    store valkey ADDR [ADDR...] | memory
    tls_ca FILE                          # required with store valkey
    key PREFIX                           # default geoscore:NAME (without the trailing dot)
    mode best | weighted                 # default best
    max-staleness DURATION               # default 5m
    ttl SECONDS                          # default 30
    fallback static | servfail | nodata  # default static
    refresh DURATION                     # default 1s
    timeout DURATION                     # default 100ms
    rationale-txt
}
```

`NAME` without a trailing dot is relative to the server block's zone, as in
a zone file (RFC 1035 §5.1): `geoscore www` in a block for `example.com`
configures `www.example.com.`. Several `geoscore` blocks may share a server
block, one per name. All properties except `endpoint` may appear at most once.

## Requirements

### Which queries are answered

**R1.** The plugin answers a query only when it has exactly one question, of
class IN, whose name is a configured `NAME`, and whose type is A or AAAA,
**and** at least one endpoint has an address of that family. It also answers
TXT at `_geoscore.NAME` when `rationale-txt` is set (R23).

**R2.** Every other query goes to the next plugin unchanged: other types at
`NAME` (MX, TXT, ANY, ...), A at a name whose endpoints are all IPv6 (and
AAAA when they are all IPv4), and every other name. So the zone's other
data, its SOA, and NXDOMAIN for names that do not exist all come from the
backend behind the plugin (`file`, `dynupdate`, ...). The zone must hold
`NAME` (for example with a TXT, or with the static A/AAAA the `static`
fallback also answers). Otherwise the backend answers NXDOMAIN for the other
types at a name that has A records, which RFC 1034 §4.3.2 does not allow.

**R3.** Names compare ASCII case-insensitively and no other way (RFC 4343
§3): no non-ASCII octet folds onto an ASCII one. The answer's owner name is
spelled as the question spelled it, so 0x20 case randomisation in the
resolver keeps working.

**R4.** An address answer is NOERROR with AA set (RFC 1035 §4.1.1) and the
**complete** RRset of the chosen endpoint's addresses of that family (up to
8), all with the configured TTL, since RRs of one RRset must have one TTL
(RFC 2181 §5.2). Addresses are never mixed across endpoints.

### Configuration: the candidate set

**R5.** An endpoint address is one an A (RFC 1035 §3.4.1) or AAAA (RFC 3596
§2.2) record can usefully carry: not unspecified, loopback or multicast,
without a zone index, and not IPv4-mapped IPv6 (RFC 4291 §2.5.5.2). A mapped
address would be answered as AAAA for what is really an IPv4 endpoint, so it
must be written as IPv4. No address may belong to two endpoints, because
then an answer could not be traced to one endpoint.

**R6.** `ttl` is 0 to 2³¹−1 (RFC 2181 §8), and is further bounded by R22.

**R7.** `fallback nodata` answers NOERROR with an empty answer section and
the zone's SOA in the authority section (RFC 2308 §2.2), with TTL
min(SOA TTL, SOA MINIMUM) (RFC 2308 §3, §5). The plugin gets the SOA by
asking the next plugin for `ZONE SOA`. If no SOA comes back, it answers
SERVFAIL, because a NODATA without an SOA cannot be cached correctly (RFC
2308 §5).

**R8.** `fallback servfail` answers SERVFAIL (RCODE 2, RFC 1035 §4.1.1).

**R9.** `NAME` must be at or below the server block's zone. It is stored
fully qualified and lowercase, and is never the root.

**R10.** A malformed block stops the server from starting: an unknown or
repeated property, a missing or extra argument, an unparsable address,
duration or number, or anything R5, R6, R9, R13 or R22 refuses (fail closed,
CONTRIBUTING.md). A block that fails validation never opens a store
connection.

**R11.** `store valkey` requires `tls_ca` and has no option to skip
certificate verification. The scores decide where clients are sent, so a
store that anyone on the path could answer for would let them steer
traffic. `tls_ca` with `store memory` is an error. If the Valkey client
cannot be built, startup fails rather than answering every query with the
fallback. `store memory` exists for tests and dry runs. Nothing outside the
process can write to it, so a warning is logged at startup and every answer
is the fallback.

**R12.** The entry for endpoint `ID` lives at the Valkey string key
`PREFIX:ID`. All of a name's keys are read with one `MGET` per refresh
(R24); against Valkey Cluster, where a name's keys hash to different slots
and one `MGET` across slots is refused, the read is one `MGET` per slot,
and it fails as a whole if any part fails (R25). `PREFIX` is 1 to 64 of
`[A-Za-z0-9:._-]`.

**R13.** The candidate set has 1 to 16 endpoints and each endpoint has 1 to
8 addresses per family. `ID` is 1 to 32 of `[a-z0-9-]`, does not start with
`-`, and is unique within the block. IDs appear in keys and in the rationale
TXT, so they are restricted to characters that need no escaping in either.
`max-staleness` is whole seconds in [1s, 24h], `refresh` is in [100ms,
max-staleness], and `timeout` is in [1ms, 5s]. The configured order of the
`endpoint` lines is the **tie-break order** (R18) and the **static fallback
order** (R20). The **candidate set for a query** is the endpoints with at
least one address of the queried family, in configured order.

### The score map

The writer publishes one JSON object per endpoint, as a plain string value:

```
SET geoscore:www.example.com:eu1 '{"score":0.83,"healthy":true,"updated":1762500000,"signal":"carbon","note":"212 gCO2/kWh"}'
```

| field | required | type and range | meaning |
|---|---|---|---|
| `score` | yes | JSON number, 0 ≤ score ≤ 1 | higher is better; 0 drains the endpoint |
| `healthy` | yes | JSON boolean | `false` means never select |
| `updated` | yes | integer Unix seconds, 1 to 253402300799 | **the writer's** clock when it computed the score |
| `signal` | no | 0 to 16 of `[a-z0-9-]` | what the score measures, e.g. `latency`, `carbon`, `cost`, `health` |
| `note` | no | 0 to 100 printable ASCII (0x20 to 0x7E) | free text shown in the rationale TXT |

Guidance for the writer (out of scope for this repository, but its contract):

- Normalise every signal to [0, 1] before writing. Different signals can be
  combined (for example 0.7 × latency score + 0.3 × carbon score); the plugin
  only sees the result. For a signal where lower is better (latency, gCO₂/kWh,
  cost), map it so the best endpoint gets the highest score.
- Write every endpoint on every run, each with its own `updated`. Run more
  often than `max-staleness`, ideally at most a third of it, so one missed
  run does not drain the name.
- Keep the writer's clock NTP-synchronised. An entry dated more than 30 s
  ahead of the plugin's clock is ignored (R21).
- To drain an endpoint, write `healthy: false` or `score: 0`. Do not delete
  the key, because a missing key and a dead writer look the same.
- A Valkey key TTL (`SET ... EX`) is optional. `max-staleness` is what
  bounds the age of a score.
- Give the plugin a Valkey ACL user that can only `MGET` its prefix.

**R14.** An entry is read through one validator (`ParseEntry`). It refuses
a value longer than 512 bytes; JSON that is not exactly one object, or has
anything after it; unknown fields, field names in the wrong case (names
must match byte for byte; `encoding/json` alone would fold case, even
Unicode case), a field that appears twice, or a missing required field; a `score` that is NaN, infinite, negative, above 1
or not representable as a float64 (`1e400`); an `updated` outside its range;
and a `signal` or `note` outside its alphabet or length. An entry it refuses
is **invalid**. The whole entry is ignored, it is logged and counted, and the
endpoint is never selected on it. There is no partial acceptance.

**R15.** An endpoint is **eligible** at time *now* exactly when its key
exists, its entry is valid (R14), `healthy` is true, the entry is fresh
(R21), and its **weight** `round(score × 10000)` is positive. Selection uses
only this integer weight, so a score below 0.00005 counts as 0. Only
eligible endpoints are selected (R17).

### Selection

**R16.** Whatever the plugin answers with, for any scores, clock, mode,
fallback and random draw, is a member of the query's candidate set (R13).

**R17.** An endpoint that is missing, invalid, unhealthy, stale,
future-dated or of weight 0 is **never** answered, with one documented
exception: the `static` fallback (R20).

**R18.** `mode best` answers the eligible endpoint of the largest weight,
and on equal weights the one listed **first**. The choice is a function of
(weights, eligibility, configured order) only. The same scores give the same
answer on every query, every replica and every restart.

**R19.** `mode weighted` answers eligible endpoint *i* with probability
wᵢ / Σw, where the sum is over the eligible endpoints of the candidate set.
It never answers an endpoint of weight 0 (the support is exactly the
eligible set), and raising one endpoint's score, all else equal, never
lowers its probability (monotonicity). The draw comes from `math/rand/v2`
per query and only spreads load; it is not a security boundary. Resolvers
cache answers (R22), so the realised split between clients is only
approximately the weights.

**R20.** When **no** endpoint in the candidate set is eligible, and only
then, the fallback applies, in either mode:

- `static` (the default): the **first-listed** endpoint of the family. This
  is what the name would answer without the plugin, so an outage of the
  score pipeline degrades to a fixed answer rather than an error. It is
  the only case where an ineligible endpoint is answered.
- `servfail`: SERVFAIL (R8).
- `nodata`: NOERROR/NODATA with the zone's SOA (R7).

The fallback is chosen per family. A query for A can be answered by score
while AAAA falls back, or the other way round.

### Time

**R21.** Freshness is judged from the **writer's** timestamp `updated`,
never from when the plugin last read the key. An entry is stale when
`now − updated > max-staleness`, and future-dated when `updated > now + 30
s`. Both are ineligible. The first rule means a writer that has stopped
cannot keep its last scores alive by leaving them in a store that is still
up. The TLA+ variant `JudgeByFetch` shows that bug happening. The second
rule means a writer with a wrong clock cannot make a score fresh for longer
than `max-staleness + 30 s`.

**R22.** `ttl` ≤ `max-staleness`, enforced by the validator. An answer is
never given on a score older than `max-staleness` (R21). A resolver keeps it
at most `ttl` more, so no client acts on a score older than
`2 × max-staleness`. The TLA+ variant `LongTTL` breaks the bound when the
check is removed. The CoreDNS `cache` plugin in front of this one is one
more such resolver, and it keeps the bound unless `serve_stale` is enabled
for the zone (see *Placement*).

**R23.** With `rationale-txt`, TXT at `_geoscore.NAME` explains the current
choice to a human or the workbench UI. The answer has one string for the
configuration, one per family the name has, and one per endpoint:

```
"geoscore name=www.example.com. mode=best fallback=static max-staleness=300s ttl=30"
"A outcome=best choice=eu1 eligible=2/3 total-weight=17000"
"AAAA outcome=fallback-static choice=eu1 eligible=0/1 total-weight=0"
"eu1 state=eligible score=0.8500 weight=8500 healthy=true age=12s signal=carbon note=212 gCO2/kWh"
"ap1 state=stale score=0.9900 weight=9900 healthy=true age=400s"
"us1 state=missing"
```

`state` is one of `missing`, `invalid`, `stale`, `future`, `unhealthy`,
`zero` or `eligible`, checked in that order. The rationale is computed from
the same snapshot and clock as an address answer. In `best` mode its
`choice` is exactly what an A or AAAA query gets at that moment. In
`weighted` mode it is one draw, and the weights show the distribution.
Every string is at most 255 octets (RFC 1035 §3.3) and printable ASCII.
The TTL is the configured `ttl`. The owner name is under an underscored
leaf (RFC 8552 §1.1), so it cannot collide with a hostname. It publishes
nothing that is not already in the Corefile or the score map. Turn it off
when the scores or notes are confidential.

**R24.** The plugin answers from an in-process snapshot of the score map.
When a query arrives and the snapshot is older than `refresh`, that query
re-reads the store (one `MGET`, bounded by `timeout`). Only one query
refreshes at a time, and queries that arrive meanwhile answer from the
snapshot they already have, so a slow store delays at most one query per
`refresh` interval, by at most `timeout`. There is no background goroutine,
so there is nothing to leak on reload (the class of bug
`verification/README.md` records for `sni_tls` and `radnr`).

**R25.** A failed read (error, timeout, wrong number of values) **keeps the
previous entries**. It is logged and counted, and the next attempt is one
`refresh` later. The kept entries keep their writers' timestamps, so they go
stale on schedule (R21). A store outage therefore turns into the fallback
at most `max-staleness` after the last good write, and never before. The
plugin keeps answering with good scores while the store blips, and it never
answers with dead ones.

**R26.** Metrics have bounded labels: `name` comes from the Corefile, and
`family` and `outcome` from fixed sets. Nothing from a query becomes a label.

- `coredns_geoscore_answers_total{name,family,outcome}`, where `outcome` is
  one of `best`, `weighted`, `fallback_static`, `fallback_servfail` or
  `fallback_nodata`.
- `coredns_geoscore_store_errors_total{name}`
- `coredns_geoscore_invalid_entries_total{name}`

## Placement in the chain

`geoscore:` goes **immediately after `dnssec:dnssec`** in CoreDNS's
`plugin.cfg`. The Dagger build (`ci/main.go`) puts it there:

- **after `rrl` and `acl`**, so rate limiting and access control see the
  query before anything answers it;
- **after `dnssec`**, so with online signing the answer is signed on the way
  out like any other. A pre-signed zone (`file` with RRSIGs) cannot carry
  signatures for an answer chosen at query time. Use `dnssec` online
  signing for the zone, or leave the name unsigned;
- **before the zone backends** (`hosts`, `dynupdate`, `file`, `probe`,
  `auto`, `secondary`), so the configured name is answered here and
  everything else falls through (R2). The `nodata` fallback asks the next
  plugin for the SOA (R7).

`cache` sits before it in `plugin.cfg` and so caches its answers, for at
most `ttl` (R22). In `weighted` mode a cache hit repeats one draw for that
long, so the split between clients becomes coarser. Keep `ttl` short, or
leave the zone out of `cache`. Do not enable `cache`'s `serve_stale` for the
zone: it would serve answers past the R22 bound.

## Formal models

**Lean (`verification/lean/CorednsPlugins/GeoScore.lean`).** This file is a
model of `selection.go` and `instance.go decide`, on the integer weights
the validator produces. It proves:

| Theorem | Statement | Rule |
|---|---|---|
| `best_sound`, `pick_sound`, `decide_mem` | what is selected is a member of the candidate set | R16 |
| `decide_eligible_or_fallback`, `decide_strict_fallback` | an answered endpoint is eligible, or nothing is eligible, the fallback is `static`, and the answer is the first-listed candidate; with `servfail`/`nodata`, only eligible endpoints are ever answered | R17, R20 |
| `best_max`, `best_first`, `best_spec`, `best_unique`, `best_complete` | best mode is exactly "maximal weight among eligible, earliest on a tie"; that specification picks out one candidate, so best mode is deterministic in (scores, eligibility, tie-break order) | R18 |
| `best_none_iff`, `pick_none_iff`, `select_none_iff` | nothing is selected exactly when no candidate is eligible | R20 |
| `pick_some` | every draw below the total weight selects | R19 |
| `pick_count` | over the `total` equally likely draws, a candidate is selected exactly `ew c` times: probability `w / Σw` | R19 |
| `pick_sound` (third part) | a selected candidate has positive effective weight: weighted mode stays in the support | R19 |
| `pick_monotone` | raising one candidate's weight never lowers its selection probability (`n·T' ≤ n'·T`) | R19 |

Everything is proved without `sorry` and rests only on Lean's standard
axioms. Evaluated examples (`by decide`) pin the stale, future-skew and
tie-break edges.

**TLA+ (`verification/tla/GeoScoreStaleness.tla`, checked by TLC and
Apalache).** This spec models the lifecycle: a writer that stamps entries
and can stop at any point, a store that can fail at any point (every Fetch
is optional), the plugin's snapshot, answers, and a resolver cache of the
answer TTL. Selection is abstracted to "any endpoint the eligibility rule
admits", which covers both modes.

| Config | Expect | Shows |
|---|---|---|
| `GeoScoreStaleness_Fixed` | pass | `NeverServeStale` (R15, R21): an endpoint answer is never on a score older than `max-staleness` or on an unhealthy or zero entry; `FallbackOnlyWhenNoneEligible` (R20); `CacheExposureBound` (R22): no resolver holds an answer on a score older than `2 × max-staleness` |
| `GeoScoreStaleness_JudgeByFetch` | violated `NeverServeStale` | judging freshness by the plugin's last read instead of the writer's timestamp serves a dead writer's score forever |
| `GeoScoreStaleness_NoExpiry` | violated `NeverServeStale` | with no staleness check, the last score is trusted however old it is |
| `GeoScoreStaleness_LongTTL` | violated `CacheExposureBound` | `ttl` > `max-staleness` (refused by the validator) lets resolvers hold answers past the bound |

TLC checks each config exhaustively (two endpoints, `max-staleness` 2,
state-graph depth 18). Apalache type-checks the spec and re-checks the
three violation configs symbolically. It also proves the inductive
invariant `IndInv` for `inductive/GeoScoreStaleness_Minute` (four
endpoints, `max-staleness` 60 s, `ttl` 60): it holds initially, every step
preserves it, and it implies the three properties, so they hold in every
reachable state at any depth. The negative control
`GeoScoreStaleness_Minute_JudgeByFetch` must fail to prove, and does. The
bounded Apalache re-check of `Fixed` to depth 18 takes about 20 minutes,
so it is marked `slow` (run it with `APALACHE_SLOW=1`); the inductive proof
covers the same properties.

The models are written by hand from this document and the Go code. As
everywhere in `verification/`, a result is a statement about the model, and
the Go tests check that the code matches it.

## What backs each rule

| Rule | Go tests | Lean | TLA+ |
|---|---|---|---|
| R1, R2 | `TestServeAnswers`, `TestServePassesOn`, `FuzzServeDNS` | | |
| R3 | `TestServeAnswers` (mixed-case question) | | |
| R4 | `TestServeAnswers` | | |
| R5, R13 | `TestValidateRejects`, `TestEightAddressesPerFamily`, `FuzzParseCorefile` | | |
| R6, R22 | `TestValidateRejects`, `TestParseRejects` | | `CacheExposureBound`, `LongTTL` |
| R7, R8, R20 | `TestServeFallbacks`, `TestStaticFallbackPerFamily` | `decide_eligible_or_fallback`, `select_none_iff` | `FallbackOnlyWhenNoneEligible` |
| R9, R10, R11 | `TestParseFull`, `TestParseRejects`, `TestParseValkeyCA`, `TestValidateRationaleNameLength` | | |
| R12 | `TestMemStore`, `TestValkeyStoreFake` (standalone and cluster), `TestValkeyStoreRoundTrip` (needs `GEOSCORE_VALKEY_ADDR`) | | |
| R14 | `TestParseEntryRejects`, `TestEntryValidateNonFinite`, `TestProperty_EntryRoundTrip`, `FuzzParseEntry` | | |
| R15, R17 | `TestIneligibleNeverChosen`, `TestFutureDatedEntry`, `TestWeightRounding`, `FuzzDecide` | `decide_eligible_or_fallback` | `NeverServeStale` |
| R16 | `TestProperty_DecideMembershipAndFallback`, `FuzzDecide`, `FuzzServeDNS` | `decide_mem` | |
| R18 | `TestBestPicksHighestThenFirstListed`, `TestProperty_BestMatchesSpec` | `best_spec`, `best_unique`, `best_complete` | |
| R19 | `TestWeightedFollowsDraw`, `TestProperty_WeightedExactDistribution`, `TestProperty_WeightedMonotone` | `pick_count`, `pick_monotone`, `pick_sound` | |
| R21 | `TestWriterDeathEndsInFallback`, `TestFutureDatedEntry` | `fresh`, evaluated examples | `NeverServeStale`, `JudgeByFetch`, `NoExpiry` |
| R23 | `TestRationaleTXT`, `TestRationaleStringBound` | | |
| R24 | `TestRefreshInterval`, `TestDecideAllocs` | | |
| R25 | `TestStoreOutage` | | `Fixed` (store failure at every step) |
| R26 | by construction (`metrics.go`) | | |

Allocation budget (`alloc_test.go`, `//go:build !race`): `decide` and a
snapshot read with no refresh due allocate nothing, and a whole `ServeDNS`
for a two-record A answer allocates at most 7 times. Benchmarks are in
`bench_test.go`.

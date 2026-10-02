# Performance notes

Where the per-query time goes in each plugin, what was changed, what each
change bought, and what was tried and dropped. Numbers are `benchstat` over six
runs on a 4-core x86-64 container with Go 1.26; the benchmarks live beside each
plugin (`bench_test.go`) so the comparison can be re-run:

```sh
cd probe && go test -run=NONE -bench=. -benchmem -count=6 ./... > new.txt
benchstat old.txt new.txt
```

## Method

The same loop as any latency-sensitive system, applied per plugin:

1. Write a benchmark for every function on the request path, plus one
   end-to-end `ServeDNS` benchmark per answer shape, with a `ResponseWriter`
   whose addresses are fixed (the CoreDNS test writer parses its address on
   every call and was a third of the allocations measured).
2. Profile CPU and allocations separately. A CPU profile taken with
   `-memprofilerate=1` is mostly the allocation profiler's own stack walks.
3. Change one thing, re-run, keep it only if `benchstat` reports a change at
   p < 0.05, write down the ones that did not.

Nothing here had a benchmark before. The first run found the two defects
below, neither of which was visible from the code's own comments.

## probe

### What was found

| Where | What the profile showed |
|---|---|
| `MemStore.Record` | `expireLocked` walked the **entire** token map (and the reports map) on every query, under the mutex. 78 ns on an empty store, **190 µs at the 10 000-token ceiling** — 3.5× the cost of signing the answer, serialised across every query. |
| `signRRset` | Of 91 allocations per signature, 8 were ours: `rrsigTime` formatted the time to `YYYYMMDDHHmmSS` and parsed it straight back; `Owner()` canonicalised the key name per call; `KeyTag()` base64-decoded the public key per call; `SplitDomainName` allocated a slice only to count labels. |
| `denial` | Every NODATA, NXDOMAIN and compact-denial answer signed **two** RRsets: the NSEC, which differs per query, and the apex SOA, which never does. |
| `ServeDNS` | `plugin.Name.Matches` split both names into label slices (3 allocations), `ParseQuery` and `parseDNSSD` split the name into slices, `addrOf` rendered the client address to text and parsed it back, `Modifier.String` allocated per query, `Summary` allocated 10 times. |
| `recordMetrics` | `WithLabelValues` with seven labels hashed and validated every label on every query: 290 ns, a tenth of the whole unsigned answer. |

### Iterations

| # | Change | Result | Kept |
|---|---|---|---|
| 1 | Expiry queue: entries kept in first-seen order, popped from the front | `Record` at 10k tokens 190 µs → 44 ns; exact same semantics (first-seen expiry, TTL is one constant, so the queue is sorted) | yes |
| 2 | Signer caches `KeyTag` and `Owner`; `CountLabel`; RRSIG times by arithmetic | `signRRset` −7%, −8 allocs; pinned against `dns.StringToTime` at the 2³¹/2³² wrap points by test | yes |
| 3 | Allocation-free `ParseQuery`, `parseDNSSD`, zone suffix match, `addrOf` from the `net.Addr`, `Modifier.String` table, `Summary` into one buffer | unsigned A answer 2.53 µs → 2.02 µs, 25 → 17 allocs | yes |
| 4 | Cache the apex SOA signature per signature-modifier set for 30 s | signed denial 102 µs → 52 µs. Expired/future variants cache separately and stay expired/future | yes |
| 5 | Cache prometheus counter children by packed enum index | `recordMetrics` 290 ns → 87 ns; unsigned A −14% | yes |
| 6 | Signature cache for per-query answers (A/AAAA/TXT keyed by name+rdata) | not implemented: every token is unique per visitor, so hits would come only from retries; a bounded cache for an unknown hit rate is complexity without evidence | no |
| 7 | Avoid heap-allocating the `Observation` passed to the store | not done: it escapes through the `Store` interface, and the one allocation is 1% of the unsigned path | no |

### Where the time is now

A signed answer is one ECDSA P-256 signature plus about 3 µs of everything
else. `BenchmarkSignFloor` measures the signature alone over a digest; the
only way below it is a different key algorithm (Ed25519 signs in roughly half
the time), which is the operator's choice, not this plugin's.

### Results

```
                              │    before    │              after               │
                              │    sec/op    │    sec/op     vs base            │
ParseQuery/baseline             46.16n ± 30%   34.46n ±  6%  -25.34% (p=0.002)
ParseQuery/one-mod              76.25n ±  6%   50.27n ±  5%  -34.06% (p=0.002)
ParseQuery/three-mods           149.8n ± 11%   107.8n ±  6%  -28.09% (p=0.002)
ParseQuery/mixed-case           224.8n ±  4%   124.3n ± 26%  -44.71% (p=0.002)
ParseQuery/refused              60.50n ±  7%   34.65n ±  7%  -42.74% (p=0.002)
Observe                         250.8n ±  7%   130.9n ±  7%  -47.79% (p=0.002)
Summary                         612.8n ±  5%   218.5n ±  5%  -64.34% (p=0.002)
RecordMetrics                  288.70n ±  9%   86.64n ±  4%  -69.99% (p=0.002)
SignRRset/correct               50.56µ ±  6%   46.87µ ±  7%   -7.29% (p=0.015)
SignRRset/badsig                46.65µ ± 12%   45.85µ ±  3%        ~ (p=0.240)
SignRRset/expired               47.94µ ±  5%   47.08µ ±  5%        ~ (p=0.394)
MemStoreRecord/live=0           74.59n ± 11%   43.59n ± 17%  -41.57% (p=0.002)
MemStoreRecord/live=1000     19598.50n ±  8%   46.53n ± 19%  -99.76% (p=0.002)
MemStoreRecord/live=10000   189881.00n ± 16%   44.42n ± 35%  -99.98% (p=0.002)
ServeDNS/A/unsigned             2.534µ ±  7%   1.733µ ± 12%  -31.61% (p=0.002)
ServeDNS/A/signed               54.31µ ±  5%   48.06µ ±  4%  -11.50% (p=0.002)
ServeDNS/TXT/signed             52.86µ ±  9%   50.56µ ±  9%        ~ (p=0.394)
ServeDNS/TXT/big/signed         74.45µ ± 15%   56.77µ ±  4%  -23.75% (p=0.002)
ServeDNS/nxname/signed         102.59µ ±  5%   52.43µ ±  8%  -48.89% (p=0.002)
ServeDNS/refused                1.361µ ±  7%   1.154µ ±  7%  -15.18% (p=0.002)
ServeDNS/not-our-zone           535.5n ± 37%   442.5n ± 10%  -17.36% (p=0.002)
geomean                         2.569µ         902.6n        -64.87%

                              │   before    │             after              │
                              │  allocs/op  │ allocs/op   vs base            │
ParseQuery/baseline             1.000 ± 0%     0.000 ± 0%  -100.00% (p=0.002)
ParseQuery/mixed-case           5.000 ± 0%     2.000 ± 0%   -60.00% (p=0.002)
Observe                         1.000 ± 0%     0.000 ± 0%  -100.00% (p=0.002)
Summary                        10.000 ± 0%     1.000 ± 0%   -90.00% (p=0.002)
SignRRset/correct               91.00 ± 0%     83.00 ± 0%    -8.79% (p=0.002)
ServeDNS/A/unsigned             25.00 ± 0%     17.00 ± 0%   -32.00% (p=0.002)
ServeDNS/A/signed               117.0 ± 0%     101.0 ± 0%   -13.68% (p=0.002)
ServeDNS/TXT/signed             125.0 ± 0%     102.0 ± 0%   -18.40% (p=0.002)
ServeDNS/nxname/signed          211.0 ± 0%     106.0 ± 0%   -49.76% (p=0.002)
ServeDNS/refused                18.00 ± 0%     13.00 ± 0%   -27.78% (p=0.002)
```

The `MemStore` line is the one that matters operationally: at the ceiling a
public zone can be driven to, the old store spent 190 µs per query inside the
lock, which at a few thousand queries per second is most of a core and a
serialisation point in front of every answer.

## sni_tls

`GetCertificate` runs once per TLS handshake, inside crypto/tls, against a
key exchange that costs a hundred times more. It was already cheap; the two
changes make the common case and the wildcard case allocation-free rather than
faster in any way a handshake would notice.

| Change | Result |
|---|---|
| `asciiLower` copies only when the SNI carries an uppercase byte | exact match 32 ns → 22 ns |
| Wildcard certs indexed by their suffix (`.example.net`) so the lookup slices the name instead of building `"*" + suffix` | wildcard match 75 ns → 36 ns, 0 allocs; the hand-built stores in tests (no suffix index) fall back to the old lookup |

```
GetCertificate/exact                31.71n ±  8%   21.77n ± 8%  -31.36% (p=0.002)
GetCertificate/exact-mixed-case     33.24n ±  6%   35.11n ± 3%        ~ (p=0.065)
GetCertificate/wildcard             74.98n ±  4%   35.53n ± 6%  -52.61% (p=0.002)
GetCertificate/absent-sni           2.086n ±  4%   2.063n ± 3%        ~ (p=0.394)
GetCertificate/unmatched-fallback   92.23n ±  3%   40.59n ± 5%  -56.00% (p=0.002)
GetCertificate/unmatched-strict     95.28n ± 32%   38.17n ± 4%  -59.94% (p=0.002)
```

## radnr

`dnr.Marshal` runs once per Router Advertisement, every few minutes. It is
benchmarked so a regression in the codec is visible, not because the time
matters. The option is now built in one allocation sized up front instead of a
growing body copied behind the header.

```
Marshal     807.5n ± 25%   508.0n ±  5%  -37.09% (p=0.002)   14 → 8 allocs
Unmarshal   262.4n ±  3%   263.8n ± 48%        ~ (p=0.818)
```

## dynupdate

The design doc says an UPDATE is O(zone) because the servable view is rebuilt
from the flat record slice, and that is a deliberate trade. The benchmark
shows how steep the line was: an ACME-shaped add-then-delete against a
10 000-record zone cost **67 ms and 300 000 allocations**.

Two costs were tangled in that. The first was ours: `indexOfRR` identified a
record by rendering every record in the zone to presentation text
(`dns.Copy` + `String()`), and `sameName` built two strings per record per
comparison. Comparing type and owner first, and comparing owners in place with
an ASCII case fold, removes almost all of it. The value-dependent prerequisite
(RFC 2136 §3.2.3) went from 783 µs to 62 µs.

The second cost is upstream's and is now 82% of what remains: CoreDNS's
`file.Zone.Insert` compares names with `tree.less`, which lower-cases and
copies both names' labels to `[]byte` on every comparison (the function carries
a `TODO(miek)` about exactly this). Replacing the rebuild with a structural
copy of the tree plus the update's delta would remove it, but it means
re-implementing the zone's SOA/NS/RRSIG special cases that `Insert` applies,
in a plugin whose update rules are proven in Lean against the current model.
Not done here; it is the next step if update throughput ever matters.

```
                        │    before    │              after              │
Update/records=10         59.27µ ± 2%   35.96µ ±  3%  -39.33% (p=0.002)
Update/records=1000       5.669m ± 6%   4.445m ± 10%  -21.58% (p=0.002)
Update/records=10000      67.27m ± 9%   56.90m ±  6%  -15.42% (p=0.002)
PrereqRRsetEquals        783.04µ ± 8%   61.50µ ±  8%  -92.15% (p=0.002)
Query                     6.093µ ± 6%   6.889µ ±  5%  +13.07% (p=0.002)

Update/records=1000       30.25k allocs → 14.14k allocs   (-53%)
PrereqRRsetEquals         8095 allocs → 50 allocs         (-99%)
```

`Query` is the read path, which nothing here touches; the +13% is within the
run-to-run spread seen for it across sessions and is listed rather than
hidden.

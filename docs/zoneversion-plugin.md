# `zoneversion`: RFC 9660 ZONEVERSION as a CoreDNS plugin

Design record: what this plugin does, what it cannot do, and why. The Lean
proofs, the TLA+ model and the Go tests are derived from the requirements
below, which quote RFC 9660.

**Source.** Every quotation was checked against the RFC text fetched from
<https://www.rfc-editor.org/rfc/rfc9660.txt> on 2026-11-07. Claims about other
RFCs that were not re-read for this document are marked **UNVERIFIED**.

## The blocker (read this first)

With the miekg/dns v1.1.73 library that CoreDNS v1.14.x and v1.15.0 build
against, **no conformant ZONEVERSION query reaches any plugin.** RFC 9660 §3.1
has the client send the option empty (OPTION-LENGTH 0). miekg/dns unpacks
option 19 as `EDNS0_ZONEVERSION`, whose `unpack` returns `ErrBuf` for fewer
than two octets. The message therefore fails to unpack, and miekg's
`Server.serveDNS` answers FORMERR before CoreDNS's handler runs. The current
`master` of miekg/dns has the same `unpack` (checked 2026-11-07 via
`raw.githubusercontent.com/miekg/dns/master/edns.go`).

The miekg/dns client side has the opposite problem: `EDNS0_ZONEVERSION{}`
packs LABELCOUNT and TYPE even when they are zero, so a miekg/dns-based
client sends a two-octet option. RFC 9660 §3.2.1 makes that a FORMERR.

So, today:

| query | what answers | rcode |
|---|---|---|
| conformant (`dig +zoneversion`, length 0) | miekg/dns server, before any plugin | FORMERR |
| miekg/dns client (length 2) | this plugin, per §3.2.1 | FORMERR |
| no ZONEVERSION option | the zone, untouched | as usual |

`wire_test.go` pins all three: `TestMiekgRejectsEmptyOption` fails as soon as
a miekg/dns upgrade starts accepting the empty option, which is the signal to
revisit `optionLength` (it assumes an `EDNS0_ZONEVERSION` in a request had at
least two octets). `TestLoopbackServer` runs the table above through a real
`dns.Server` over loopback UDP.

The plugin is still correct for what it does receive, and becomes useful
end to end once miekg/dns accepts a zero-length option 19. That fix belongs in
miekg/dns, not in a plugin, and is not part of this change. Whether an
upstream issue already exists is **UNVERIFIED**.

## Wire format (RFC 9660 §2.1, §4)

OPTION-CODE **19**. In a query, OPTION-LENGTH is 0 and there is no data. In a
response, OPTION-DATA is:

| octets | field | here |
|---|---|---|
| 0 | LABELCOUNT | labels of the zone name, not counting the root |
| 1 | TYPE | 0, SOA-SERIAL, the only type RFC 9660 defines |
| 2 to 5 | VERSION | the zone's SOA SERIAL, 4 octets, network byte order |

OPTION-LENGTH is therefore always 6. The byte order is not spelled out in §4
("a copy of the unsigned 32-bit SERIAL field of the SOA RR"), but the §5
example fixes it: serial 2023073001 is shown as `78 95 a4 e9`, which is
big-endian. `TestRFC9660Example` and `ZoneVersion.rfc9660_example` reproduce
that example (`02 00 78 95 a4 e9`) byte for byte.

## Requirements

Every normative statement in RFC 9660 that a responder can act on, numbered.
"Implemented" means there is code for it and a test or proof that checks it
(see "What backs each rule").

| # | RFC 9660 | requirement | status |
|---|---|---|---|
| R1 | §2.1 | "OPTION-CODE for the ZONEVERSION option is 19." | implemented |
| R2 | §2.1 | "OPTION-LENGTH ... MUST have a value of 0 for queries" | enforced on receipt, through R12 |
| R3 | §2.1 | OPTION-LENGTH "MUST have the value of the length (in octets) of the OPTION-DATA for responses"; OPTION-DATA is LABELCOUNT, TYPE, VERSION (Figure 1) | implemented |
| R4 | §2.1 | "The value of the LABELCOUNT field MUST NOT count the null (root) label ... MUST be less than or equal to the number of labels in the original QNAME. The Root zone (".") has a LABELCOUNT field value of 0." | implemented; the root zone is **deliberately not supported** (below) |
| R5 | §2.2, §4.1 | presentation format MUSTs (mnemonic, decimal) | **not applicable**: a server emits wire format only |
| R6 | §3.1 | client: "SHOULD NOT send the ZONEVERSION option to non-authoritative name servers", "MUST NOT include more than one ZONEVERSION option" | **not applicable** (client side); the plugin's own SOA lookups carry no option at all |
| R7 | §3.2 | include the option when the server "(a) understands the ZONEVERSION option, (b) receives a query with the ZONEVERSION option, (c) is authoritative for one or more enclosing zones of the original QNAME, and (d) chooses to honor" the request; "Otherwise, a server MUST NOT include a ZONEVERSION option in the response." | implemented: (c) is "QNAME is in a zone listed for the plugin and the response is authoritative or a referral out of it"; (d) is "the serial could be determined soundly" (G1, G2) |
| R8 | §3.2 | "MAY include more than one ZONEVERSION option ... if it supports multiple TYPEs ... [or] if it is authoritative for more than one enclosing zone" | **not implemented, deliberately**: one option, for the deepest listed zone; RFC 9660 defines one TYPE |
| R9 | §3.2 | "MUST NOT include more than one ZONEVERSION option for a given TYPE and LABELCOUNT." | implemented: any ZONEVERSION option already on the response is removed before the plugin's own is added |
| R10 | §3.2 | downward referral: the option should be included (lower-case "should", in a Note) "even though the response's Authoritative Answer bit is not set. In this case, the ZONEVERSION data MUST correspond to the version of the referring zone." | implemented |
| R11 | §3.2 | NXDOMAIN and NODATA: include it (same Note, lower-case "should") | implemented |
| R11a | §3.2 | "Server failure (SERVFAIL) when the server is authoritative for the original QNAME" (same Note) | **not implemented, deliberately**: see below |
| R12 | §3.2.1 | "MUST return a FORMERR response when: The ZONEVERSION OPTION-LENGTH is not zero. More than one ZONEVERSION option is present." | implemented for QNAMEs in the listed zones; outside them the plugin passes the query on untouched (below) |
| R13 | §3.2.2 | "MUST NOT blindly copy the ZONEVERSION option from a query it receives into a subsequent query" | implemented: internal SOA lookups are fresh messages without EDNS |
| R14 | §3.2.2 | "A name server MUST NOT send a ZONEVERSION option back to a client that did not request it." | implemented: a query without the option goes to the next plugin untouched |
| R15 | §4 | where the SOA serial is not how the zone is versioned, "a name server SHOULD NOT include a ZONEVERSION option with type SOA-SERIAL" | operator's responsibility: list only zones whose content never changes without the serial changing (assumption A2) |
| R16 | §4 | "The EDNS(0) OPTION-LENGTH for this type MUST be set to "6" in responses." | implemented; proved |
| R17 | §4 | "The VERSION value for the SOA-SERIAL type MUST be a copy of the unsigned 32-bit SERIAL field of the SOA RR" | implemented; the serial is read from an SOA RR the zone served, never computed |
| R18 | §7 | the option is not covered by DNSSEC; TSIG, SIG(0) or an encrypted transport can protect it | informational: the plugin sits after `tsig`, so the option is on the response before TSIG signs it |

RFC 9660 says nothing specific about **DNAME** or **wildcard** answers
(verified: neither word appears in its text). Both are positive authoritative
answers from the QNAME's zone and get that zone's version, bracketed like any
other positive answer. A **CNAME or DNAME chain into another zone** gets the
version of the QNAME's zone: §2.1 says LABELCOUNT is what disambiguates "a
CNAME and a target name in another zone", and the SOA in the authority section
of such a response (the target zone's) is not used, because its owner is not
the QNAME's zone.

### Deliberate deviations

- **The root zone (R4).** Listing `.` would make every QNAME the server sees
  "in the zone", including answers `forward` or `cache` produced. The plugin
  refuses `.` at startup, whether named or inherited from a `.:53` server
  block. Name the zones this server is authoritative for.
- **SERVFAIL (R11a).** The Note's wording is lower-case "should", not BCP 14.
  A SERVFAIL rarely has AA set, so the plugin cannot tell a failure of its own
  zone from one produced elsewhere in the chain, and a zone that failed to
  answer is unlikely to answer the SOA lookup either. Omitting the option is
  always allowed (condition (d) of R7).
- **FORMERR scope (R12).** The plugin speaks for the zones it is configured
  with. A malformed option on a query for any other name is passed on: that
  answer is not this plugin's to give, and a recursive or forwarding block
  elsewhere in the same server should not start returning FORMERR because a
  plugin for one zone was added.
- **Other plugins' options (R14).** On the no-request path the plugin does
  not inspect the response at all (that path must cost nothing, D5). If some
  other plugin adds a ZONEVERSION option unasked, that plugin violates R14.
  On the request path, any foreign ZONEVERSION option is removed (R9).

## What the plugin guarantees

A negative answer (NXDOMAIN, NODATA) carries the zone's SOA, so the serial
comes from the same response, the same snapshot of the zone as the answer.

A positive answer and a referral carry no SOA. The serial has to be obtained
separately, by asking the rest of the chain for the apex SOA (an internal
query through `Next` into a capturing writer, never sent to the client), and
the zone may reload between the answer and that lookup. A single lookup after
the answer would attach the new serial to the old answer. TLA+
`ZoneVersionSerial_PostOnly` finds exactly that interleaving.

So a positive answer is **bracketed**:

```
before := cache[apex] if fresh, else lookup(apex)     (an observation before the answer)
answer := rest of the chain
after  := lookup(apex)                                (an observation after the answer)
attach after   if and only if   before == after
```

The plugin guarantees:

- **G1. During the query.** Any advertised serial is one the zone actually
  had at some instant between the query's arrival and its response: never
  invented, never assembled from two versions, never left over from before the
  query began. This holds unconditionally, rollbacks included. (TLA+
  `DuringQuery`, all five configs; the option is a 6-octet copy of one SOA RR,
  `ZoneVersion.decode_encode`.)
- **G2. The version that answered.** Any advertised serial is the serial of
  the zone version that produced the answer, under three assumptions:
  - **A1.** Between the before- and after-observations, the zone's serial
    never returns to a value it had left. True when serials only advance
    (RFC 1982 §3.1 additions; `file` only reloads a zone with a greater
    serial) and the total advance in that window is below 2^32
    (`ZoneVersion.bracket_sound`). A rollback breaks it
    (`ZoneVersionSerial_Rollback`), as does a serial lapping 2^32
    (`ZoneVersion.aba_possible`).
  - **A2.** The zone's content never changes without its serial changing.
    True of `file` with serial-based reloading and of `dynupdate` (it bumps
    the serial on every change). **Not true** of `file` reloading on file
    mtime without a serial change (CoreDNS v1.15.0 has a `ReloadByMtime`
    zone setting; the Corefile spelling of it is **UNVERIFIED**), nor of
    backends with no meaningful SOA. Such zones fall under R15: do not list
    them.
  - **A3.** The serving plugin answers each query from one snapshot of the
    zone, and the SOA lookup reads the same zone object the answer came from.
    True of `file` (its lookup takes the zone's read lock once).

When the bracket fails, the option is withheld, never guessed
(`coredns_zoneversion_requests_total{result="serial_changed"}`); the answer
itself is served unchanged. A lookup that does not return an authoritative
NOERROR answer with exactly one SOA serial for the apex also withholds the
option (`result="lookup_failed"`).

### The cache (D3)

The before-observation would cost a second lookup per query. The plugin keeps
a per-apex cache of the last observed serial (one entry per listed zone, so as
small as the Corefile) and uses it as the before-observation when it is at
most `maxEntryAge` (30 s) old. Every lookup, and every negative answer's SOA,
is an observation. The update rule, `update` in `cache.go`:

| cached entry | observed serial | result |
|---|---|---|
| none, or older than 30 s | s | store s |
| fresh, s | the same s | refresh its time |
| fresh, c | s with s > c in RFC 1982 order | store s (the zone advanced) |
| fresh, c | s not > c (smaller, or exactly 2^31 away) | keep c, untouched; count `serial_regressions_total` |

Lean proves the rule never stores a serial nobody observed and never moves a
fresh entry backwards in RFC 1982 order (`update_observed`,
`update_fresh_monotone`, reusing `Serial.lean`'s proof that `serialGreater`
is exactly RFC 1982 §3.2). The cached value is never advertised by itself:
only an after-lookup is, so G1 does not depend on the cache.

After a rollback the cache holds the higher serial until it goes stale, so
every bracket fails and the option is withheld for at most 30 s; then a fresh
lookup accepts the rolled-back serial. `maxEntryAge` is a constant, not a
directive: it trades one extra lookup per zone per 30 s against the window in
which A1 has to hold, and no value removes that window except not caching.

## Placement in the chain (D1)

`zoneversion` goes **immediately after `transfer:transfer`**, which in the
v1.14.6 `plugin.cfg` is after `cache` and `dnssec` and before every plugin that
serves a zone (`hosts`, `dynupdate`, `file`, `probe`, `auto`, `secondary`,
`sign`):

- before the zone backends, so it sees their responses and can ask them for
  the apex SOA through the rest of the chain;
- after `cache`: CoreDNS's cache strips OPT RRs before storing, and a cached
  answer came from some earlier zone version, so it is served without the
  option rather than with a serial looked up now;
- after `transfer`, so AXFR/IXFR never reach it (it also passes them on
  untouched itself);
- after `tsig`, so the option is added before TSIG signs the response.

Limitations of the slot:

- `hosts` sits after it. If `hosts` answers names inside a listed zone (AA
  set), those answers are versioned with the zone's serial although `hosts`
  produced them. Do not let `hosts` answer inside a listed zone.
- `rewrite` sits before it. RFC 9660 counts LABELCOUNT against the *original*
  QNAME; after a rewrite the plugin sees the rewritten name. A rewrite that
  moves a name across zones gives a LABELCOUNT for the wrong name.
- Plugins earlier in the chain that answer by themselves (`chaos`, `any`,
  `template`, `cache` hits) produce responses without the option.

## Configuration

```
zoneversion [ZONES...]
```

`ZONES` defaults to the server block's zones. The root zone is refused, as is
a block or a second `zoneversion` line in the same server block. There are no
other settings.

## Metrics

- `coredns_zoneversion_requests_total{result}`: ZONEVERSION requests for a
  listed zone, by `added`, `formerr`, `ineligible` (not an authoritative
  response or referral), `lookup_failed`, `serial_changed`.
- `coredns_zoneversion_serial_regressions_total`: observations not greater
  than the cached serial: a zone was rolled back (A1 at risk).

## Cost (D5)

A query without the option costs one branch and one walk over its EDNS
options: no allocation by the plugin (`TestAllocs`; the one allocation the
budget allows is CoreDNS's own `pluginWriter` in `plugin.NextOrFailure`). A
query with the option costs one extra internal SOA lookup (two when the cache
is cold) through the zone backend; `bench_test.go` measures both paths. The
option is a diagnostic one that almost no client sends.

## What backs each rule

| Rule | Go tests | TLA+ | Lean |
|---|---|---|---|
| R1, R3, R16: code 19, 6-octet LABELCOUNT/TYPE/serial | `TestEDNS0Wire`, `TestRFC9660Example` | | `encode_length`, `rfc9660_example` |
| R17: the serial is copied exactly, both directions | `TestProperty_VersionRoundTrip`, `FuzzDecode`, `FuzzNewVersion` | | `decode_encode`, `encode_decode`, `decode_serial_lt` |
| R4: LABELCOUNT ≤ QNAME labels, never root | `TestNewVersion`, `TestDecodeRejects`, `TestParse`, `FuzzNewVersion` | | `decode_root` |
| R2, R12: FORMERR for a non-empty or repeated option | `TestFormErr`, `TestClassify`, `TestProperty_Classify`, `FuzzServeDNS` | | `classify_version_iff`, `classify_two_malformed`, `classify_nonempty_malformed` |
| R14: no request, no option, no lookups | `TestNoRequestNoOption`, `FuzzServeDNS` | | `classify_none_iff` |
| R7, R10, R11: answer, NODATA, NXDOMAIN, referral, wildcard, CNAME out; never non-authoritative, SERVFAIL, REFUSED | `TestResponseCases` | | |
| R9: at most one option, foreign ones removed | `TestStrayOptionReplaced`, `FuzzServeDNS` | | |
| R13: lookups carry no option; the request is not modified | `TestRequestNotModified`, `TestNoRequestNoOption` | | |
| G1: advertised serial existed during the query | `TestSerialChangesAfterAnswer`, `FuzzServeDNS` | `ZoneVersionSerial` `DuringQuery` (all configs, rollback included); Apalache inductive proof `IndInvG1` (3 queries, 10 changes, rollbacks) | |
| G2: advertised serial is the answering version's | `TestSerialChangesAfterAnswer`, `TestNegativeAnswerUsesItsOwnSOA`, `FuzzServeDNS` | `AnswerConsistent` (`Bracket`, `NoCache` pass; `PostOnly`, `Rollback` violated, as expected); Apalache inductive proof `IndInv` (3 queries, 10 changes), refuted for `PostOnly` and `Rollback` | `bracket_sound`, `aba_possible` |
| D3: cache rule | `TestCacheObserve`, `TestCacheFreshness`, `TestProperty_CacheUpdate`, `TestCacheSavesALookup`, `TestRollback` | `CacheNotAhead` | `update_observed`, `update_fresh_monotone`, `update_regression_keeps`, `update_stale_replaces`, `update_advance` |
| D4: lookup failure withholds | `TestLookupFailure` | | |
| D5: no allocation on the no-option path | `TestAllocs` | | |
| the blocker | `TestMiekgRejectsEmptyOption`, `TestMiekgPacksEmptyStructAsTwoOctets`, `TestLoopbackServer` | | |

The same caveat as the rest of `verification/` applies: the TLA+ model is
written by hand from `handler.go` and `cache.go`, not extracted from them, and
models RFC 1982 order as `>` on naturals (exact while the zone has advanced by
less than 2^31 since the cached observation, which `ZoneVersion.lean` covers
separately). A result is a statement about the model.

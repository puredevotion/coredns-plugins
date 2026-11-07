# `resinfo`: DNS Resolver Information (RFC 9606) as a CoreDNS plugin

Design record: what this plugin does, what it deliberately does not do, and
which test or proof backs each rule. Every requirement below is quoted from
the RFC text, fetched from <https://www.rfc-editor.org/rfc/rfc9606.txt> (and
RFC 6763, RFC 9462 from the same place) on 2026-11-07. The IANA "DNS Resolver
Information Keys" registry was read from
<https://www.iana.org/assignments/dns-parameters/dns-parameters.xml> the same
day. The RFC 9606 errata page lists two reports, both rejected (8223, 8425);
neither changes a rule here (8223 asked to spell out the one-pair-per-string
rule this plugin already follows).

## Problem

RFC 9606 lets a resolver describe itself to clients with a RESINFO record
(RR type 261): whether it does QNAME minimisation, which Extended DNS Errors it
can return, where to read more. Clients that discovered an encrypted resolver
through DNR (RFC 9463, which `radnr` emits) or DDR (RFC 9462) ask for RESINFO
at the resolver's name before choosing it. CoreDNS has nothing that answers
RESINFO: as a resolver it would forward the query like any other name, which
§3 rules out ("RESINFO is a property of the resolver and is not subject to
recursive resolution"). miekg/dns (v1.1.73) knows the type (`dns.RESINFO`), so
only the server side is missing.

## Where the query arrives (RFC 9606 §3)

- "A DNS client can retrieve the resolver information using the RESINFO RR
  type and the QNAME of the domain name that is used to authenticate the DNS
  resolver (referred to as the Authentication Domain Name (ADN) in DNR
  [RFC9463])." The name a client asks for is the resolver's ADN: the name in
  its TLS certificate and in the DNR option, e.g. `resolver.example.net`.
- "If the Special-Use Domain Name "resolver.arpa", defined in [RFC9462], is
  used to discover an encrypted DNS resolver, the client can retrieve the
  resolver information using the RESINFO RR type and QNAME of
  "resolver.arpa"." So `resolver.arpa` is a second, optional name, for
  resolvers discovered through DDR by IP address.

The plugin therefore takes the names as arguments: the ADN(s), and
`resolver.arpa` if the operator runs DDR. It answers RESINFO at exactly those
names, not below them (`_dns.resolver.arpa` is DDR's SVCB name, not a RESINFO
name).

## Requirements

Status: **I** implemented, **N** deliberately not implemented (reason given),
**C** a client-side rule the server cannot implement (listed so the gap is
visible), **T** tightened here beyond the RFC.

| Id | Source | Requirement (quoted) | Status | Backed by |
|---|---|---|---|---|
| R1 | 9606 §3 | "If the resolver understands the RESINFO RR type, the RRset MUST have exactly one record." | I | Lean `answer_exactly_one`, `answer_shape`; `TestAnswersConfiguredName`, `TestProperty_AnswersExactlyConfigured`, `FuzzServeDNS` |
| R2 | 9606 §3 | "RESINFO is a property of the resolver and is not subject to recursive resolution." | I: answered by the plugin itself, never passed to `cache`/`forward`, whatever RD says | Lean `handle_answers_iff` (RD is not an input); `TestEDNSAndRD` |
| R3 | 9606 §3 | "The DNS client MUST discard the response if the AA flag in the response is set to 0" | I: AA is set on every answer | Lean `answer_shape`; `TestAnswersConfiguredName` |
| R4 | 9606 §3 | "The DNS client MUST set the Recursion Desired (RD) bit of the query to 0." | C. The server answers with RD 0 or 1 (refusing RD=1 would only break clients for no gain) | `TestEDNSAndRD` |
| R5 | 9606 §3 | "Invalid records MUST be silently ignored by DNS clients." | C. The server side of it: the plugin never publishes an invalid record, because the record is validated at startup and a Corefile that would produce one fails to load | `TestNewRejects`, `TestParseRejects`; Lean `encode_decode` |
| R6 | 9606 §3 | "If a group of resolvers is sharing the same ADN and/or anycast address, then these instances SHOULD expose a consistent RESINFO." | I: the RDATA is a function of the *set* of configured keys, not of their order in the Corefile, so equal configurations give byte-identical RDATA. Keeping the configurations equal is the operator's job | Lean `canonical_unique`, `new_order_independent`, `handle_names_as_set`; `TestParseOrderIndependent`, `TestProperty_NewDecodeRoundTrip` (shuffled input) |
| R7 | 9606 §4, RFC 1035 §3.3, §3.3.14, RFC 6763 §6.1 | TXT format: "one or more strings", each "a single length byte, followed by 0-255 bytes of text data"; "DNS-SD implementations MUST NOT emit empty TXT records" | I: at least one key; every string ≤ 255 octets; RDLENGTH ≤ 65535 | Lean `unpack_pack`, `pack_unpack`, `pack_bytes`, `valid_strings_short`, `encode_length`; `TestTotalRDATALimit`, `checkWire` in the property tests (miekg/dns packs exactly our octets) |
| R8 | 9606 §4, RFC 6763 §6.2 | "Using TXT records larger than 1300 bytes is NOT RECOMMENDED" | I: a warning at startup above 1300 octets; not an error, since the hard limit is R7's | `TestLargeRDATAWarnsButLoads` |
| R9 | 9606 §4, RFC 6763 §6.3 | "Each key/value pair is encoded as its own constituent string ... Everything up to the first '=' character is the key ... Everything after the first '=' ... (including subsequent '=' characters, if any) is the value" | I | Lean `split_render`, `split_render_eq_in_value`, `render_split`; `FuzzPair` |
| R10 | 9606 §4, RFC 6763 §6.4 | "The key MUST be at least one character." "The characters of a key MUST be printable US-ASCII values (0x20-0x7E), excluding '=' (0x3D)." | I, T: keys are restricted further to `a-z`, `0-9`, `-`. Every registered key fits; the subset has no case to fold ("Case is ignored when interpreting a key") and no spaces to get wrong | Lean `keyOk_no_eq`; `TestNewRejects` |
| R11 | RFC 6763 §6.4 | "The key SHOULD be no more than nine characters long." | N for `temp-` keys: a `temp-` key has four characters left under that limit, too few to be useful, and the 255-octet string limit (R7) is what actually bounds it. Every registered key is at most eight | — |
| R12 | RFC 6763 §6.4 | "A given key SHOULD NOT appear more than once in a TXT record." | I, T: a hard error, not a SHOULD; keys are kept strictly increasing, which rules repeats out | Lean `valid_nodup`; `TestNewRejects`, `TestParseRejects` |
| R13 | 9606 §4 | "Resolver information keys MUST either be defined in the IANA registry (Section 8.2) or begin with the substring "temp-" for names defined for local use only." | I: `qnamemin`, `exterr`, `infourl`, `deleg`, or `temp-` plus at least one more character | `TestNewRejects`, `TestParseRejects` |
| R14 | 9606 §5 `qnamemin` | "if there is no '=' in a key, then it is a boolean attribute, simply identified as being present, with no value." | I: `qnamemin` (and `deleg`) must have no `=` | `TestNewRejects` |
| R15 | 9606 §5 `exterr` | "the value of this key lists the possible EDE codes ... A value can be an individual EDE or a range of EDEs. Range values MUST be identified by "-". When multiple non-contiguous values are present, these values MUST be comma-separated." | I, T: one canonical spelling per set of codes: sorted, overlapping and adjacent runs merged, a run of one code written `N`, a longer one `LO-HI` (so `{15,16,17}` is `15-17`, RFC 9606 §6's example). The Corefile may list codes in any order or shape; the published value is canonical | Lean `ranges_unique`; `TestExtErr`, `TestProperty_ExtErrCanonical`, `FuzzParseExtErr` |
| R16 | 9606 §8.2 Table 1 `exterr` | "It must be an INFO-CODE decimal value in the "Extended DNS Error Codes" registry" | N: any 16-bit INFO-CODE (RFC 8914 §2) is accepted, including unassigned and private-use (49152-65535) codes. The registry grows; checking against a snapshot would reject new codes, and the lowercase "must" is registry text, not BCP 14 | `TestExtErr` (`65536` refused) |
| R17 | 9606 §5 `infourl` | "The DNS client MUST reject the URL as invalid if the scheme is not "https"." | I (server side): a non-https `infourl` is refused at startup, as is a URL with no host, with userinfo, with spaces or non-ASCII, or not in `net/url`'s canonical form | `TestNewRejects`, `TestParseRejects` |
| R18 | 9606 §5 `infourl` | "The resolver information server MUST support only the content-type "text/html" for the resolver information." | N: that is the web server at the URL, not this plugin | — |
| R19 | 9606 §7 | "DNS clients communicating with discovered DNS resolvers MUST use one of the following measures ... 1. Establish an authenticated secure connection to the DNS resolver. 2. Implement local DNSSEC validation" | C. Server side: the plugin does not sign RESINFO (N: a resolver is rarely authoritative for the zone of its own ADN, and `resolver.arpa` cannot be signed at all, "only the first one can apply to queries for "resolver.arpa""). **Serve it on the encrypted listeners** (`tls://`, `https://`, `quic://`) so measure 1 is available; a client following §7 ignores a RESINFO it got over plain UDP anyway | README, *Deploying* |
| R20 | 9606 §3, §6 (implied) | The answer is for QTYPE RESINFO at the configured name. RFC 9606 says nothing about other types at that name | I: every other type at the name, RESINFO at any other name, any class but IN, any opcode but QUERY, is **passed on unchanged**. The ADN is an ordinary name with A/AAAA records the resolver must still resolve; answering NODATA for them would break the very connection RESINFO describes | Lean `handle_answers_iff`, `only_type_261`, `only_class_IN`, `only_configured_names`; `TestPassesEverythingElseOn`, `TestProperty_AnswersExactlyConfigured`, `FuzzServeDNS` |
| R21 | RFC 9462 §6.4 | "DNS resolvers that support DDR by responding to queries for _dns.resolver.arpa. MUST treat resolver.arpa as a locally served zone per [RFC6303]. In practice, this means that resolvers SHOULD respond to queries of any type other than SVCB for _dns.resolver.arpa. with NODATA and queries of any type for any domain name under resolver.arpa with NODATA." | N: that is the DDR responder's zone, not this plugin's. With `resolver.arpa` listed here, RESINFO at the apex is answered and everything else at or under `resolver.arpa` is passed on to whatever serves the DDR zone (for example a `template` or `file` block for `resolver.arpa`). If nothing does, `forward` will send it upstream, which RFC 9462 §6.1 says a forwarder "SHOULD NOT" do; that is a gap in the DDR setup, not one this plugin can close without taking over the zone | README, *Corefile* |
| R22 | RFC 4343 §3 | Names compare equal under ASCII case folding only | I: the name match folds A-Z onto a-z and nothing else (the KELVIN SIGN does not match `k`), without allocating; the answer is owned by the query name exactly as sent, so 0x20 randomisation round-trips | Lean `eqFoldLoop_iff`, `handle_case_insensitive`; `TestEqualFoldASCII`, `TestAnswersConfiguredName` |
| R23 | RFC 6891 §7 | A response to a request with an OPT RR carries one | I: CoreDNS's `SizeAndDo`; a reply over the client's size is truncated (`Scrub`), not dropped | `TestEDNSAndRD`, `TestTruncatesOverUDP` |
| R24 | RFC 2181 §8 | TTLs are 0 to 2^31 - 1 | I: `ttl` outside that range is refused; default 3600 | `TestParseTTLBounds`, `TestParseRejects` |
| R25 | IANA registry, `deleg` | "The presence of the key indicates that the DELEG protocol is supported. (TEMPORARY - registered 2026-08-24, expires 2027-08-24)" | I as a boolean key. **UNVERIFIED**: the shape is taken from the registry's description; draft-ietf-deleg-11 itself was not read. CoreDNS does not implement DELEG, so publishing `deleg` would be a false claim today; it is accepted because it is registered | `TestNewAccepts` |

## Wire format and canonical form

The RDATA is a list of key/value pairs, held by `Info`, which can only be
built by `New` (from pairs in any order; it sorts them) or `Decode` /
`DecodeWire` (which accept only RDATA already in canonical form). Both run the
one `validate`:

- at least one pair (R7);
- keys strictly increasing in byte order, which also rules out repeats (R12)
  and makes the output a function of the set of pairs (R6);
- each key valid (R10, R13) and its value of the right shape (R14, R15, R17;
  `temp-` keys: no value, or printable US-ASCII);
- each rendered string at most 255 octets, the RDATA at most 65535 (R7).

Order is byte order, not the registry order of RFC 9606 §6's Figure 1, so
Figure 1's record is published as `exterr=15-17 infourl=... qnamemin`. RFC
9606 does not ask for any order; clients look keys up by name. Byte order is
the one rule that needs no table and covers `temp-` keys.

**miekg/dns stores TXT-like strings in presentation form.** Its packer reads
`\` as an escape (`\X` is `X`, `\DDD` a byte), and its unpacker writes `"` and
`\` back escaped. A raw value with a backslash put into `dns.RESINFO.Txt`
would lose it on the wire. The handler escapes `\` and `"` once, at startup
(`escapeTXT`); `TestBackslashAndQuoteReachTheWire` and the property tests'
`checkWire` compare miekg/dns's packed RDATA byte for byte with
`Info.AppendWire`.

## Server behaviour

| Request | Action |
|---|---|
| QUERY, one question, QTYPE RESINFO (261), QCLASS IN, name equal (ASCII case-insensitive) to a configured name | NOERROR, AA=1, one RESINFO record with the configured RDATA and TTL, owned by the query name as sent; OPT added if the request had one; truncated if over the client's size |
| anything else | passed on to the next plugin, untouched |

A request with no question never reaches a plugin (CoreDNS answers it with
SERVFAIL first, `core/dnsserver/server.go`); the handler still passes it on.

## Placement in the chain

`resinfo:` goes **immediately after `chaos:chaos`** (v1.14.6 `plugin.cfg`:
`… any chaos resinfo loadbalance tsig cookie cache rewrite rrl acl … forward …`):

- before `forward`, so a RESINFO query for the resolver's own name is never
  sent upstream (R2);
- before `cache`, so the answer is always the configured one;
- next to `chaos`, the other plugin that answers for the server itself.

Consequence: `cookie`, `rrl` and `acl` sit later and do not see RESINFO
queries, the same as for `chaos`. The answer is small and fixed, but it is an
answer to an unauthenticated UDP query; serving it on the encrypted listeners
only (R19) removes both the amplification question and the forgery one.

## What the formal model covers, and what it does not

`verification/lean/CorednsPlugins/Resinfo.lean` (core Lean 4, no Mathlib, no
`sorry`, only the standard axioms) models `AppendWire`/`unpackStrings`,
`Pair.String`/`splitPair`, `keyKind`'s syntax check, `validate`, `Decode`,
`CanonicalRanges`' output shape, `equalFoldASCII` and `answers`/`reply`. The
theorem names are in the table above. Abstracted, and checked by Go tests
instead: the per-key value rules (an arbitrary predicate in the model), the
decimal rendering of `exterr`, `net/url`'s canonical form, `escapeTXT`, and
CoreDNS's EDNS and truncation handling.

No TLA+ model: the plugin has no state that changes after startup, no
goroutine, no timer and no reload logic of its own (a Corefile reload builds a
new handler), so there is no interleaving to check.

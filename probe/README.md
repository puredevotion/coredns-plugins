# probe

## Name

*probe* - serves a synthetic, per-visitor DNS measurement zone that can be asked to answer wrong on purpose.

## Description

Every name below the configured zone is synthesized on demand from a random token in the query name. That uniqueness is the mechanism, not a detail: a name nobody has asked for before defeats every cache between a visitor and this server, so the visitor's resolver is forced to query us directly and we get to observe it.

What each query reveals is recorded against its token: the resolver's egress address (which is almost never the visitor's), the address family and transport (including whether it arrived encrypted, RFC 9539), whether EDNS and the DO bit are present, the advertised UDP buffer, DNS cookie support, EDNS Client Subnet disclosure, whether the resolver signals understanding of compact denial (`CO`) or extensible delegation (`DE`), whether it asked for the zone version (RFC 9660), which DNSSEC trust anchors it signalled (RFC 8145), and whether it randomizes label case (DNS-0x20). A separate web tier reads those observations back by token and reports "your resolver did X".

The zone can also be asked to answer **deliberately wrongly**, which is how a page establishes whether a resolver genuinely validates DNSSEC rather than merely setting the DO bit and hoping. Each failure mode is produced differently on purpose, because resolvers get different subsets of them right.

### EDNS header flags

Three bits in the OPT flags field are read. `miekg/dns` has an accessor only for `DO`, so `CO` and `DE` are masked by hand off the same field:

| Bit | Flag | Meaning | Status |
|---|---|---|---|
| 0 (`1<<15`) | `DO` | DNSSEC OK (RFC 4035) | assigned |
| 1 (`1<<14`) | `CO` | resolver understands compact denial (RFC 9824) | assigned |
| 2 (`1<<13`) | `DE` | resolver is DELEG-aware (`draft-ietf-deleg`) | **provisional** |

`CO` is worth pairing with the `_nxname` modifier below: this zone *serves* compact denial, so recording who *asked* for it says something neither half does alone.

`DE` is a temporary testing assignment. `draft-ietf-deleg-08` expects bit 2 but writes the permanent request as "Bit TBA2". If IANA lands it elsewhere this code keeps compiling and returns a plausible but wrong answer, so re-check the registry before trusting `deleg_aware`, and read a sudden collapse to all-false as a moved bit rather than a finding about resolvers.

### EDNS Client Subnet has three states, not two

RFC 7871 §7.1.2 lets a resolver send the option with `SOURCE PREFIX-LENGTH 0` to mean "deliberately disclosing nothing". That is the *opposite* finding from disclosing a prefix, and one boolean cannot express it:

| `ecs` | `ecs_src` | `ecs_prefix` | Meaning |
|---|---|---|---|
| `0` | `0` | absent | no option — the resolver said nothing |
| `1` | `0` | absent | option sent, disclosure **declined** — the good outcome |
| `1` | `>0` | present | resolver disclosed this many bits of the client |

The middle row must never be presented as a leak. `ecs_prefix` is deliberately left unset there rather than becoming a `/0`, which would render as "leaked everything".

`ecs_prefix` is the most identifying value this plugin stores — a truncated form of the visitor's own address. It exists because showing someone what leaked is the point of the measurement, it is reachable only through the random token the visitor holds, and it expires with the rest of the observation on the store's TTL. Do not add a second index over it.

### Opportunistic encryption from resolvers (RFC 9539)

RFC 9539 has recursive resolvers simply **try** encrypted transport to authoritative servers — no signalling, no negotiation, no coordination with the zone operator. A resolver opens DoT on port 853; if it works the query is private from a passive observer, and if not it falls back to cleartext.

That design makes adoption almost unmeasured, because the only party who can see an attempt is the authoritative being probed — and few authoritatives both accept encrypted transport and publish what reaches them.

`encrypted` and the `tls` block record it. Note two fields whose **emptiness is meaningful**, not a defect:

- **No SNI** is the expected case (RFC 9539 §4.2). An opportunistic prober has no name to authenticate. A resolver that *does* send SNI is doing something more deliberate.
- **`did_resume`** means the resolver kept session state from a previous encrypted conversation — under an opportunistic model, that is the signal it is persisting success rather than re-probing each time.

The negotiated key-exchange group is recorded because a DoT handshake is where oversized post-quantum certificates hurt first.

**This fixed a real gap rather than adding a feature.** Transport used to be derived from CoreDNS's `request.Proto()`, which distinguishes only UDP from TCP by inspecting the remote address type and cannot see TLS at all. So `tls` and `quic` existed as transport values and were never once produced, while `Transport`'s own documentation claimed a DoT-to-Do53 fallback would be visible in the change. It would not have been — every encrypted query was recorded as plain TCP. Detection now goes through `dns.ConnectionStater`, walking CoreDNS's writer wrappers, since the TLS state is not on the outermost one.

Serving DoT is a deployment matter, not a plugin one: the zone needs a `tls://` server block and a certificate. Until then this records that every query arrived in cleartext, which is true.

### Per-visitor service discovery (RFC 6763)

A DNS-SD browse tree is served **under the token**, not at the usual fixed names:

```
_services._dns-sd._udp.<token>.<zone>   browse: which service types exist
_probe._tcp.<token>.<zone>              enumerate instances of that type
probe._probe._tcp.<token>.<zone>        the instance: SRV + TXT
```

That placement is the whole reason it is measurable. DNS-SD normally lives at `_services._dns-sd._udp.<zone>` — a **fixed, cacheable** name, so the first visitor's query would populate every cache between here and the internet and no later visitor would ever be observed. It would look implemented and measure nothing.

What it measures is whether a client actually follows the chain, and how. The three levels arrive as separate queries for distinguishable names, so the observation sequence shows which levels were reached. The enumerate step returns SRV and TXT in the **additional** section (RFC 6763 §12), so a conforming client finishes in two round trips and one that ignores additional records asks again — and that difference is visible.

Underscore service labels are RFC 8552 attrleaf names, so this doubles as a check that a resolver transports them intact — the same mangling the ECH canary looks for, one layer up.

Wrong type at a valid level is **NODATA**, not NXDOMAIN: a client asking `SRV` at the enumerate level made a type mistake, it did not visit a name that is absent. Nothing listens on the advertised SRV port — worth stating, because an SRV record is a promise a naive client will try to keep.

### Service binding and ECH (RFC 9460 + RFC 9848)

`HTTPS` (TYPE65) and `SVCB` (TYPE64) are answered at probe names, carrying an `ech=` parameter.

The measurement is **transport integrity**, not encryption. SVCB/HTTPS is uncommon enough that resolvers and middleboxes are known to strip, truncate or refuse parameters they do not understand — and `ech=` is the one most likely to be interfered with *deliberately*, because stripping it is exactly how an operator forces SNI back into the clear. Comparing the bytes that arrive against the bytes served attributes any difference to the path.

**The published config is a canary, not a capability.** Nothing holds the private half of the key, on purpose: publishing a usable ECH config from a zone that serves no TLS would invite clients to attempt real ECH against names that cannot complete it. Do not read "this zone publishes an ECH config" as an ECH deployment.

It is derived from the zone name via SHA-256 rather than generated or configured, which makes it stable across restarts and identical on every replica — both required, since the whole measurement is a byte comparison. It is distinct per zone as a side effect.

The `ECHConfigList` encoding is hand-built (Go consumes these but exposes no encoder), so every length prefix is load-bearing. It is validated by feeding it to `crypto/tls` — the real consumer — and asserting a ClientHello is actually constructed and written, which is the step that parses the list and encrypts with it. A test that merely fails the handshake proves nothing, because the write can fail before ECH is touched.

With no canary configured the zone answers NODATA rather than an `HTTPS` record with no `ech=` in it: a record the measurement cannot use is worse than no record.

### Trust anchor knowledge (RFC 8145)

RFC 8145 lets a validating resolver tell a server which DNSSEC keys it would validate that server's answers with — the mechanism that measured the root KSK rollover, and one essentially only root operators have ever run the receiving side of.

It defines two mechanisms, and **they are not equally useful here**:

| Mechanism | Applies to | Expect |
|---|---|---|
| **EDNS option 14** (`edns-key-tag`) | any query | real data — this is the useful half |
| **Key Tag queries** (`_ta-<hex>…`) | the apex of a resolver's *configured* trust anchors | ~nothing |

Key Tag queries are sent only to zones a resolver has been configured to trust directly (RFC 8145 §5.1). This zone chains from root through a DS, so it is nobody's configured anchor. It is handled anyway because the case where one *does* arrive means somebody pinned this zone as a trust anchor — exactly the kind of thing a measurement zone should notice rather than answer `REFUSED` to.

Key tags are **hexadecimal, zero-padded to four digits, sorted smallest to largest**: `_ta-0635-7aae-aa1b`. Decimal is the natural wrong guess and would parse many names into confidently wrong numbers.

Two deliberate refusals to be helpful:

- An **unpadded** tag (`_ta-635`) is rejected rather than read as `0x0635`. Normalising it away would hide a real implementation bug, which is the opposite of the point.
- Arrival **order is preserved** and sortedness reported separately, rather than sorted on the way in. A sender that violates §5.2's ordering requirement is a finding.

A Key Tag query is answered `NODATA` — NOERROR with the SOA in authority — because RFC 8145 §5.3 makes the response whatever the zone content implies, and this synthesized zone has no `_ta-*` records. Not `NXDOMAIN`, and definitely not `REFUSED`.

`knows_zone_key` is only meaningful alongside a non-empty `key_tags`: a resolver that signalled nothing has **not** told us it lacks our key.

### Zone version (RFC 9660)

A client that sends an **empty** `ZONEVERSION` option is asking which version of the zone answered; the reply carries the version alongside the data, so a diagnosis cannot be confused by the zone changing between the answer and a follow-up `SOA` query.

Both directions are useful here. The option is answered when asked (SOA-SERIAL, version type 0 — the only type RFC 9660 defines), and `zoneversion_asked` records whether the resolver asked at all. Almost nothing does, which is what makes it worth counting: it is a direct measure of how much diagnostic protocol a resolver actually implements.

The option is **only** sent in response to a request. Sending it unsolicited would add bytes to every answer from a zone whose purpose includes measuring response size.

One implementation note, because it is a trap rather than a detail: the response is built from *our* zone, never echoed from the client's option. A querier may send a populated `ZONEVERSION`; echoing it would let them choose what we appear to assert about our own zone version, which any downstream diagnosis would then believe.

### DNS Error Reporting (RFC 9567) — both halves

RFC 9567 lets an authoritative server invite resolvers to report resolution failures back to it. The authoritative side advertises an **agent domain** in an unsolicited EDNS0 Report-Channel option (code 18); a validating resolver that then hits a reportable failure encodes it into a QNAME and sends a TXT query to that agent domain:

```
_er.<QTYPE>.<failing name>.<EDE code>._er.<agent domain>
```

Almost nobody runs the receiving side. Unbound is the resolver that generates these; BIND and Knot have the authoritative advertisement. `agent_domain` turns this plugin into both — advertiser and monitoring agent — in one process, and that is not an economy but the point:

**This zone manufactures, on purpose, exactly the failures RFC 9567 exists to report.** `_badsig`, `_expiredsig`, `_futuresig` and `_unsigned` each provoke a specific validation failure, and each is labelled with the extended error code we know to be true (see the EDE section above). When a report comes back, the code the resolver *concluded* can be compared against the code we *caused*. Agreement means it diagnosed correctly; disagreement is the finding, and silence is a third reading.

And because the failing name contains the visitor's token, a report is attributable to the page that provoked it — `_badsig.a1b2c3d4.check.example.com` recovers `a1b2c3d4`. A public agent domain normally receives anonymous reports about names it knows nothing about.

Four constraints, all of them load-bearing:

- **The agent domain must not be inside the zone it reports on.** RFC 9567 §6.3 requires this, and the reason is a deadlock: if resolving the agent domain first requires resolving the zone that is failing, the report can never be delivered — and the failures here are manufactured, so the deadlock would be guaranteed rather than hypothetical. Setup refuses the configuration. It also refuses the reverse nesting, on this plugin's own account: with the probe zone underneath the agent domain, a probe name and a report name would be indistinguishable and the more permissive parser would win silently.
- **The agent zone is never signed**, even when the probe zone has a signer. RFC 9567 §7 recommends against signing an agent domain because it costs the reporting resolver a validation; here it is sharper than that. This zone exists to receive reports about broken signatures. Signing it with the same key means a resolver that cannot validate our signatures also cannot deliver the report saying so — the failure would silence its own report.
- **NXDOMAIN is never returned** from the agent domain. RFC 9567 §6.2 forbids it for monitored domains, because the negative cache entry suppresses subsequent reports. Every name under the agent domain answers NOERROR: a TXT for a well-formed report, NODATA for anything else.
- **A report QNAME is attacker-chosen input**, unlike everything else this plugin parses. The label count and the two numeric labels are bounded before any per-label work; the reported name is stored as a string and never resolved, never re-queried, never used to build a name we look up.

Reports land in the store beside observations, under `probe:reports:<token>`, or `probe:reports:unattributed` when the reported name carried no token of ours. Unattributed reports are kept rather than dropped — a report about the zone apex is legitimate and interesting — and that list has its own, larger ceiling, because it is a single list shared with every reporter on the internet and is precisely what a flood would target.

Reports are **asynchronous and lossy**. A resolver reports after it gives up, and caches the report query for a TTL before repeating it. A report can therefore arrive long after the visitor closed the page, which is why reports are stored independently of observations and survive a token whose observations have already expired. The corollary matters more: *absence of a report is not evidence that nothing failed*, and must never be rendered as one.

## Syntax

```
probe ZONE {
    key           BASENAME
    ttl           SECONDS
    ns            NAME
    mbox          NAME
    validity      DURATION
    store_ttl     DURATION
    max_tokens    N
    max_per_token N
    big_size      BYTES
    valkey        ADDR [ADDR...]
    valkey_ca     FILE
    valkey_timeout DURATION
    agent_domain  NAME
    agent_ttl     SECONDS
}
```

* **ZONE** is the origin served. Required.
* `key` **BASENAME** loads a DNSSEC keypair from `BASENAME.key` and `BASENAME.private` — the same BIND file layout CoreDNS's own `sign` and `dnssec` plugins use, so key material for this zone is generated, rotated and inspected with the same tooling and habits as any other signed zone. Startup fails if the key's owner name is not **ZONE**, because that misconfiguration otherwise presents as "everything is bogus" with nothing logged. Without `key` the zone is unsigned and the four signature modifiers become no-ops; setup warns rather than failing, since an unsigned zone is still useful while keys are being generated.
* `ttl` is the TTL on every synthesized record, default **10**. Deliberately tiny: an answer describes one visitor at one moment, so a cached answer is a wrong answer for the next one.
* `ns` and `mbox` set the apex NS name and SOA mailbox, defaulting to `ns.ZONE` and `hostmaster.ZONE`.
* `validity` is how long a correct signature stays valid, default **1h**. Short is preferable — signatures are minted per query, nothing caches them for long, and a narrow window bounds the damage if the key leaks.
* `store_ttl` bounds how long a token stays readable, default **10m**. This is transient diagnostic state about someone's network, not history to keep.
* `max_tokens` (default **10000**) and `max_per_token` (default **64**) bound memory. A public zone invites walking the token space purely to grow the store.
* `valkey` **ADDR...** switches the observation store from in-process to Valkey, which is what the separate web tier reads and what more than one replica requires. Data model: `probe:seen:<token>` is a counter and `probe:obs:<token>` a capped list of JSON observations — separate keys on purpose, so the count stays truthful past the detail cap ("we saw this 200 times" is itself the finding). `valkey_ca` is **required** and there is deliberately no bypass: the fleet's Valkey has no authentication of its own, so the server certificate is the only thing distinguishing it from anything else answering on that address, and what crosses the link is observations about other people's networks. An escape hatch would only ever be used to paper over a wrong CA path. `valkey_timeout` (default **100ms**) bounds how long a store round-trip may delay a DNS answer; exceeding it degrades the measurement rather than failing the query. Connecting fails at startup rather than silently falling back to the in-process store, because a zone that answers perfectly while recording nothing nobody can read is the worst outcome.
* `agent_domain` **NAME** enables RFC 9567 DNS Error Reporting: the Report-Channel option is advertised on every response from **ZONE**, and **NAME** becomes a second zone this plugin serves as the monitoring agent. Unset by default, and unset means *both* halves are off — advertising a channel nobody answers is worse than advertising none, because it sends every reporting resolver into a lookup that cannot succeed. **NAME** must share no ancestry with **ZONE** in either direction; setup refuses otherwise, for the reasons above. The server block has to list both zones (`check.example.com er.example.com { … }`) or CoreDNS never routes the report queries here.
* `agent_ttl` is the TTL on agent-zone answers, default **300**, and through the SOA MINIMUM it also governs negative caching there. Deliberately not `ttl`: that one is tiny because a probe answer describes one moment, whereas this one is a rate limit on *inbound* reports. RFC 9567 §6.2 calls that caching essential — it is what holds a reporting resolver to one report query per TTL for the same problem — so a short value converts one persistently broken resolver into a stream of reports about the same failure. Zero is rejected rather than treated as "no caching".
* `big_size` is the payload the `_big` modifier aims for, default **1400**, capped at 4096. The default is above the DNS-flag-day-2020 EDNS cap of 1232 — so the answer demonstrably exceeds what a resolver should advertise room for — but below the ~1500-byte Ethernet MTU, so it actually arrives. Measured on a 1500-byte-MTU path: ~1419 bytes is delivered over UDP, anything past ~1540 silently vanishes, while the same 3125-byte answer arrives intact over TCP. Larger values are a legitimate experiment (they test path-MTU behaviour and fragment filtering, a real failure mode) but a poor default, because the demonstration then presents as "the server is broken" rather than "look how large this answer is".

## Query grammar

Relative to the zone:

```
[_modifier[._modifier...].]<token>
```

The token is the label closest to the zone, because it is the stable per-visitor identity — everything to its left modifies this one query. Tokens are 8–32 hex characters. Modifiers are underscore-prefixed, following the RFC 8552 *attrleaf* convention for labels that are not hostnames, so a modifier can never collide with a real name.

Modifiers are order-insensitive, may each appear once, and cannot conflict. Anything that does not parse is answered **REFUSED** rather than guessed at: a probe zone that silently reinterprets a malformed request produces measurements nobody can trust, and REFUSED also keeps "not a valid probe request" distinguishable from "this name does not exist".

| Modifier | Effect | What it tests |
|---|---|---|
| `_unsigned` | no RRSIG at all | the resolver's "this zone is signed, where is the signature?" check — depends on it having the DS/DNSKEY chain, not on crypto |
| `_badsig` | RRSIG present, signature corrupted | signature *verification*. The signature is computed correctly and then corrupted, so it stays valid base64 of the same length and fails verification rather than failing to parse |
| `_expiredsig` | cryptographically valid, window closed | timestamp enforcement |
| `_futuresig` | cryptographically valid, window not yet open | timestamp enforcement, the direction implementations more often forget |
| `_truncate` | TC=1, empty answer | TCP fallback. Also exactly the shape response rate limiting uses when it *slips* a response |
| `_nxdomain` | literal NXDOMAIN, signed SOA only | negative-answer handling with a **deliberately unprovable** proof — traditional non-existence needs an NSEC chain a synthesized zone cannot have, so a strict validator should judge this bogus. Finding out which resolvers do is the experiment |
| `_nxname` | compact denial of existence, RFC 9824 | the provable counterpart. NOERROR with an NSEC whose bitmap carries the `NXNAME` meta-type (128); a resolver that understands it synthesizes NXDOMAIN for its own client, one that does not sees an ordinary NODATA. Comparing this against `_nxdomain` is the point of having both |
| `_servfail` | SERVFAIL | the failure most often confused with a validation failure |
| `_big` | oversized answer | amplification. Delivered only to a client that advertised room for it; a small-buffer client gets TC=1 and must return over TCP |

The four signature modifiers are mutually exclusive (there is one signature to spoil); `_nxdomain`, `_nxname` and `_servfail` are mutually exclusive (one rcode). Modifiers from different groups compose.

A query with `QTYPE=NXNAME` is answered **FORMERR**, per RFC 9824 §3.4 — NXNAME is a meta-type that exists only inside an NSEC bitmap, so NODATA would wrongly imply it is a real type this zone happens to have none of.

## Answered types

| Type | Answer |
|---|---|
| `A` | the resolver's own IPv4 address, or NODATA if it reached us over IPv6 |
| `AAAA` | the resolver's own IPv6 address, or NODATA if it reached us over IPv4 |
| `TXT` | the observation as a flat `key=value` readout, so a bare `dig` gets the same result as the web page with no correlation store involved |
| `PTR`, `SRV`, `TXT` | inside the per-visitor DNS-SD browse tree (RFC 6763) |
| `HTTPS`, `SVCB` | a service binding carrying the `ech=` transport canary (RFC 9460/9848) |
| `SOA`, `NS`, `DNSKEY` | at the apex only |

Apex signatures are **never** spoiled, whatever a query asks for: a broken SOA or DNSKEY signature would make the whole zone bogus and every per-query variant beneath it unmeasurable.

Under `agent_domain`, when configured, the table is much shorter and nothing is signed:

| Type | Answer |
|---|---|
| `TXT` on a well-formed report name | `"report received"`, and the report is recorded |
| anything else | NODATA with the agent zone's SOA — never NXDOMAIN, per RFC 9567 §6.2 |
| `SOA`, `NS` | at the agent apex only. No TXT there, so a resolver that truncated a report name down to the apex gets a visible NODATA instead of a success hiding the truncation |

## Examples

```
check.example.com er.example.com {
    probe check.example.com {
        key /etc/coredns/keys/Kcheck.example.com.+013+12345
        ttl 10
        ns  ns.example.com

        # RFC 9567. Both zones are listed on the server block above, or the
        # report queries never reach this plugin.
        agent_domain er.example.com
    }
    rrl check.example.com er.example.com {
        responses-per-second 20
        slip-ratio 2
    }
    # Not optional alongside rrl: this is what lets rrl account every
    # synthesized name against the zone apex instead of giving each random
    # token its own bucket. Without it the limits above never trigger.
    metadata
    prometheus
    errors
}
```

```console
$ dig +short TXT a1b2c3d4.check.example.com
"resolver=192.0.2.53 prefix=192.0.2.0/24 proto=udp ipv6=0 edns=1 do=1 bufsize=1232 cookie=1 ecs=0 ecs_src=0 co=1 deleg=0 zoneversion=0 encrypted=0 case0x20=1 seen=1"

$ dig +dnssec TXT _badsig.a1b2c3d4.check.example.com   # a validating resolver should SERVFAIL
```

End-to-end for the reporting channel, with Unbound as the reference implementation of the half we do not write:

```console
$ dig +dnssec TXT a1b2c3d4.check.example.com | grep -i report
; REPORT-CHANNEL: er.example.com.

$ # what a reporting resolver sends after _badsig fails validation (EDE 6):
$ dig TXT _er.16.\_badsig.a1b2c3d4.check.example.com.6._er.er.example.com
;; ANSWER SECTION:
… IN TXT "report received"
```

## Safety

This zone answers the public internet, synthesizes signed responses, and has a modifier whose entire purpose is to emit a large answer.

* It **must** sit behind response rate limiting — see [`docs/rrl-plugin.md`](../docs/rrl-plugin.md). Note that `rrl` occupies an earlier chain slot than this plugin, so it does cover these answers.
* **`metadata` must be enabled in the same server block, or the rate limiting above is decorative.** `rrl` buckets a response by the full QNAME unless a provider publishes `zone/wildcard`; every name here is synthesized from a caller-supplied random token, so without it each query gets a bucket to itself and no limit is ever reached. This plugin implements the provider (`metadata.go`) and publishes the wildcard parent for whichever of its two zones matched — but a provider nothing collects is inert, so the `metadata` directive has to be present too. This is `rrl`'s documented wildcard-flooding evasion, except that here an attacker does not need to discover a wildcard: varying the token is the zone's normal grammar.
* It must **never** share a server block with a forwarder or a cache. An open resolver is a categorically worse reflector than an authoritative server, and `cache` sits *ahead* of the rate-limiting slot, so cached answers would bypass it.
* Observations are transient by construction: bounded count, bounded per token, expiry keyed on first-seen so a token cannot be kept alive by continuing to query it.
* The agent domain is the one surface here that parses a name a stranger composed, so it is the one with real security surface. Bounds are in `ParseReport` (label count, numeric-label length) and in the store (per-token cap, separate ceiling on the unattributed list). Report queries are also *queries*: put the agent domain inside the `rrl` zone list, and when moving `rrl` from `report-only` to enforcing, check the report path against the observed baseline separately — reports arrive at a fraction of a probe zone's rate, so an allowance tuned on probe traffic can be wrong for them in either direction.

## Known limitations

* **`_nxdomain` is unprovable by design, not by omission.** Denial uses a signed SOA plus an NSEC asserting the queried name, with the "black lies" next-name trick (`\000.<qname>`) — which also makes the zone unwalkable, a requirement rather than a bonus for a zone of unbounded synthetic names. That proves NODATA correctly, but a literal NXDOMAIN needs an NSEC chain a synthesized zone cannot have. `_nxname` is the provable form (RFC 9824); `_nxdomain` is kept as the legacy shape precisely so the two can be compared.
* **DoT and DoH are not distinguished from TCP.** CoreDNS reports the transport as `udp` or `tcp`, and the encrypted transports are TCP underneath. Recording them separately needs the listener to pass that down.
* **The default in-process store is single-replica.** A visitor's queries and their report request must reach the same process. Configure `valkey` for anything the separate web tier reads, or for more than one replica.
* Signing is online, per query. That is the only option for synthesized names, but it means the private key is live in the serving process rather than used offline. Key files are opened through `os.Root`, so a symlink in the key directory cannot redirect the read outside it.

## Independence

The label grammar and every behaviour above were designed for this plugin rather than adapted from another implementation of the idea, so this package carries no licence obligations beyond the repository's own MIT.

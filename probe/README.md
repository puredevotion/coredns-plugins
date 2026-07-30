# probe

## Name

*probe* - serves a synthetic, per-visitor DNS measurement zone that can be asked to answer wrong on purpose.

## Description

Every name below the configured zone is synthesized on demand from a random token in the query name. That uniqueness is the mechanism, not a detail: a name nobody has asked for before defeats every cache between a visitor and this server, so the visitor's resolver is forced to query us directly and we get to observe it.

What each query reveals is recorded against its token: the resolver's egress address (which is almost never the visitor's), the address family and transport, whether EDNS and the DO bit are present, the advertised UDP buffer, DNS cookie and ECS support, and whether the resolver randomizes label case (DNS-0x20). A separate web tier reads those observations back by token and reports "your resolver did X".

The zone can also be asked to answer **deliberately wrongly**, which is how a page establishes whether a resolver genuinely validates DNSSEC rather than merely setting the DO bit and hoping. Each failure mode is produced differently on purpose, because resolvers get different subsets of them right.

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
    valkey_insecure_tls
    valkey_timeout DURATION
}
```

* **ZONE** is the origin served. Required.
* `key` **BASENAME** loads a DNSSEC keypair from `BASENAME.key` and `BASENAME.private` — the same BIND file layout CoreDNS's own `sign` and `dnssec` plugins use, so key material for this zone is generated, rotated and inspected with the same tooling and habits as any other signed zone. Startup fails if the key's owner name is not **ZONE**, because that misconfiguration otherwise presents as "everything is bogus" with nothing logged. Without `key` the zone is unsigned and the four signature modifiers become no-ops; setup warns rather than failing, since an unsigned zone is still useful while keys are being generated.
* `ttl` is the TTL on every synthesized record, default **10**. Deliberately tiny: an answer describes one visitor at one moment, so a cached answer is a wrong answer for the next one.
* `ns` and `mbox` set the apex NS name and SOA mailbox, defaulting to `ns.ZONE` and `hostmaster.ZONE`.
* `validity` is how long a correct signature stays valid, default **1h**. Short is preferable — signatures are minted per query, nothing caches them for long, and a narrow window bounds the damage if the key leaks.
* `store_ttl` bounds how long a token stays readable, default **10m**. This is transient diagnostic state about someone's network, not history to keep.
* `max_tokens` (default **10000**) and `max_per_token` (default **64**) bound memory. A public zone invites walking the token space purely to grow the store.
* `valkey` **ADDR...** switches the observation store from in-process to Valkey, which is what the separate web tier reads and what more than one replica requires. Data model: `probe:seen:<token>` is a counter and `probe:obs:<token>` a capped list of JSON observations — separate keys on purpose, so the count stays truthful past the detail cap ("we saw this 200 times" is itself the finding). Setup **refuses plaintext**: pass `valkey_ca` to verify the server certificate, or `valkey_insecure_tls` to opt out explicitly. That is deliberate — the fleet's Valkey has no authentication at all, so transport security is the only thing protecting these observations, and it should not be absent by accident. `valkey_timeout` (default **100ms**) bounds how long a store round-trip may delay a DNS answer; exceeding it degrades the measurement rather than failing the query. Connecting fails at startup rather than silently falling back to the in-process store, because a zone that answers perfectly while recording nothing nobody can read is the worst outcome.
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
| `SOA`, `NS`, `DNSKEY` | at the apex only |

Apex signatures are **never** spoiled, whatever a query asks for: a broken SOA or DNSKEY signature would make the whole zone bogus and every per-query variant beneath it unmeasurable.

## Examples

```
check.example.com {
    probe check.example.com {
        key /etc/coredns/keys/Kcheck.example.com.+013+12345
        ttl 10
        ns  ns.example.com
    }
    rrl check.example.com {
        responses-per-second 20
        slip-ratio 2
    }
    prometheus
    errors
}
```

```console
$ dig +short TXT a1b2c3d4.check.example.com
"resolver=192.0.2.53 prefix=192.0.2.0/24 proto=udp ipv6=0 edns=1 do=1 bufsize=1232 cookie=1 ecs=0 case0x20=1 seen=1"

$ dig +dnssec TXT _badsig.a1b2c3d4.check.example.com   # a validating resolver should SERVFAIL
```

## Safety

This zone answers the public internet, synthesizes signed responses, and has a modifier whose entire purpose is to emit a large answer.

* It **must** sit behind response rate limiting — see [`docs/rrl-plugin.md`](../docs/rrl-plugin.md). Note that `rrl` occupies an earlier chain slot than this plugin, so it does cover these answers.
* It must **never** share a server block with a forwarder or a cache. An open resolver is a categorically worse reflector than an authoritative server, and `cache` sits *ahead* of the rate-limiting slot, so cached answers would bypass it.
* Observations are transient by construction: bounded count, bounded per token, expiry keyed on first-seen so a token cannot be kept alive by continuing to query it.

## Known limitations

* **`_nxdomain` is unprovable by design, not by omission.** Denial uses a signed SOA plus an NSEC asserting the queried name, with the "black lies" next-name trick (`\000.<qname>`) — which also makes the zone unwalkable, a requirement rather than a bonus for a zone of unbounded synthetic names. That proves NODATA correctly, but a literal NXDOMAIN needs an NSEC chain a synthesized zone cannot have. `_nxname` is the provable form (RFC 9824); `_nxdomain` is kept as the legacy shape precisely so the two can be compared.
* **DoT and DoH are not distinguished from TCP.** CoreDNS reports the transport as `udp` or `tcp`, and the encrypted transports are TCP underneath. Recording them separately needs the listener to pass that down.
* **The default in-process store is single-replica.** A visitor's queries and their report request must reach the same process. Configure `valkey` for anything the separate web tier reads, or for more than one replica.
* Signing is online, per query. That is the only option for synthesized names, but it means the private key is live in the serving process rather than used offline.

## Independence

The label grammar and every behaviour above were designed for this plugin rather than adapted from another implementation of the idea, so this package carries no licence obligations beyond the repository's own MIT.

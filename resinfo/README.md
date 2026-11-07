# resinfo

## Name

*resinfo* - publishes the resolver's capabilities as an RFC 9606 RESINFO record.

## Description

A client that found an encrypted resolver through DNR (RFC 9463) or DDR (RFC 9462) can ask it, before choosing it, what it does: a RESINFO query (RR type 261) for the resolver's own name. The answer is a list of `key` or `key=value` strings, the same format as TXT: `qnamemin` (QNAME minimisation is on), `exterr=15-17` (the Extended DNS Errors it can return), `infourl=https://...` (a page for IT staff).

*resinfo* answers those queries. It answers RESINFO, class IN, at the configured names and nothing else; every other query, including other types at those names, goes to the next plugin unchanged. Answers have AA set and exactly one record, as RFC 9606 §3 requires ("the RRset MUST have exactly one record"; a client "MUST discard the response if the AA flag in the response is set to 0"). They are never forwarded or cached: "RESINFO is a property of the resolver and is not subject to recursive resolution".

The record is checked when the Corefile is loaded and a record the RFC would not allow fails startup: an unregistered key, a value on a boolean key, a malformed EDE list, a non-https URL, a string over 255 octets. The published RDATA is canonical: keys in byte order, each once, the EDE list sorted with runs merged, so the same configuration always produces the same bytes, whatever order the lines are in (RFC 9606 §3: resolvers sharing a name or anycast address "SHOULD expose a consistent RESINFO").

The design, every RFC requirement and what checks it (Go tests, Lean proofs) are in [`docs/resinfo-plugin.md`](../docs/resinfo-plugin.md).

## Syntax

~~~
resinfo NAME... {
    qnamemin
    exterr CODE|LO-HI...
    infourl URL
    deleg
    temp-KEY [VALUE]
    ttl SECONDS
}
~~~

* **NAME** the names to answer at: the resolver's authentication domain name (the name in its TLS certificate and in the DNR option), and `resolver.arpa` if clients discover it through DDR by IP address. At least one; each must be inside a zone of the server block. Matched without regard to ASCII case.
* `qnamemin` publishes `qnamemin`: the resolver does QNAME minimisation (RFC 9156). Only say so if it does; CoreDNS's `forward` does not resolve iteratively, so this is about the upstream.
* `exterr` publishes the RFC 8914 INFO-CODEs the resolver can return, as codes and `LO-HI` ranges in any order: `exterr 15 16 17` and `exterr 17 15-16` both publish `exterr=15-17`.
* `infourl` publishes an `https` URL with more information for IT staff. RFC 9606 §5: the page must be served as `text/html`.
* `deleg` publishes `deleg` (DELEG supported; a temporary IANA registration for draft-ietf-deleg). CoreDNS does not implement DELEG.
* `temp-KEY` publishes a local-use key (RFC 9606 §4), as a boolean or with one value of printable ASCII.
* `ttl` the record's TTL, 0 to 2147483647; default 3600.

Keys are lower-case `a-z`, `0-9` and `-`. Each may be given once, and the block once per server block. At least one key is required (an empty RESINFO is not a valid record).

## Examples

RFC 9606 §6's example, on the encrypted listeners only:

~~~ corefile
tls://.:853 {
    tls cert.pem key.pem
    resinfo resolver.example.net resolver.arpa {
        qnamemin
        exterr 15 16 17
        infourl https://resolver.example.com/guide
        ttl 7200
    }
    forward . 192.0.2.53
}
~~~

`dig @resolver.example.net +tls +nordflag resolver.example.net RESINFO` then returns

~~~
resolver.example.net. 7200 IN RESINFO "exterr=15-17" "infourl=https://resolver.example.com/guide" "qnamemin"
~~~

with the `aa` flag.

## Deploying

* **Serve it on encrypted listeners.** RFC 9606 §7: a client "MUST use" an authenticated secure connection to the resolver or DNSSEC validation; this plugin does not sign the record, so the connection is what makes the answer trustworthy, and for `resolver.arpa` it is the only option. On plain UDP the answer is also unauthenticated and unrate-limited (see *Placement*).
* **Publish only what is true.** The plugin cannot check that the resolver does QNAME minimisation or returns the listed EDEs; RFC 9606 §1 expects clients to choose resolvers by these claims.
* **Keep every instance the same.** Resolvers sharing a name or an anycast address should have identical `resinfo` blocks; the bytes then match exactly.
* **`resolver.arpa` is the DDR responder's zone.** RFC 9462 §6.4: a DDR resolver "MUST treat resolver.arpa as a locally served zone", answering NODATA for everything but its SVCB records. This plugin answers only RESINFO at `resolver.arpa` and passes everything else on, so something else (a `template` or `file` block for `resolver.arpa`) must still serve that zone, or `forward` will send those queries upstream.

## Placement in the chain

*resinfo* goes **immediately after `chaos`**: before `cache` and `forward`, so its answer is never cached or forwarded, and next to `chaos`, the other plugin that answers for the server itself. The Dagger build in [`ci/`](../ci/main.go) puts it there.

`cookie`, `rrl` and `acl` sit later in the chain and do not see RESINFO queries, the same as for `chaos`. That is why the encrypted listeners are the place for it.

## Metrics

* `coredns_resinfo_responses_total{server}` - RESINFO answers written.

## See also

RFC 9606 (DNS Resolver Information), RFC 6763 §6 (the key/value string rules it borrows), RFC 9462 (DDR), RFC 9463 (DNR; [`radnr`](../radnr/) emits it), RFC 8914 (Extended DNS Errors).

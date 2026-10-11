# cookie

## Name

*cookie* - answers DNS Cookies (RFC 7873) with interoperable server cookies (RFC 9018).

## Description

*cookie* is the server side of DNS Cookies. A client puts an 8-byte client cookie in an EDNS0 COOKIE option; the server answers with a server cookie it can later recognise as its own for that client address, without keeping any per-client state. A request that carries a valid server cookie has shown that its source address is real, which is the one thing a spoofed reflection query cannot do.

CoreDNS has no cookie support of its own. Up to v1.14.6 it copies a request's COOKIE option into the response unvalidated, which RFC 7873 §5.2 does not allow for a server that does not implement cookies. This plugin takes that over: the response carries exactly one COOKIE option, the one computed here, whatever else is in the response when it is written. It does not register option 10 with CoreDNS's `edns.SetSupportedOption`, so it behaves the same before and after upstream stops echoing the option.

The server cookie is the RFC 9018 §4 version 1 construction, `SipHash-2-4(client cookie | version | reserved | timestamp | client IP)` under a 16-byte server secret, so it validates against, and is validated by, BIND 9.16+ and Knot DNS 2.9+ instances sharing the secret. The design, the choices made, and what each rule is checked by (Go tests, TLA+ models, Lean proofs) are in [`docs/cookie-plugin.md`](../docs/cookie-plugin.md).

**A cookie is not access control.** A client that sends no COOKIE option cannot be made to: RFC 7873 §5.2.1 requires such a request to be answered as if cookies did not exist. A spoofer simply omits the option. Cookies do not replace rate limiting; they add a signal (see *Metadata*) and, in `enforce` mode, stop cookie-bearing requests from unproven sources being answered with anything larger than a BADCOOKIE.

## Syntax

~~~
cookie {
    secret SECRET
    secret_file FILE
    verify_secret SECRET
    mode permissive | enforce
}
~~~

* `secret` **SECRET** the generating secret: 32 hex digits (16 bytes). It makes every cookie this server issues, and is also accepted for verification.
* `secret_file` **FILE** the same secret read from a file, whitespace trimmed. An alternative to `secret`, not an addition. The file's modification time is what `coredns_cookie_secret_age_seconds` counts from. A file readable by group or others is logged as a warning.
* `verify_secret` **SECRET** a secret accepted for verification only, never used to issue. May be repeated, up to four. This is how a secret is rolled over (below).
* `mode` what to do with a **UDP** request that carried a COOKIE option but no valid server cookie. `permissive` (the default) answers it normally, with a fresh cookie so the client can bootstrap. `enforce` answers **BADCOOKIE** with a fresh cookie and nothing else. TCP, and any transport that is not plain UDP, is always answered normally: the connection already proves the address, and RFC 7873 §5.2.3 warns that BADCOOKIE over TCP can loop.

With no secret at all, a random one is generated at startup and a warning is logged. That is right for a single server, where a restart costs each client one extra round trip at most. It is **wrong for an anycast set**: RFC 9018 §4 says "The Server Secret MUST be configurable to make sure that servers in an anycast network return consistent results."

Secrets are never logged, put in errors, metrics or metadata.

## What it does with a request

Only the first COOKIE option in a request is considered (RFC 7873 §5.2).

| Request | Response |
|---|---|
| no OPT, or no COOKIE option | passed on untouched; no cookie in the response |
| COOKIE of a length other than 8 or 16 to 40 | FORMERR |
| client cookie only | served (`permissive`, TCP) or BADCOOKIE (`enforce`, UDP), with a cookie |
| client cookie and a server cookie that does not verify | the same as client cookie only |
| client cookie and a valid server cookie | served, with a cookie |

Every response with a cookie carries the request's client cookie and a **freshly generated** server cookie under the generating secret. That satisfies RFC 9018 §4.3 (a new cookie when the received one is over half an hour old) and RFC 7873 §7.1 (a new cookie when the old secret was used) without having to decide which applies.

A server cookie is valid for at most **1 hour** after its timestamp and at most **5 minutes** before it (RFC 9018 §4.3), compared in RFC 1982 serial arithmetic so the 2106 wrap of the 32-bit timestamp is harmless. These are fixed, not directives: every server of an anycast set must apply the same window.

## Placement in the chain

*cookie* belongs **immediately after `tsig` and before `cache`**. The Dagger build in [`ci/`](../ci/main.go) puts it there.

* Before `cache`, so a cache hit cannot skip cookie handling (the trap [`docs/rrl-plugin.md`](../docs/rrl-plugin.md) records for `rrl`).
* Before `rrl`, so in `enforce` mode an unvalidated cookie-bearing request is answered with a small BADCOOKIE before rate limiting spends state on it.
* After `tsig`, so the cookie is on the response before TSIG signs it.

`chaos`, `any`, `local` and `dns64` sit earlier and can answer first; those answers carry no cookie.

## Rolling a secret over

Edit the configuration and reload (`SIGUSR1`, or the *reload* plugin). The plugin never rotates on a timer: no goroutines, and nothing that could make servers of an anycast set disagree. RFC 9018 §5 has three stages, and **every** server must finish stage 1 before **any** server starts stage 2:

| Stage | `secret` | `verify_secret` |
|---|---|---|
| steady | A | |
| 1. every server learns B | A | B |
| 2. start issuing with B | B | A |
| 3. forget A, at least the longest zone TTL plus one hour after stage 2 | B | |

RFC 7873 §7.1 says a server secret MUST NOT be used for more than 36 days and SHOULD NOT for more than 26 hours; RFC 9018 §4 relaxes the recommendation to about a month for SipHash. Alert on `coredns_cookie_secret_age_seconds`.

## Examples

A single authoritative server, answering cookies and refusing to answer unproven cookie-bearing UDP clients with anything but BADCOOKIE:

~~~ corefile
example.org {
    cookie {
        mode enforce
    }
    file /etc/coredns/zones/db.example.org
}
~~~

Two or more servers behind one anycast address, secret from a file managed by your configuration tooling:

~~~ corefile
example.org {
    cookie {
        secret_file /run/secrets/dns-cookie
        verify_secret 445536bcd2513298075a5d379663c962
        mode enforce
    }
    file /etc/coredns/zones/db.example.org
}
~~~

Check it with `dig`, which sends a client cookie by default:

~~~
$ dig +cookie @192.0.2.53 example.org A
;; COOKIE: 2464c4abcf10c957010000006acbf93bd14a3ed0616fd641 (good)
~~~

## Metrics

If monitoring is enabled (via the *prometheus* plugin):

* `coredns_cookie_requests_total{case}` requests by case: `no_cookie`, `malformed`, `client_only`, `invalid_server`, `valid`, `valid_previous` (valid under a `verify_secret`). RFC 7873 §7.2 asks for counters of these.
* `coredns_cookie_badcookie_responses_total` responses with extended RCODE BADCOOKIE.
* `coredns_cookie_formerr_responses_total` FORMERR responses to a malformed option.
* `coredns_cookie_secret_age_seconds` age of the generating secret.

## Metadata

With the *metadata* plugin loaded before it, *cookie* sets `cookie/status` to one of the `case` values above, for plugins that act on request metadata.

## Known limitations

* **RFC 7873 §5.4 is not implemented.** A QUERY with QDCOUNT 0 and a COOKIE option, used to fetch a server cookie, is answered SERVFAIL by CoreDNS's server before any plugin runs (`core/dnsserver/server.go`). A client gets a server cookie from any ordinary query.
* **`rrl` cannot yet exempt validated clients.** That needs a change in `rrl` itself (upstream CoreDNS issue [#6187](https://github.com/coredns/coredns/issues/6187) suggests it). The metadata is there for when it can.
* **DoQ is treated as UDP.** CoreDNS reports a DoQ request's transport as `udp`, so `enforce` would answer a cookie-bearing DoQ client without a valid server cookie BADCOOKIE. A DoQ client that sends no COOKIE option is unaffected.
* **The 1-hour window is stricter than RFC 9018's own example.** Appendix A.3 shows a server accepting a cookie 1 hour 52 minutes old. §4.3 says a server SHOULD allow an hour; this plugin allows exactly that, and a client holding an older cookie is simply sent a fresh one (or BADCOOKIE in `enforce` mode, and retries).
* **No automatic secret rotation**, deliberately; see above.
* Keep servers' clocks in step: the timestamp is checked against the local clock (RFC 9018 §8.2).

## See Also

RFC 7873 and RFC 9018 for the protocol, RFC 1982 for the timestamp arithmetic, [`docs/cookie-plugin.md`](../docs/cookie-plugin.md) for the design record and [`verification/`](../verification/README.md) for the models and proofs. CoreDNS's *rrl*, *cache* and *tsig* plugins interact with this one as described under *Placement in the chain*.

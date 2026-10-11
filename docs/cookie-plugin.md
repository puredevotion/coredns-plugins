# `cookie`: DNS Cookies (RFC 7873, RFC 9018) as a CoreDNS plugin

Design record: what this plugin does, what it cannot do, and the decisions
made before any code was written. The TLA+ models, Lean proofs and Go tests
are all derived from the rules below, which are quoted from the RFCs.

## Problem

CoreDNS has no DNS Cookie support. The picture as of 2026-10-11 (checked
against `coredns/coredns` and <https://coredns.io/plugins/>,
<https://coredns.io/explugins/>):

- No in-tree or external plugin implements cookies. `coredns/rrl` has no cookie
  handling either.
- Upstream issue [#6187] ("Create proper support for DNS cookies", open since
  2023-07, no maintainer decision) asks for RFC 7873 and RFC 9018, and a
  comment suggests `rrl` should apply different limits to clients with a
  valid cookie.
- **Up to and including v1.14.6, CoreDNS copies a request's COOKIE option into
  the response unvalidated** (`request/edns0.go`, `supportedOptions`). That
  violates RFC 7873 §5.2: where cookies are not implemented the option "is
  ignored and the server responds as if no COOKIE option had been included".
  Upstream PR [#8514] (merged 2026-09-05) removes the echo on `master`; an
  option is only copied if a plugin registers it with
  `edns.SetSupportedOption`.

This plugin must work on both sides of that change, so it **does not register
option 10 with `SetSupportedOption`** and it **strips any COOKIE option already
present in a response before adding its own**. Either way the response carries
exactly one COOKIE option, the one this plugin computed.

[#6187]: https://github.com/coredns/coredns/issues/6187
[#8514]: https://github.com/coredns/coredns/pull/8514

## What a cookie buys, and what it doesn't

A DNS Cookie lets a server tell a client that has *proven* its source address
(it echoed back a server cookie we minted for that address) from one that has
not. It does not authenticate anything beyond that, protects nothing against an
on-path observer (RFC 9018 §4, §8), and **a client that sends no COOKIE option
cannot be made to**: RFC 7873 §5.2.1 requires such a request to be answered as
if cookies did not exist. So:

- Cookies do not replace rate limiting. A spoofer simply omits the option, and
  `rrl` (see [`rrl-plugin.md`](rrl-plugin.md)) is still what bounds that.
- What they add is a *signal*: "this UDP request comes from a client that holds
  a valid server cookie for its source address". The plugin exposes it as
  metadata (`cookie/status`), and counts every case (RFC 7873 §7.2 asks for
  counters).
- `rrl` cannot yet exempt validated clients. That needs a change upstream in
  `rrl` (the #6187 suggestion). Placing this plugin before `rrl` is still
  correct.

## Wire format (the parts the code and proofs rely on)

COOKIE is EDNS0 option code **10**. OPTION-LENGTH distinguishes the forms
(RFC 7873 §4): **8** is a client cookie only; **16 to 40** is an 8-byte client
cookie followed by an 8 to 32 byte server cookie. "In summary, valid cookie
lengths are 8 and 16 to 40 inclusive" (§5.2.2). Every other length, 0 to 7,
9 to 15 and 41 and up, is malformed.

Server cookie, version 1 (RFC 9018 §4): 16 bytes.

| bytes | field | notes |
|---|---|---|
| 0 | Version | `1` |
| 1 to 3 | Reserved | zero on construction; **not enforced on verification**, and the hash is computed over the received value (§4.2) |
| 4 to 7 | Timestamp | 32-bit unsigned seconds since the Unix epoch, big endian; compared with RFC 1982 serial arithmetic (§4.3) |
| 8 to 15 | Hash | `SipHash-2-4(key = Server Secret, msg = ClientCookie \| Version \| Reserved \| Timestamp \| ClientIP)`, 8 bytes, as SipHash outputs them |

`ClientIP` is 4 bytes (IPv4) or 16 bytes (IPv6) and is not carried in the
cookie, so the SipHash input is exactly **20** or **32** bytes. Verification
requires the whole COOKIE option to be exactly 24 bytes (8 + 16). That is what
makes the input an injective function of its parts, so a 36-byte option from an
IPv4 client cannot be validated as an IPv6 one (§4.4). Any other server cookie
length (8 to 15, 17 to 32) is simply not a valid version-1 cookie.

**IPv4-mapped IPv6** (`::ffff:a.b.c.d`) is unmapped to IPv4 before hashing, so
the 20-byte form is used. Which form a client lands in must not depend on the
socket family CoreDNS happened to accept it on.

Timestamp window: accept if the cookie is at most **1 hour old** or at most
**5 minutes in the future** (§4.3, "SHOULD allow"). These two numbers are fixed
constants, not directives: every server in an anycast set must apply the same
window, and a knob is only a way to get it wrong.

The SipHash-2-4 key is the 16-byte Server Secret. SipHash-2-4 is the REQUIRED
algorithm (§6); it is implemented in this module rather than imported, as a
~60-line function with no dependency, checked against the RFC 9018 Appendix A
test vectors and the SipHash paper's vectors.

## Server behaviour: the five cases (RFC 7873 §5.2)

Only the **first** COOKIE option in the request is considered (§5.2).

| # | request | action |
|---|---|---|
| 1 | no OPT, or OPT without COOKIE | pass on untouched; **no cookie in the response** |
| 2 | COOKIE of malformed length | **FORMERR** |
| 3 | client cookie only (length 8) | policy: see below |
| 4 | client cookie + server cookie that does not validate | same as 3 (§5.2.4 "as if the invalid Server Cookie was not present") |
| 5 | client cookie + valid server cookie | serve, with a COOKIE option in the response |

**Cases 3 and 4, by transport and mode.** Option (1) of §5.2.3, silently
discarding, is not offered: a server MUST "at least occasionally" answer such
requests so the client can bootstrap, and discarding cannot meet that without
per-client state.

- **TCP (and anything not plain UDP)**: serve normally, with a cookie in the
  response. "If the request was received over TCP, the server SHOULD take the
  authentication provided by the use of TCP into account and SHOULD choose (3)",
  and choosing BADCOOKIE over TCP risks an indefinite retry loop (§5.2.3, §5.3).
- **UDP, `mode permissive` (default)**: serve normally (option 3), with a
  cookie in the response so the client can bootstrap.
- **UDP, `mode enforce`**: answer **BADCOOKIE** (extended RCODE 23) with a cookie
  in the response (option 2). The reply is the query plus the OPT RR, not an
  answer, so it amplifies nothing. This applies *only* to requests that carried
  a COOKIE option (see the previous section).

**Response cookie.** Every response to a request in cases 3 to 5 carries
exactly one COOKIE option: the request's client cookie, then a **freshly
generated** server cookie under the *current* secret. RFC 9018 §4.3 says a
server "SHOULD generate a new Server Cookie at least if the received Server
Cookie from the client is more than half an hour old, but it MAY generate a new
cookie more often than that", and RFC 7873 §7.1 says a response to a request
whose cookie was accepted under the previous secret "MUST include a new Server
Cookie". Generating one every time satisfies both and removes the branch where
they could be gotten wrong. It costs one SipHash.

**Not implemented: RFC 7873 §5.4** (a QUERY with QDCOUNT 0 and a COOKIE option,
to fetch a server cookie). CoreDNS answers any request with no question with
SERVFAIL before the plugin chain runs (`core/dnsserver/server.go`, `ServeDNS`),
so a plugin cannot see it. Clients that need a server cookie get one from any
ordinary query.

## Secrets and rollover (RFC 9018 §5, RFC 7873 §7.1)

```
cookie {
    secret      <32 hex digits>     # generates and verifies
    verify_secret <32 hex digits>   # verifies only; repeatable
    secret_file <path>              # file holding the hex secret; may replace `secret`
    mode        permissive | enforce
}
```

- The generating secret is the one named by `secret`/`secret_file`;
  `verify_secret` entries are accepted for verification only. With **no**
  secret configured the plugin generates a random one at startup and logs that
  it did so. That is correct for a single instance (a restart costs each
  client one extra BADCOOKIE round trip in `enforce` mode and nothing in
  `permissive` mode) and **wrong for an anycast set**, where RFC 9018 §4 says
  "The Server Secret MUST be configurable to make sure that servers in an
  anycast network return consistent results."
- The three-stage rollout is done by editing the config and reloading, never
  by a timer in the plugin: no goroutines, nothing to leak on restart (the class
  of bug found in `sni_tls` and `radnr`, see `verification/README.md`).

  | stage | `secret` (generates) | `verify_secret` |
  |---|---|---|
  | steady | A | none |
  | 1: everyone learns B | A | B |
  | 2: start generating with B | B | A |
  | 3: forget A (≥ longest zone TTL + 1h after stage 2) | B | none |

  Stage 1 must complete on **every** server before any server enters stage 2;
  otherwise a server generating with B has its cookies rejected by one that
  does not know B yet. The TLA+ model `CookieRollout` checks exactly that
  ordering constraint, including the out-of-order variants.
- RFC 7873 §7.1: a server secret MUST NOT be used for more than 36 days and
  SHOULD NOT for more than 26 hours; RFC 9018 §4 relaxes the recommendation to
  about once a month for SipHash. The plugin cannot rotate itself without
  breaking anycast consistency, so it exports
  `coredns_cookie_secret_age_seconds` (file mtime for `secret_file`, process
  start otherwise) to alert on.
- Secrets are never logged and never appear in metrics or metadata.

## Placement in the chain

`cookie:` goes **immediately after `tsig:tsig` and before `cache:cache`**
(v1.14.6 `plugin.cfg`):

- before `cache`, so a cache hit does not bypass cookie handling (the same
  trap `rrl-plugin.md` records for `rrl`);
- before `rrl`, so unvalidated, cookie-bearing UDP requests in `enforce` mode
  are answered with a tiny BADCOOKIE before rate limiting spends state on them;
- after `tsig`, so the cookie is added to the response before TSIG signs it.

Limitation: `chaos`, `any`, `local` and `dns64` sit earlier and can answer
before the plugin sees the request; those answers carry no cookie.

DoQ (RFC 9250): `state.Proto()` reports `udp` for it, because the writer's
remote address is a UDP address, so `mode enforce` would treat DoQ like plain
UDP. DoQ clients that send no COOKIE option are unaffected (case 1).

## What backs each rule

| Rule | Go tests | TLA+ | Lean |
|---|---|---|---|
| valid lengths are 8 and 16..40 | `TestClassify` | | `Cookie.classify_valid_iff` |
| 20/32-byte SipHash input is injective in (client cookie, ts, IP) | `TestHashInputInjective` | | `Cookie.hashInput_injective` |
| timestamp window under RFC 1982, across the 2^32 wrap | `TestTimestampWindow`, `TestInWindowMatchesLeanModel`, `FuzzVerify` | | `Cookie.window_wrap`, `window_edges` |
| Reserved bytes are hashed, not enforced | `TestReservedNotEnforced` (RFC 9018 A.3) | | `Cookie.verify_reserved` |
| SipHash-2-4 matches RFC 9018 Appendix A | `TestRFC9018Vectors` | | `Cookie.vector_A1` to `vector_A4` |
| construction then verification succeeds inside the window | `TestRoundTrip` | | `Cookie.verify_generate` |
| all servers in a correctly rolled-out set accept each other's cookies | `TestRolloutStages` | `CookieRollout` | |
| rollout out of order is caught | | `CookieRollout` (expected violation) | |
| a client is never stuck in a BADCOOKIE loop | `TestBootstrap`, `TestEnforceNeverBadCookieOverTCP` | `CookieBootstrap` | |
| a client sees at most two BADCOOKIEs per query, then a TCP answer | `TestBootstrap` | `CookieBootstrap` (`BoundedBadCookies`) | |

The same caveat as the rest of `verification/` applies: the TLA+ models are
written by hand from this document and the RFC text, not extracted from the Go,
and the Lean proofs treat SipHash as an opaque PRF where they are about
structure (and check it concretely only against the published vectors). A
result is a statement about the model.

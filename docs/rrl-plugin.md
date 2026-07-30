# Adopting upstream's `rrl` plugin (response rate limiting)

Why this repo wires in a third-party plugin instead of writing one, what was
verified before trusting it, and the three operational traps found while
verifying.

## Problem

Serving a zone authoritatively to the public internet makes the server a DDoS
*reflection* amplifier: an attacker spoofs the victim's source address in small
UDP queries, and our large answers land on the victim. DNSSEC makes this worse,
not better — a ~60-byte query returning a multi-KB signed answer is a ~50x
amplifier, and signing the zone is a stated goal.

Response Rate Limiting is the standard mitigation (BIND/Knot/PowerDNS all ship
it natively). CoreDNS does not: the pinned `v1.14.6` in-tree `plugin.cfg` has
no rate-limiting plugin of any kind. The homelab plan
(`docs/plans/authoritative-dns-hivre.md`) therefore made "build an RRL plugin"
the highest-priority roadmap item here, and a hard gate on ever exposing our
own authoritative server directly.

## Chosen approach: adopt `github.com/coredns/rrl`, don't reimplement

That plan's check was of CoreDNS's **in-tree** plugin list only. RRL exists as
an **external** plugin, under the `coredns` org itself
(<https://github.com/coredns/rrl>, Apache-2.0, listed on
<https://coredns.io/explugins/>), and it already implements precisely what the
plan specified:

| Plan requirement | Upstream `rrl` |
|---|---|
| Per-client-*prefix* tracking, not per-IP (so spoofing within a network can't dodge it) | `ipv4-prefix-length` (default 24), `ipv6-prefix-length` (default 56) |
| TC=1 "slip" so real clients retry over TCP while spoofed victims get a tiny packet | `slip-ratio N` |
| Separate allowances per response class | `responses-`/`nodata-`/`nxdomains-`/`referrals-`/`errors-per-second`, plus `requests-per-second` |
| Exported counters for the "attack in progress, being handled" alert | `coredns_rrl_responses_exceeded_total`, `coredns_rrl_requests_exceeded_total` |
| Bounded memory | `max-table-size` (default 100000) |
| — (bonus, not in the plan) | `report-only`, which counts without enforcing — the right first deployment step |

Writing our own was rejected. This is the single safety-critical piece in the
whole hivre.com plan: if it is subtly wrong, the failure mode is "we amplified
an attack against a third party." A widely-reviewed implementation under the
CoreDNS org beats a fresh one of ours, and the learning-project appetite this
repo exists to serve is better spent on the items that genuinely do not exist
(RFC 2136 dynamic update, DNS cookies, a general EDE plugin — all confirmed
absent from both the in-tree and external plugin lists).

## Wiring

Registered in `ci/main.go`'s `pluginCfgPatches` as the first *external*
(non-vendored) entry — resolved by a pinned `go get` rather than a `go.mod`
replace directive against local source. See that map's doc comment for the
mechanism and for why the version is pinned exactly rather than floating.

Chain slot comes from upstream's own `plugin.cfg.yaml`
(`landmark: acl`, `after: false`) = immediately **before** `acl:acl`, which in
`v1.14.6` is immediately after `rewrite:rewrite`. Rate limiting belongs ahead
of the plugins that actually answer, so a limited response is never built.

## Verified, not assumed (2026-07-30, CoreDNS v1.14.6)

Upstream `rrl`'s own `go.mod` pins `coredns v1.12.4` — two minor versions
behind the fleet's pin — so "does it even compile against ours" was a real
question, and "does it enforce" a second one. Both were checked against a real
binary rather than inferred:

1. **Builds and registers.** Full three-plugin build (`sni_tls` + `radnr`
   vendored, `rrl` external) against `v1.14.6`: clean build, and all three
   appear in `/coredns -plugins`. The plugin API it uses is unchanged across
   that version gap.
2. **Corefile accepted.** The full option set above parses and the server
   binds.
3. **Actually enforces, and actually slips.** 40 concurrent identical queries
   from one source against `responses-per-second 2`, `slip-ratio 2`:
   2 full answers, **19 responses slipped with TC=1, 19 dropped**,
   `coredns_rrl_responses_exceeded_total 38`. This is the intended shape: a
   real resolver retries the truncated answer over TCP and still resolves; a
   spoofed victim receives only a small truncated packet, so the amplification
   factor collapses.

## Three traps found while verifying

- **`slip-ratio` defaults to `0`, which means "never slip" — always set it.**
  Left at the default, every limited response is silently *dropped*. That still
  stops amplification, but it also makes the zone unresolvable for any
  legitimate resolver sharing the limited prefix (think a large CGNAT or a big
  public resolver's egress range), with no TCP escape hatch. The entire reason
  slip exists is to separate those two outcomes.

- **`cache` sits *before* this slot in the chain, so cache hits bypass RRL.**
  In `v1.14.6`'s order, `cache:cache` is at position 33 and the rrl slot at 35;
  `cache` answers a hit without calling the rest of the chain. Harmless for the
  intended use — a public authoritative block must carry no `cache` and no
  `forward` anyway — but it means **this plugin does not protect a
  forwarding/caching resolver block**, which is the shape of every other
  CoreDNS instance in the fleet. Don't add `rrl` to a resolver Corefile and
  assume it's covered.

- **The metrics carry a `client_ip` label — unbounded cardinality, at exactly
  the wrong moment.** `coredns_rrl_responses_exceeded_total{client_ip="…"}`
  emits one series *per client IP*. Under the very event these metrics exist to
  observe — a flood from spoofed, effectively random sources — this becomes a
  cardinality explosion aimed at the metrics backend, turning a DNS incident
  into a Mimir incident too. Drop or aggregate the label in the
  OTel-collector/relabel stage before these series reach long-term storage;
  keep the per-IP detail in `dnstap` (which the plan already calls for) where
  high-cardinality forensics belong.

## Deployment sequence

1. Ship it with `report-only` set. Counters populate, nothing is enforced —
   this reveals the zone's real per-prefix response-rate baseline instead of
   guessing an allowance.
2. Pick allowances from that baseline, set `slip-ratio 2`, drop `report-only`.
3. Only then is the plan's Phase-2 gate satisfied.

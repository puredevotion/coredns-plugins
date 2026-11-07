# geoscore

## Name

*geoscore* - answers A and AAAA for a name with the endpoint that scores best on a live signal (latency, carbon intensity, cost, health) read from Valkey.

## Description

You list a name's candidate endpoints in the Corefile, each with an ID and its addresses. A separate writer, which is not part of this repository, measures some signal and keeps one score per endpoint in Valkey. *geoscore* reads those scores and answers each A or AAAA query at the name with the addresses of one endpoint:

* `mode best`: the endpoint with the highest score. On equal scores, the one listed first.
* `mode weighted`: an endpoint at random, with probability proportional to its score.

Only an **eligible** endpoint is ever chosen: its score entry exists and passes validation, it is marked healthy, its score is above zero, and it was written no more than `max-staleness` ago by the writer's own clock. When no endpoint is eligible, the configured `fallback` answers instead.

The design, every rule (R1 to R26), and what checks each one (Go tests, Lean proofs, a TLA+ model) are in [`docs/geoscore-plugin.md`](../docs/geoscore-plugin.md).

The answer does not depend on the client. There is no ECS or GeoIP lookup: "geo" means the endpoints are in different places, not that the answer depends on where the client is.

## Syntax

~~~
geoscore NAME {
    endpoint ID ADDRESS [ADDRESS...]
    store valkey ADDR [ADDR...] | memory
    tls_ca FILE
    key PREFIX
    mode best | weighted
    max-staleness DURATION
    ttl SECONDS
    fallback static | servfail | nodata
    refresh DURATION
    timeout DURATION
    rationale-txt
}
~~~

* **NAME** is the owner name to answer. Without a trailing dot it is relative to the server block's zone, and it must be inside that zone.
* `endpoint` **ID ADDRESS...** declares one candidate, and is repeated once per endpoint (1 to 16). The ID is 1 to 32 of `a-z 0-9 -`. Each endpoint has 1 to 8 IPv4 and 1 to 8 IPv6 unicast addresses; an endpoint may have only one family. No address may appear in two endpoints. **The order of the `endpoint` lines matters**: it is the tie-break order, and the `static` fallback answers the first-listed endpoint.
* `store` is where the scores are read from. `valkey` **ADDR...** takes host:port addresses and **requires `tls_ca`**: the scores decide where clients are sent, so the store must be authenticated. There is no option to skip verification. `memory` is an in-process store that nothing outside can write to. It is for tests and dry runs, and with it every answer is the fallback.
* `tls_ca` **FILE** is the PEM bundle the Valkey server certificate is verified against.
* `key` **PREFIX**: endpoint ID's score is at `PREFIX:ID`. The default is `geoscore:` followed by NAME without its trailing dot.
* `mode`: `best` (the default) or `weighted`.
* `max-staleness` **DURATION** is how old a score may be, by its own `updated` timestamp, and still be used. It is whole seconds from 1s to 24h, and defaults to `5m`.
* `ttl` **SECONDS** is the TTL of the answers, 30 by default. It must not exceed `max-staleness`, so a cached answer is never acted on more than `2 × max-staleness` after its score was computed.
* `fallback` is what to answer when no endpoint is eligible. `static` (the default) answers the first-listed endpoint, `servfail` answers SERVFAIL, and `nodata` answers NOERROR with no answer and the zone's SOA, which it gets from the next plugin. Without an SOA, `nodata` answers SERVFAIL instead.
* `refresh` **DURATION** is how often the snapshot of the scores is re-read, on demand (default `1s`, from 100ms up to `max-staleness`).
* `timeout` **DURATION** bounds one store read (default `100ms`). Only one query per `refresh` interval does the read; the others answer from the snapshot.
* `rationale-txt` also answers TXT at `_geoscore.NAME`, explaining the current choice (see below).

Everything else at NAME (other types, and A or AAAA when no endpoint has that family) and every other name goes to the next plugin. So the zone file still holds NAME, its other records and the zone's SOA.

## The score map

The writer stores one JSON string per endpoint at `PREFIX:ID`:

~~~
SET geoscore:www.example.com:eu1 '{"score":0.83,"healthy":true,"updated":1762500000,"signal":"carbon","note":"212 gCO2/kWh"}'
~~~

| field | required | type and range |
|---|---|---|
| `score` | yes | number in [0, 1]; higher is better; 0 drains the endpoint |
| `healthy` | yes | boolean; `false` means never chosen |
| `updated` | yes | integer Unix seconds when the writer computed the score |
| `signal` | no | up to 16 of `a-z 0-9 -`, e.g. `latency`, `carbon`, `cost` |
| `note` | no | up to 100 printable ASCII characters |

An entry with anything else is ignored whole and counted. That includes an unknown field, a missing field, a score that is NaN, negative, above 1 or too large to represent, trailing data, or more than 512 bytes. An entry dated more than 30 s in the future is also ignored, so keep the writer's clock in sync. Have the writer rewrite every endpoint well within `max-staleness`, and drain an endpoint with `healthy:false` or `score:0` rather than by deleting its key. The writer's full contract is in the design doc.

If Valkey becomes unreachable, the plugin keeps the last scores it read. They go stale on their own timestamps, so the name falls back at most `max-staleness` after the last good write.

## Rationale TXT

With `rationale-txt`:

~~~
$ dig +short _geoscore.www.example.com TXT
"geoscore name=www.example.com. mode=best fallback=static max-staleness=300s ttl=30" "A outcome=best choice=eu1 eligible=2/3 total-weight=17000" "eu1 state=eligible score=0.8500 weight=8500 healthy=true age=12s signal=carbon note=212 gCO2/kWh" "us1 state=stale score=0.9900 weight=9900 healthy=true age=400s" "ap1 state=missing"
~~~

It publishes the configuration and the scores, including notes. Leave it off if those are not public.

## Placement in the chain

*geoscore* goes **immediately after `dnssec`** in `plugin.cfg`, and the Dagger build in [`ci/`](../ci/main.go) puts it there:

* after `rrl` and `acl`, so they see the query first;
* after `dnssec`, so with online signing its answers are signed. A pre-signed zone cannot carry signatures for an answer chosen at query time;
* before `hosts`, `dynupdate`, `file`, `probe`, `auto` and `secondary`, so it answers the name and passes everything else to the zone.

`cache` comes earlier and caches the answers for at most `ttl`. In `weighted` mode that repeats one draw for the TTL, so keep `ttl` short. Do not use `cache`'s `serve_stale` for this zone.

## Examples

Three regions ranked by carbon intensity. If the score pipeline dies, the answer is eu1 after five minutes:

~~~ corefile
example.com {
    geoscore www {
        endpoint eu1 192.0.2.1 2001:db8::1
        endpoint us1 198.51.100.1 2001:db8:1::1
        endpoint ap1 203.0.113.1
        store valkey valkey.example.net:6380
        tls_ca /etc/coredns/valkey-ca.pem
        mode best
        max-staleness 5m
        ttl 30
        fallback static
        rationale-txt
    }
    file /etc/coredns/zones/db.example.com
}
~~~

Spread load by score, and refuse to answer rather than guess when no score is fresh:

~~~ corefile
example.com {
    geoscore api {
        endpoint a 192.0.2.10
        endpoint b 192.0.2.20
        store valkey valkey.example.net:6380
        tls_ca /etc/coredns/valkey-ca.pem
        mode weighted
        max-staleness 60s
        ttl 10
        fallback servfail
    }
    file /etc/coredns/zones/db.example.com
}
~~~

## Metrics

If monitoring is enabled (via the *prometheus* plugin):

* `coredns_geoscore_answers_total{name, family, outcome}` counts answers. `outcome` is `best`, `weighted`, `fallback_static`, `fallback_servfail` or `fallback_nodata`.
* `coredns_geoscore_store_errors_total{name}` counts failed reads of the score map.
* `coredns_geoscore_invalid_entries_total{name}` counts score entries the validator refused.

Alert on a rising `fallback_*` rate: it means the writer has stopped or every endpoint is draining.

## Known limitations

* **The writer is not included.** The plugin only reads scores.
* **No per-client answers** (no ECS, no GeoIP).
* **No Valkey AUTH.** As with `probe`, the store is authenticated by its TLS certificate only.
* **DNSSEC needs online signing** for the name (see *Placement*).
* **Weighted mode is approximate in practice**, because resolvers and `cache` hold each draw for `ttl`.

## See Also

[`docs/geoscore-plugin.md`](../docs/geoscore-plugin.md) for the design and requirements, [`verification/`](../verification/README.md) for the Lean proofs (`GeoScore.lean`) and the TLA+ model (`GeoScoreStaleness.tla`), and `probe` for the same Valkey client and Store seam.

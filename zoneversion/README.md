# zoneversion

## Name

*zoneversion* - answers RFC 9660 ZONEVERSION requests with the SOA serial of
the zone that produced the response.

## Description

A client that puts an empty ZONEVERSION option (EDNS(0) option 19) in its
query is asking which version of the zone the answer came from. For a query
in one of its zones, *zoneversion* adds one ZONEVERSION option to the
authoritative response: LABELCOUNT (the zone name's label count), TYPE 0
(SOA-SERIAL) and the zone's SOA serial. It does so for answers, NODATA,
NXDOMAIN and downward referrals out of the zone, and never for a response
that is not authoritative (a forwarded answer, SERVFAIL, REFUSED) or to a
query that did not ask. A query whose option is not empty, or that carries
two, is answered FORMERR (RFC 9660 §3.2.1).

Positive answers carry no SOA, so the plugin observes the serial before and
after the answer (the "before" usually from a 30-second cache) and attaches
it only if the two agree. If the zone reloaded in between, the option is
withheld rather than attached to an answer from another version. The full
design, every RFC 9660 requirement and what checks it:
[`docs/zoneversion-plugin.md`](../docs/zoneversion-plugin.md).

> **Blocker.** With miekg/dns v1.1.73 (CoreDNS v1.14.x, v1.15.0), a
> conformant query (empty option) fails to unpack and is answered FORMERR by
> the server before any plugin runs. See "The blocker" in the design doc.
> Until miekg/dns is fixed, the plugin is correct but not reachable by
> conformant clients.

## Syntax

```
zoneversion [ZONES...]
```

* **ZONES** the zones this server is authoritative for. Defaults to the
  server block's zones. The root zone is refused: list real zones. List
  every zone the chain serves, including zones below a listed one (an
  `auto` directory, a second `file`): an answer from `sub.example.com` is
  not versioned by `example.com`'s serial, and the plugin can only detect
  that when the response carries the sub-zone's SOA or NS.

## plugin.cfg ordering

**Immediately after `transfer:transfer`**: after `cache` (a cache hit is
served without the option) and before every plugin that serves a zone
(`hosts`, `dynupdate`, `file`, `auto`, `secondary`, `sign`). It must sit
before the plugin serving the zone, or it never sees the response and cannot
look up the SOA. `ci/main.go` puts it there.

## Examples

```
example.com:53 {
    zoneversion
    file db.example.com
}
```

```
. {
    zoneversion example.com example.net
    file db.example.com example.com
    file db.example.net example.net
    forward . 192.0.2.53
}
```

In the second block, forwarded answers are never versioned: they are outside
the listed zones.

## Metrics

* `coredns_zoneversion_requests_total{result}`: `added`, `formerr`,
  `ineligible`, `lookup_failed`, `serial_changed`.
* `coredns_zoneversion_serial_regressions_total`: a zone's serial went
  backwards (a rollback).

## Bugs

List only zones whose content never changes without the SOA serial changing
(RFC 9660 §4); `file` reloading on mtime alone breaks that.

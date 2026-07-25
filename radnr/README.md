# radnr — CoreDNS plugin

## Name

*radnr* - advertises an encrypted DNS resolver to the LAN via IPv6 Router
Advertisements (RFC 9463 DNR option 144), optionally with RFC 8106 RDNSS.

## Description

*radnr* is a **listener-only** plugin: like *health* and *metrics* it does not
handle DNS queries. It runs a background IPv6 Router Advertisement sender from
`OnStartup` and stops it on reload/shutdown. RA-DNR-capable clients
(systemd-resolved >=256, Windows 11) auto-discover the encrypted resolver by its
authentication domain name (ADN) and connect over DoT/DoH/DoQ, validated by
hostname PKIX — no per-device certificate install.

Advertisements are both periodic (interval randomized per RFC 4861 §6.2.1, so
multiple advertisers on a link don't stay synchronized) and solicited: a valid
incoming Router Solicitation triggers an immediate RA, rate-limited to at most
one send per 3s (`MIN_DELAY_BETWEEN_RAS`, RFC 4861 §6.2.6) regardless of
trigger.

**SAFETY:** a second RA sender can disrupt LAN IPv6. *radnr* defaults to a
non-default-router RA (RouterLifetime=0) and refuses to advertise prefixes. Use
`dry-run`, then `unicast`, before multicast on a live network.

## Syntax

```
radnr {
    interface IFACE
    adn ADN
    addr ADDR...
    alpn PROTO...
    port PORT
    dohpath TEMPLATE
    unicast CLIENT
    rdnss
    dry-run
}
```

* **interface** (required) interface to advertise on.
* **adn** (required) authentication domain name, e.g. `dns.example.com`.
* **addr** (required) one or more IPv6 resolver addresses.
* **alpn** ALPN ids, e.g. `dot doq h2 h3`.
* **port** resolver port (default none).
* **dohpath** DoH URI template, e.g. `/dns-query{?dns}`.
* **unicast** send only to this client (spike-safe); default multicast `ff02::1`.
* **rdnss** also advertise an RFC 8106 RDNSS option.
* **dry-run** marshal + log, never transmit.

Advanced (guarded): `router-lifetime SECONDS` + `allow-default-router` to act as
a default router (refused without the override). `advertise-prefix` is always
rejected outright — unlike `router-lifetime`, there is no override flag; prefix
advertisement would interfere with the existing router's SLAAC and is never
permitted by this plugin.

## Examples

Advertise an encrypted resolver, dry-run first:

```
. {
    radnr {
        interface eth0
        adn dns.example.com
        addr fde3:6ad1:6501::240
        alpn dot doq
        port 853
        dohpath /dns-query{?dns}
        dry-run
    }
}
```

## Building

This plugin lives out-of-tree. Build a CoreDNS binary with it via the assembly
main in `cmd/coredns`:

```sh
go build -o coredns ./cmd/coredns
./coredns -plugins | grep radnr
```

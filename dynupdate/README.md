# dynupdate

## Name

*dynupdate* - serves a zone and accepts RFC 2136 dynamic updates for it.

## Description

*dynupdate* implements [RFC 2136](https://www.rfc-editor.org/rfc/rfc2136) DNS UPDATE for a single zone held in memory. It exists so an ACME client's built-in RFC 2136 DNS-01 solver can publish `_acme-challenge` records straight into a zone you author yourself, instead of delegating that name to a third party whose API happens to be scriptable.

CoreDNS's server does not filter on opcode: an UPDATE's Zone section occupies the question slot and ZCLASS is `IN`, so an UPDATE reaches the plugin chain like any query. A plugin that does not expect one will read the Zone section as a question and answer nonsense. This one dispatches on opcode and hands everything else to a `file` view of the same zone.

### This plugin owns the zone

The tempting design — keep dynamically-added records in a side table, fall through to *file* for the rest — is wrong in exactly the deployment this plugin is for. The *transfer* plugin takes the **first** `Transferer` that does not return `ErrNotAuthoritative`; it does not merge. A side table would therefore be invisible to AXFR, so a challenge record would never reach the secondary that the public NS records point at, and validation would fail against a primary insisting the record was there.

Owning the zone also means reads, wildcards, delegation, NODATA proofs and AXFR all come from CoreDNS's own `file.Zone` rather than from a second, subtly different authoritative lookup written here.

### Atomicity

RFC 2136 §3.4.2.1 requires that a client never observe half an update. Every change is applied to a **copy** of the record set; only once all prerequisites have passed and the entire update section has prescanned clean is a fresh zone built and swapped in under a write lock.

Rebuilding is O(zone) per update. That is deliberate: this plugin exists for low-rate mutation, where atomicity is worth far more than update throughput. A zone taking thousands of updates a second wants a different design and should say so rather than discover it.

### Authentication is the *tsig* plugin's job

*dynupdate* does not verify TSIG and holds no keys. It checks only that verification **happened**, and refuses the update otherwise — a dynamic-update endpoint that answers an unsigned request is an open zone-mutation API, and "the operator surely configured *tsig* in front" is not an access control. There is deliberately no insecure mode.

Put *tsig* in the same server block with `require_opcode UPDATE`, so unsigned updates are refused before they reach here as well.

### Why `mutable` exists

TSIG authenticates the sender; it cannot say what the sender is allowed to change. A key issued to an ACME client needs to publish TXT records under one name and nothing else, but a bare RFC 2136 grant lets it repoint your A records. `mutable` narrows that to a type list, checked during the prescan so a disallowed type rejects the whole update rather than letting part of it land.

## Syntax

~~~
dynupdate [ZONE] {
    file SEEDFILE
    mutable TYPE...
}
~~~

* **ZONE** the zone to serve and accept updates for. Defaults to the server block's zone. Exactly one — two zones in one block would share a lock and a rebuild, so a bad update to either would stall and endanger both.
* `file` **SEEDFILE** the zone file to load at startup. **Required**: an UPDATE is applied *to* a zone, and a zone with no SOA cannot have its serial advanced or be transferred. Parsed through the same code path as the *file* plugin, so `$ORIGIN`, `$INCLUDE` and `$GENERATE` behave identically.
* `mutable` **TYPE...** restricts updates to these RR types. Omitted, RFC 2136's own rules are the only limit.

## What is implemented

All five prerequisite forms of §3.2, the prescan/apply split of §3.4.1–2, and the update rules that keep a zone a zone:

| Rule | Behaviour |
|---|---|
| Prerequisites | NXDOMAIN / YXDOMAIN / NXRRSET / YXRRSET, including value-dependent RRset equality |
| Out-of-zone name | NOTZONE — a distinct answer from NXDOMAIN; the name may exist, just not here |
| Wrong zone | NOTAUTH — "wrong server", not "wrong credentials" |
| Apex SOA | never deleted; an added SOA applies only if its serial is greater (RFC 1982 arithmetic) |
| Last apex NS | never deleted |
| CNAME exclusivity | enforced both ways, silently ignored rather than rejected, per §3.4.2.3 |
| Identical record re-added | TTL updated, no serial bump, NOERROR |
| Serial | incremented on any real change, so a secondary's serial comparison sees it |
| NOTIFY | sent after a change when *transfer* is configured in the block |

## Known limitations

* **In memory only.** A restart reloads the seed file, so anything added since is lost. Fine for short-lived challenge records — the point of the design — and wrong for anything you expect to survive a rolling update. There is no journal.
* **No NSEC3.** `file.Zone` rejects NSEC3 records outright, so an NSEC3-signed seed zone will not load.
* **Online signing is the *dnssec* plugin's job.** Place *dynupdate* after it in the chain (the default slot does) so added records are signed on the way out; a bare record served from a signed zone reads as bogus.

## Examples

Accept challenge records from an ACME client, and nothing else:

~~~ corefile
example.org {
    tsig {
        secret acme-updater.example.org. <base64 key>
        require_opcode UPDATE
    }

    dynupdate {
        file /etc/coredns/zones/db.example.org
        mutable TXT
    }

    transfer {
        to 192.0.2.53
    }
}
~~~

Test it with `nsupdate`:

~~~
$ nsupdate -y hmac-sha256:acme-updater.example.org.:<base64 key>
> server 192.0.2.1
> zone example.org.
> update add _acme-challenge.example.org. 60 TXT "token"
> send
~~~

## See Also

RFC 2136 for the update protocol, RFC 8945 for TSIG, and CoreDNS's *tsig*, *file* and *transfer* plugins, all three of which this composes with rather than reimplements.

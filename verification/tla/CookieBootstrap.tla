--------------------------- MODULE CookieBootstrap ---------------------------
(***************************************************************************)
(* One DNS client and one `cookie` server, bootstrap and retry (RFC 7873   *)
(* sections 5.2.3, 5.2.4, 5.3; docs/cookie-plugin.md, "Server behaviour"). *)
(*                                                                         *)
(* Server, per request carrying a COOKIE option (cases 3 to 5):            *)
(*   - Mode "permissive": always serve.                                    *)
(*   - Mode "enforce", valid server cookie: serve.                         *)
(*   - Mode "enforce", no or invalid server cookie: over UDP answer        *)
(*     BADCOOKIE; over TCP serve. Either way the response carries a        *)
(*     freshly generated cookie under the secret in use.                   *)
(* Client, RFC 7873 section 5.3: send with the cached server cookie (if    *)
(* any); on BADCOOKIE cache the cookie in the response and retry once      *)
(* over UDP; if that is BADCOOKIE too, retry over TCP; any other response  *)
(* ends the exchange.                                                      *)
(*                                                                         *)
(* Abstractions:                                                           *)
(*  - SipHash is opaque and unforgeable, no spoofer. A Server Cookie is    *)
(*    just the secret it was minted under plus its age in ticks.           *)
(*  - The client cookie is constant and always echoed correctly, so the    *)
(*    section 5.3 "Client Cookie in the reply matches" test always holds.  *)
(*  - Network is reliable. A request and its reply are one atomic step     *)
(*    (Exchange). Ticks and the passage of the window happen only between  *)
(*    exchanges: a query's retries finish far inside the 1 hour window.    *)
(*  - A server restart picks a new random secret and forgets the old one   *)
(*    (no `secret` configured); at most MaxRestarts of them, at any point, *)
(*    including between the legs of one query. Secret numbers stand for    *)
(*    distinct secrets.                                                    *)
(*  - Inconsistent: the anycast set disagrees. Each request is answered by *)
(*    an arbitrary instance whose secret is any of the MaxRestarts+1       *)
(*    secrets, so a cookie minted by one instance is not valid at the next *)
(*    (RFC 7873 section 5.2.4: "an anycast cluster of servers is not       *)
(*    consistently configured").                                           *)
(*  - A response served for a query ends the query; the content of the     *)
(*    answer is not modelled. A query that the client gives up on is       *)
(*    "failed".                                                            *)
(*  - MaxAge is the acceptance window in ticks. Only the newest cookie is  *)
(*    cached.                                                              *)
(*                                                                         *)
(* Variants:                                                               *)
(*  BadOverTCP   TRUE: the server ignores the transport and answers        *)
(*               BADCOOKIE over TCP as well (section 5.2.3's "choosing     *)
(*               (2)" over TCP).                                           *)
(*  ClientLoops  TRUE: after BADCOOKIE over TCP the client goes back to    *)
(*               UDP instead of giving up.                                 *)
(***************************************************************************)
EXTENDS Integers

CONSTANTS
    \* @type: Str;
    Mode,           \* "permissive" or "enforce"
    \* @type: Int;
    MaxAge,         \* acceptance window, ticks
    \* @type: Int;
    MaxRestarts,    \* server secret changes
    \* @type: Int;
    MaxQueries,     \* logical queries the client makes
    \* @type: Bool;
    Inconsistent,
    \* @type: Bool;
    BadOverTCP,
    \* @type: Bool;
    ClientLoops

VARIABLES
    \* @type: Int;
    secret,     \* the secret the server currently uses (and verifies with)
    \* @type: Int;
    cs,         \* secret of the cached server cookie, -1 = none cached
    \* @type: Int;
    ca,         \* its age in ticks, saturating at MaxAge+1 (expired)
    \* @type: Str;
    phase,      \* "idle" | "sending" | "answered" | "failed"
    \* @type: Str;
    step,       \* next send: "udp0" first, "udp1" retry, "tcp" fallback
    \* @type: Int;
    bad,        \* BADCOOKIEs seen for the current query, saturating at 3
    \* @type: Int;
    queries,    \* logical queries started
    \* @type: Str;
    resp        \* ghost: last response: "none" | "ok" | "badudp" | "badtcp"

vars == <<secret, cs, ca, phase, step, bad, queries, resp>>

Secrets == 0..MaxRestarts
BadCap == 3

TypeOK ==
    /\ Mode \in {"permissive", "enforce"}
    /\ secret \in Secrets
    /\ cs \in -1..MaxRestarts
    /\ ca \in 0..(MaxAge + 1)
    /\ phase \in {"idle", "sending", "answered", "failed"}
    /\ step \in {"udp0", "udp1", "tcp"}
    /\ bad \in 0..BadCap
    /\ queries \in 0..MaxQueries
    /\ resp \in {"none", "ok", "badudp", "badtcp"}

Init ==
    /\ secret = 0
    /\ cs = -1 /\ ca = 0
    /\ phase = "idle" /\ step = "udp0"
    /\ bad = 0 /\ queries = 0
    /\ resp = "none"

-----------------------------------------------------------------------------
(* The environment.                                                        *)

\* Time passes only while no exchange is in flight.
Tick ==
    /\ phase # "sending"
    /\ ca' = IF ca > MaxAge THEN MaxAge + 1 ELSE ca + 1
    /\ UNCHANGED <<secret, cs, phase, step, bad, queries, resp>>

\* The server restarts with a new random secret, at any moment.
Restart ==
    /\ secret < MaxRestarts
    /\ secret' = secret + 1
    /\ UNCHANGED <<cs, ca, phase, step, bad, queries, resp>>

-----------------------------------------------------------------------------
(* The client.                                                             *)

Start ==
    /\ phase \in {"idle", "answered"} /\ queries < MaxQueries
    /\ phase' = "sending" /\ step' = "udp0"
    /\ bad' = 0 /\ queries' = queries + 1
    /\ UNCHANGED <<secret, cs, ca, resp>>

\* One request and its reply. inst is the instance that handles it.
Exchange ==
    /\ phase = "sending"
    /\ \E inst \in (IF Inconsistent THEN Secrets ELSE {secret}) :
        LET tcp   == step = "tcp"
            valid == cs = inst /\ ca <= MaxAge
            \* RFC 7873 5.2.3 / 5.2.4: no usable server cookie is treated as
            \* "client cookie only", where the server picks (2) or (3).
            refuse == /\ Mode = "enforce"
                      /\ ~valid
                      /\ (~tcp \/ BadOverTCP)
        IN
          /\ cs' = inst /\ ca' = 0          \* every response carries a fresh cookie
          /\ IF refuse
               THEN \* BADCOOKIE: the client retries as section 5.3 says
                    /\ resp' = IF tcp THEN "badtcp" ELSE "badudp"
                    /\ bad' = IF bad >= BadCap THEN BadCap ELSE bad + 1
                    /\ queries' = queries
                    /\ CASE step = "udp0" -> step' = "udp1" /\ phase' = "sending"
                         [] step = "udp1" -> step' = "tcp"  /\ phase' = "sending"
                         [] OTHER ->
                              IF ClientLoops
                                THEN step' = "udp0" /\ phase' = "sending"
                                ELSE step' = "tcp" /\ phase' = "failed"
               ELSE /\ resp' = "ok"
                    /\ phase' = "answered" /\ step' = step
                    /\ UNCHANGED <<bad, queries>>
    /\ UNCHANGED secret

Next == Tick \/ Restart \/ Start \/ Exchange

Spec == Init /\ [][Next]_vars /\ WF_vars(Exchange)

-----------------------------------------------------------------------------
(* Properties.                                                             *)

\* NoBadCookieOverTCP. RFC 7873 section 5.2.3: "If the request was received
\* over TCP, the server SHOULD take the authentication provided by the use
\* of TCP into account and SHOULD choose (3). In this case, if the server is
\* not willing to accept the security provided by TCP as a substitute for
\* the security provided by DNS Cookies but instead chooses (2), there is
\* some danger of an indefinite loop of retries (see Section 5.3)."
NoBadCookieOverTCP == resp # "badtcp"

\* BoundedBadCookies. RFC 7873 section 5.3: "The client SHOULD retry the
\* request using the new Server Cookie from the response. [...] If the reply
\* to a retried request with a fresh Server Cookie is BADCOOKIE, the client
\* SHOULD retry using TCP as the transport". So a query is sent over UDP,
\* over UDP again, then over TCP, and the server never refuses TCP: at most
\* 2 BADCOOKIEs per logical query. This holds with the secret changing
\* between legs, too, because the third leg cannot be refused. (The bound
\* is on the counter, which saturates at 3, so 3 means "3 or more".)
BoundedBadCookies == bad <= 2

\* In permissive mode a client never sees BADCOOKIE.
PermissiveNeverBad == Mode = "permissive" => bad = 0

\* EventuallyAnswered. A query in flight is answered, under weak fairness of
\* the exchange (the network eventually delivers). Section 5.2.3: servers
\* "MUST, at least occasionally, respond to such requests" so that the
\* client "can bootstrap"; the TCP fallback is what makes the answer certain.
EventuallyAnswered == (phase = "sending") ~> (phase = "answered")

=============================================================================

---------------------------- MODULE CookieRollout ----------------------------
(***************************************************************************)
(* RFC 9018 section 5: the three-stage Server Secret rollout across an     *)
(* anycast set of servers, as the `cookie` plugin does it (docs/cookie-    *)
(* plugin.md, "Secrets and rollover"): the operator edits each server's    *)
(* config (`secret` generates and verifies, `verify_secret` verifies only) *)
(* and reloads. No timer inside the plugin.                                *)
(*                                                                         *)
(*   stage | generating | verify-only   (per server)                      *)
(*   ------+------------+------------                                      *)
(*   0     | A          | {}           steady state                        *)
(*   1     | A          | {B}          Learn:  everyone learns B           *)
(*   2     | B          | {A}          Switch: start generating with B     *)
(*   3     | B          | {}           Forget: drop A                      *)
(*                                                                         *)
(* A server's accept set is {generating} U verify-only.                    *)
(*                                                                         *)
(* Abstractions:                                                           *)
(*  - SipHash is an opaque, unforgeable function. A Server Cookie is only  *)
(*    ever (issuing secret, issue time): the client, its IP and the client *)
(*    cookie are fixed and equal for every cookie, and a spoofer cannot    *)
(*    mint one. A server verifies a cookie iff the cookie's secret is in   *)
(*    its accept set and the cookie is inside the acceptance window.       *)
(*  - Time is a discrete tick. MaxAge is the acceptance window (the 1 hour *)
(*    of RFC 9018 section 4.3) in ticks: a cookie issued at tick t is      *)
(*    inside the window while now - t <= MaxAge. The 5-minute future       *)
(*    allowance is not modelled (clocks are shared).                       *)
(*  - The plugin always issues a fresh cookie, so the "half an hour"       *)
(*    regeneration rule is not modelled.                                   *)
(*  - Nothing is stored per cookie. `age[s][x]` is the age of the NEWEST   *)
(*    cookie server s has issued under secret x (-1: none within the       *)
(*    window). Acceptance depends only on (secret, age), so the newest is  *)
(*    the one that is inside the window longest: if any cookie of (s, x)   *)
(*    is inside the window, the newest is. A client may obtain a cookie    *)
(*    from any server at any time (Issue). Ages are therefore bounded and  *)
(*    the state space is finite without a clock bound.                     *)
(*  - Secrets are {A, B}; a second rollover back to A is not modelled.     *)
(*  - Reloads are atomic per server and the operator may interleave the    *)
(*    servers in any order.                                                *)
(*                                                                         *)
(* Flags (the variants in the suite):                                      *)
(*  StrictOrder   TRUE: Switch only once EVERY server has learned B.       *)
(*  WaitWindow    TRUE: Forget only once more than MaxAge ticks have       *)
(*                passed since the LAST server switched.                   *)
(*  ReloadReplaces TRUE: a reload replaces the verify-only list; FALSE: a  *)
(*                reload that drops `verify_secret A` keeps A verifying    *)
(*                (a plausible implementation bug, kept as a negative      *)
(*                control for NeverVerifiesRemovedSecret).                 *)
(* Forget always also requires every server to be generating with B: that *)
(* is "stage 3 follows stage 2".                                           *)
(***************************************************************************)
EXTENDS Integers

CONSTANTS
    \* @type: Set(Str);
    Servers,        \* the anycast set
    \* @type: Int;
    MaxAge,         \* acceptance window, in ticks
    \* @type: Bool;
    StrictOrder,
    \* @type: Bool;
    WaitWindow,
    \* @type: Bool;
    ReloadReplaces

Old == "A"
New == "B"
Secrets == {Old, New}

VARIABLES
    \* @type: Str -> Str;
    gen,       \* secret each server generates with
    \* @type: Str -> Set(Str);
    ver,       \* each server's verify-only secrets
    \* @type: Str -> Set(Str);
    removed,   \* ghost: secrets the operator has taken out of the config
    \* @type: Str -> Str -> Int;
    age,       \* newest cookie issued by s under x: age in ticks, -1 = none in window
    \* @type: Str -> Int;
    since2     \* ticks since s switched to generating with B, saturating at MaxAge+1; -1 = not yet

vars == <<gen, ver, removed, age, since2>>

Accepts(s) == {gen[s]} \cup ver[s]

TypeOK ==
    /\ gen \in [Servers -> Secrets]
    /\ ver \in [Servers -> SUBSET Secrets]
    /\ removed \in [Servers -> SUBSET Secrets]
    /\ age \in [Servers -> [Secrets -> -1..MaxAge]]
    /\ since2 \in [Servers -> -1..(MaxAge + 1)]

Init ==
    /\ gen = [s \in Servers |-> Old]
    /\ ver = [s \in Servers |-> {}]
    /\ removed = [s \in Servers |-> {}]
    /\ age = [s \in Servers |-> [x \in Secrets |-> -1]]
    /\ since2 = [s \in Servers |-> -1]

-----------------------------------------------------------------------------
(* Time. Every age moves one tick; a cookie past MaxAge leaves the window. *)

\* @type: (Int) => Int;
Older(a) == IF a < 0 \/ a >= MaxAge THEN -1 ELSE a + 1

\* @type: (Int) => Int;
Since(a) == IF a < 0 THEN -1 ELSE IF a > MaxAge THEN MaxAge + 1 ELSE a + 1

Tick ==
    /\ age' = [s \in Servers |-> [x \in Secrets |-> Older(age[s][x])]]
    /\ since2' = [s \in Servers |-> Since(since2[s])]
    /\ UNCHANGED <<gen, ver, removed>>

\* Some client gets a cookie from server s, under the secret s generates with.
Issue(s) ==
    /\ age' = [age EXCEPT ![s][gen[s]] = 0]
    /\ UNCHANGED <<gen, ver, removed, since2>>

-----------------------------------------------------------------------------
(* The operator.                                                           *)

\* Stage 1, one server: learn B, keep generating with A.
Learn(s) ==
    /\ gen[s] = Old /\ New \notin ver[s]
    /\ ver' = [ver EXCEPT ![s] = @ \cup {New}]
    /\ UNCHANGED <<gen, removed, age, since2>>

\* Stage 2, one server: start generating with B, keep verifying A.
\* RFC 9018 section 5: "it is vital that the Server Secret is shared among all
\* servers before it is used to generate Server Cookies on any server."
\* Stage 2: "This stage is initiated by the operator after the Server Cookie
\* is present on all members in the anycast set."
Switch(s) ==
    /\ gen[s] = Old /\ New \in ver[s]
    /\ StrictOrder => \A t \in Servers : New \in ver[t]
    /\ gen' = [gen EXCEPT ![s] = New]
    /\ ver' = [ver EXCEPT ![s] = @ \cup {Old}]
    /\ since2' = [since2 EXCEPT ![s] = 0]
    /\ UNCHANGED <<removed, age>>

\* Stage 3, one server: forget A.
\* "It is RECOMMENDED that the operator wait, after initiating Stage 2 and
\* before initiating Stage 3, at least a period of time equal to the longest
\* TTL in the zones served by the server plus 1 hour. The operator SHOULD
\* wait at least longer than the period clients are allowed to use the same
\* Server Cookie, which SHOULD be 1 hour (see Section 4.3)."
\* The wait runs from the LAST server's switch: until then some server is
\* still minting cookies under A.
Forget(s) ==
    /\ gen[s] = New /\ Old \in ver[s]
    /\ \A t \in Servers : gen[t] = New
    /\ WaitWindow => \A t \in Servers : since2[t] > MaxAge
    /\ removed' = [removed EXCEPT ![s] = @ \cup {Old}]
    /\ ver' = IF ReloadReplaces
                THEN [ver EXCEPT ![s] = @ \ {Old}]
                ELSE ver
    /\ UNCHANGED <<gen, age, since2>>

Operator == \E s \in Servers : Learn(s) \/ Switch(s) \/ Forget(s)

Next == Tick \/ (\E s \in Servers : Issue(s)) \/ Operator

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* Properties.                                                             *)

\* NoSpuriousReject. RFC 9018 section 5: "All servers in an anycast set must
\* be able to verify the Server Cookies constructed by all other servers in
\* that anycast set at all times." Stated for a rollout that follows the
\* RFC's ordering: every cookie still inside its window, from ANY server, is
\* in the accept set of EVERY server. A cookie under a secret the verifier
\* does not hold would be a BADCOOKIE for a client that did nothing wrong.
NoSpuriousReject ==
    \A s \in Servers : \A x \in Secrets : \A t \in Servers :
        age[s][x] >= 0 => x \in Accepts(t)

\* NeverVerifiesRemovedSecret. RFC 9018 section 5, stage 3: "the previous
\* Server Secret can be removed and MUST NOT be used anymore for verifying."
\* A secret the operator removed from a server's config is in neither its
\* generating nor its verify set.
NeverVerifiesRemovedSecret ==
    \A s \in Servers : removed[s] \cap Accepts(s) = {}

=============================================================================

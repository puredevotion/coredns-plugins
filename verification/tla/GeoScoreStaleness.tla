-------------------------- MODULE GeoScoreStaleness --------------------------
(***************************************************************************)
(* The `geoscore` plugin's score lifecycle (docs/geoscore-plugin.md,       *)
(* R15, R20-R22, R25): a writer (the refresher CronJob, out of scope for   *)
(* the plugin) stamps each endpoint's score entry with its own clock and   *)
(* writes it to the store; the plugin re-reads the store into an           *)
(* in-process snapshot (instance.go `current`/`fetch`); a query is         *)
(* answered from the snapshot (handler.go, `instance.decide`); a resolver  *)
(* caches the answer for the configured TTL.                               *)
(*                                                                         *)
(* Abstractions:                                                           *)
(*  - Selection itself is proved in Lean (GeoScore.lean). Here the plugin  *)
(*    may answer ANY endpoint its eligibility rule admits, which covers    *)
(*    both best and weighted mode.                                         *)
(*  - A score entry is (present, healthy, positive weight, age). The       *)
(*    score's value and its validation are Lean's and the Go tests'.       *)
(*  - Time is a discrete tick and ages saturate (Cap), as in               *)
(*    CookieRollout: an entry's age is now minus its writer timestamp, so  *)
(*    the state space is finite without a clock bound. The Go code         *)
(*    tolerates `skew` seconds of writer clock ahead; not modelled here    *)
(*    (skew = 0; GeoScore.lean covers future-dated entries).               *)
(*  - The refresh interval is abstracted to "a fetch may happen at any     *)
(*    step": every refresh schedule is a subset of these behaviours.       *)
(*  - Failures need no state of their own: nothing forces a Write or a     *)
(*    Fetch to happen, so a writer that has died (no more Writes) and a    *)
(*    store that is down (every Fetch fails, the snapshot is kept and      *)
(*    ages: R25) are behaviours of the spec, from any point and for as     *)
(*    long as you like, and so is their recovery.                          *)
(*  - A fallback answer carries no score, so it has no staleness, and the  *)
(*    model resolver does not cache it.                                    *)
(*                                                                         *)
(* Flags (the variants in the suite):                                      *)
(*  JudgeByWriter  TRUE: an entry is fresh iff its age, from the writer's  *)
(*                 own timestamp, is <= MaxStale (the plugin). FALSE: iff  *)
(*                 the snapshot was fetched within MaxStale (a plausible   *)
(*                 bug: a store that is up but no longer written keeps     *)
(*                 the snapshot "fresh" forever).                          *)
(*  CheckStaleness FALSE: the plugin ignores age altogether.               *)
(*  TTL            the answer TTL; the validator enforces TTL <= MaxStale. *)
(***************************************************************************)
EXTENDS Integers

CONSTANTS
    \* @type: Set(Str);
    Endpoints,
    \* @type: Int;
    MaxStale,
    \* @type: Int;
    TTL,
    \* @type: Bool;
    JudgeByWriter,
    \* @type: Bool;
    CheckStaleness

VARIABLES
    \* @type: Str -> $entry;
    store,
    \* @type: Str -> $entry;
    snap,
    \* @type: Int;
    fetchAge,
    \* @type: { kind: Str, stale: Bool, eligible: Bool };
    ans,
    \* @type: { held: Bool, age: Int, left: Int };
    cache

vars == <<store, snap, fetchAge, ans, cache>>

\* Ages above Cap are all "older than anything the properties distinguish".
Cap == 2 * MaxStale + 1

Inc(a) == IF a < Cap THEN a + 1 ELSE Cap

\* @typeAlias: entry = { present: Bool, healthy: Bool, pos: Bool, age: Int };
\* @type: $entry;
Missing == [present |-> FALSE, healthy |-> FALSE, pos |-> FALSE, age |-> Cap]

\* @type: ($entry) => $entry;
Older(x) == [x EXCEPT !.age = Inc(x.age)]

\* Whether snapshot entry x counts as fresh now.
\* @type: ($entry) => Bool;
Fresh(x) ==
    IF JudgeByWriter THEN x.age <= MaxStale ELSE fetchAge <= MaxStale

\* The eligibility rule the plugin applies (R15).
PluginEligible(e) ==
    /\ snap[e].present /\ snap[e].healthy /\ snap[e].pos
    /\ (CheckStaleness => Fresh(snap[e]))

\* The rule as the design states it, whatever the variant: present,
\* healthy, positive, and written no more than MaxStale ago.
TrulyEligible(e) ==
    /\ snap[e].present /\ snap[e].healthy /\ snap[e].pos
    /\ snap[e].age <= MaxStale

Init ==
    /\ store = [e \in Endpoints |-> Missing]
    /\ snap = [e \in Endpoints |-> Missing]
    /\ fetchAge = Cap
    /\ ans = [kind |-> "none", stale |-> FALSE, eligible |-> FALSE]
    /\ cache = [held |-> FALSE, age |-> 0, left |-> 0]

\* One second passes: everything ages, and the resolver drops what expires.
Tick ==
    /\ store' = [e \in Endpoints |-> Older(store[e])]
    /\ snap' = [e \in Endpoints |-> Older(snap[e])]
    /\ fetchAge' = Inc(fetchAge)
    /\ cache' = IF ~cache.held THEN cache
                ELSE IF cache.left = 0 THEN [held |-> FALSE, age |-> 0, left |-> 0]
                ELSE [held |-> TRUE, age |-> Inc(cache.age), left |-> cache.left - 1]
    /\ UNCHANGED ans

\* The writer stamps an entry with its own clock (age 0).
Write(e, h, p) ==
    /\ store' = [store EXCEPT ![e] = [present |-> TRUE, healthy |-> h, pos |-> p, age |-> 0]]
    /\ UNCHANGED <<snap, fetchAge, ans, cache>>

\* instance.go fetch: a successful read replaces the snapshot. A failed one
\* is a Fetch that does not happen: the old entries stay and go on ageing.
Fetch ==
    /\ snap' = store
    /\ fetchAge' = 0
    /\ UNCHANGED <<store, ans, cache>>

\* handler.go: answer an endpoint from the snapshot; the resolver caches it.
AnswerEndpoint(e) ==
    /\ PluginEligible(e)
    /\ ans' = [kind |-> "endpoint", stale |-> snap[e].age > MaxStale,
               eligible |-> TrulyEligible(e)]
    /\ cache' = [held |-> TRUE, age |-> snap[e].age, left |-> TTL]
    /\ UNCHANGED <<store, snap, fetchAge>>

\* handler.go: nothing eligible, so the configured fallback (R20).
AnswerFallback ==
    /\ \A e \in Endpoints : ~PluginEligible(e)
    /\ ans' = [kind |-> "fallback", stale |-> FALSE,
               eligible |-> \E e \in Endpoints : TrulyEligible(e)]
    /\ UNCHANGED <<store, snap, fetchAge, cache>>

Next ==
    \/ Tick
    \/ \E e \in Endpoints, h \in BOOLEAN, p \in BOOLEAN : Write(e, h, p)
    \/ Fetch
    \/ \E e \in Endpoints : AnswerEndpoint(e)
    \/ AnswerFallback

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
Ages == 0..Cap

Entries == [present : BOOLEAN, healthy : BOOLEAN, pos : BOOLEAN, age : Ages]

TypeOK ==
    /\ store \in [Endpoints -> Entries]
    /\ snap \in [Endpoints -> Entries]
    /\ fetchAge \in Ages
    /\ ans \in [kind : {"none", "endpoint", "fallback"}, stale : BOOLEAN, eligible : BOOLEAN]
    /\ cache \in [held : BOOLEAN, age : Ages, left : 0..TTL]

\* R15, R21: an endpoint answer is never based on a score older than
\* MaxStale at the moment it is given, and only on a healthy, positive entry,
\* whatever the writer and the store do (or stop doing).
NeverServeStale ==
    ans.kind = "endpoint" => (~ans.stale /\ ans.eligible)

\* R20: the fallback is taken only when nothing is eligible: a fresh,
\* healthy score is used as soon as it is in the snapshot.
FallbackOnlyWhenNoneEligible ==
    ans.kind = "fallback" => ~ans.eligible

\* R22: with TTL <= MaxStale, no resolver holds an answer based on a score
\* written more than 2 * MaxStale ago.
CacheExposureBound ==
    cache.held => cache.age <= 2 * MaxStale

-----------------------------------------------------------------------------
\* Inductive invariant (tla/inductive/, Apalache): it holds initially, every
\* step preserves it, and it implies the three properties above, so they
\* hold in every reachable state of an instance of any depth. The cache
\* conjunct is the heart of it: a held answer's age plus the TTL it has
\* left never exceeds MaxStale + TTL, because it was fresh when given.
IndInv ==
    /\ TypeOK
    /\ ans.kind = "endpoint" => (~ans.stale /\ ans.eligible)
    /\ ans.kind = "fallback" => ~ans.eligible
    /\ cache.held => cache.age + cache.left <= MaxStale + TTL
    /\ TTL <= MaxStale
=============================================================================

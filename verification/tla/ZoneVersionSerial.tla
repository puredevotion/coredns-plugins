------------------------- MODULE ZoneVersionSerial -------------------------
(***************************************************************************)
(* RFC 9660 ZONEVERSION in zoneversion (handler.go, cache.go): which SOA   *)
(* serial a response may advertise while the zone's serial moves under     *)
(* concurrent queries.                                                     *)
(*                                                                         *)
(* A positive answer carries no SOA, so serveVersioned brackets it:        *)
(*                                                                         *)
(*   before := cache.get(apex)  or, if absent/stale, lookup(apex)  -- Pre  *)
(*   res    := Next.ServeDNS(query)                                -- Main *)
(*   after  := lookup(apex)                                        -- Post *)
(*   advertise after  iff  before = after                                  *)
(*                                                                         *)
(* and a negative answer carries the zone's SOA from the same snapshot,    *)
(* which is advertised directly. Every lookup is an observation the cache  *)
(* takes under cache.go's rule (keep the RFC 1982 greater; modelled as >   *)
(* on naturals, exact while the zone has moved by less than 2^31, see      *)
(* ZoneVersion.lean). The cache entry going stale (maxEntryAge) is the     *)
(* nondeterministic Expire action: any time, as often as it likes.         *)
(*                                                                         *)
(* Each step is atomic: a lookup and the answer each read the zone once,   *)
(* as file does under its RWMutex; the cache is under its mutex.          *)
(*                                                                         *)
(* Properties (docs/zoneversion-plugin.md):                                *)
(*   DuringQuery      (G1) the advertised serial is one the zone had at    *)
(*                         some instant while the query was in progress:   *)
(*                         never invented, never a mix, never stale from   *)
(*                         before the query began.                         *)
(*   AnswerConsistent (G2) the advertised serial is the one of the zone    *)
(*                         version that produced the answer.               *)
(*                                                                         *)
(* Variants: Bracket = FALSE is "look the serial up once, after the        *)
(* answer" (violates G2, keeps G1); Rollback = TRUE lets the operator set  *)
(* the serial back to an earlier value (violates G2: assumption A1; G1     *)
(* still holds); UseCache = FALSE always looks up before the answer.       *)
(***************************************************************************)
EXTENDS Integers, FiniteSets

CONSTANTS
    \* @type: Int;
    NumQueries,  \* concurrent queries
    \* @type: Int;
    MaxChanges,  \* bound on zone serial changes
    \* @type: Bool;
    Bracket,     \* compare a before-observation with the after-lookup
    \* @type: Bool;
    UseCache,    \* the before-observation may come from the cache
    \* @type: Bool;
    Rollback     \* the zone's serial may go back to an earlier value

Q == 1..NumQueries
None == 0      \* no serial: serials are >= 1
Active == {"pre", "main", "post"}

VARIABLES
    \* @type: Int;
    serial,   \* the zone's current SOA serial
    \* @type: Set(Int);
    history,  \* every serial the zone has had
    \* @type: Int;
    changes,  \* serial changes so far
    \* @type: Int;
    cache,    \* the cached observation for the apex, None if none/stale
    \* @type: Int -> Str;
    pc,       \* "idle" | "pre" | "main" | "post" | "done"
    \* @type: Int -> Set(Int);
    seen,     \* ghost: serials the zone had while query q was in progress
    \* @type: Int -> Int;
    before,   \* the before-observation, None if none
    \* @type: Int -> Int;
    ans,      \* ghost: the serial of the zone version that answered q
    \* @type: Int -> Int;
    adv       \* the serial advertised on q's response, None if withheld

vars == <<serial, history, changes, cache, pc, seen, before, ans, adv>>

\* cache.go update(), on a fresh entry; a stale one is None after Expire.
Observe(c, s) == IF c = None THEN s ELSE IF s > c THEN s ELSE c

Init ==
    /\ serial = 1
    /\ history = {1}
    /\ changes = 0
    /\ cache = None
    /\ pc = [q \in Q |-> "idle"]
    /\ seen = [q \in Q |-> {}]
    /\ before = [q \in Q |-> None]
    /\ ans = [q \in Q |-> None]
    /\ adv = [q \in Q |-> None]

\* A query asking for the version arrives.
Start(q) ==
    /\ pc[q] = "idle"
    /\ pc' = [pc EXCEPT ![q] = "pre"]
    /\ seen' = [seen EXCEPT ![q] = {serial}]
    /\ UNCHANGED <<serial, history, changes, cache, before, ans, adv>>

\* The before-observation from a fresh cache entry.
PreCache(q) ==
    /\ pc[q] = "pre" /\ UseCache /\ cache # None
    /\ before' = [before EXCEPT ![q] = cache]
    /\ pc' = [pc EXCEPT ![q] = "main"]
    /\ UNCHANGED <<serial, history, changes, cache, seen, ans, adv>>

\* The before-observation by an internal SOA lookup.
PreLookup(q) ==
    /\ pc[q] = "pre" /\ (~UseCache \/ cache = None)
    /\ before' = [before EXCEPT ![q] = serial]
    /\ cache' = Observe(cache, serial)
    /\ pc' = [pc EXCEPT ![q] = "main"]
    /\ UNCHANGED <<serial, history, changes, seen, ans, adv>>

\* The rest of the chain answers from the zone as it is now. A negative
\* answer (NXDOMAIN, NODATA) carries the apex SOA from the same snapshot.
Main(q) ==
    /\ pc[q] = "main"
    /\ ans' = [ans EXCEPT ![q] = serial]
    /\ \E negative \in BOOLEAN :
         IF negative
           THEN /\ adv' = [adv EXCEPT ![q] = serial]
                /\ cache' = Observe(cache, serial)
                /\ pc' = [pc EXCEPT ![q] = "done"]
           ELSE /\ pc' = [pc EXCEPT ![q] = "post"]
                /\ UNCHANGED <<adv, cache>>
    /\ UNCHANGED <<serial, history, changes, seen, before>>

\* The after-lookup, and the decision.
Post(q) ==
    /\ pc[q] = "post"
    /\ cache' = Observe(cache, serial)
    /\ adv' = [adv EXCEPT ![q] =
                 IF ~Bracket \/ before[q] = serial THEN serial ELSE None]
    /\ pc' = [pc EXCEPT ![q] = "done"]
    /\ UNCHANGED <<serial, history, changes, seen, before, ans>>

\* The entry passes maxEntryAge.
Expire ==
    /\ cache # None
    /\ cache' = None
    /\ UNCHANGED <<serial, history, changes, pc, seen, before, ans, adv>>

\* The zone moves to s: every query in progress has now seen it.
SetSerial(s) ==
    /\ serial' = s
    /\ history' = history \cup {s}
    /\ changes' = changes + 1
    /\ seen' = [q \in Q |-> IF pc[q] \in Active THEN seen[q] \cup {s} ELSE seen[q]]
    /\ UNCHANGED <<cache, pc, before, ans, adv>>

\* A reload with a greater serial (file only reloads on a greater one).
Advance == changes < MaxChanges /\ SetSerial(serial + 1)

\* An operator rolls the zone back to a serial it had before.
RollBack ==
    /\ Rollback /\ changes < MaxChanges
    /\ \E s \in history \ {serial} : SetSerial(s)

Finished ==
    /\ \A q \in Q : pc[q] = "done"
    /\ UNCHANGED vars

Next ==
    \/ \E q \in Q : Start(q) \/ PreCache(q) \/ PreLookup(q) \/ Main(q) \/ Post(q)
    \/ Expire \/ Advance \/ RollBack \/ Finished

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------

TypeOK ==
    /\ serial \in history
    /\ cache = None \/ cache \in history
    /\ \A q \in Q : adv[q] = None \/ adv[q] \in history

\* G1: never invented, never from before the query began.
DuringQuery == \A q \in Q : adv[q] # None => adv[q] \in seen[q]

\* G2: the version advertised is the version that answered.
AnswerConsistent == \A q \in Q : adv[q] # None => adv[q] = ans[q]

\* The cache never runs ahead of the zone while serials only advance: the
\* lemma the bracket's soundness rests on.
CacheNotAhead == ~Rollback => (cache = None \/ cache <= serial)

-----------------------------------------------------------------------------

\* Inductive invariant for Apalache (tla/inductive/ZoneVersionSerial_*.cfg),
\* for the plugin as built (Bracket, no Rollback; with or without the cache).
\* It covers every reachable state of instances far larger than TLC's.
\*
\* Why the bracket is sound, in one line: while serials only advance,
\* before[q] <= ans[q] <= serial, so before[q] = serial at Post forces
\* ans[q] = serial. A rollback breaks the first inequality, a missing
\* bracket drops the test; inductive/ has both as negative controls.
MaxSerial == 1 + MaxChanges

IndInv ==
    /\ changes \in 0..MaxChanges
    /\ serial = 1 + changes
    /\ history \in SUBSET (1..MaxSerial)
    /\ \A i \in 1..MaxSerial : i \in history <=> i <= serial
    /\ cache \in 0..MaxSerial
    /\ cache <= serial
    /\ pc \in [Q -> {"idle", "pre", "main", "post", "done"}]
    /\ seen \in [Q -> SUBSET (1..MaxSerial)]
    /\ before \in [Q -> 0..MaxSerial]
    /\ ans \in [Q -> 0..MaxSerial]
    /\ adv \in [Q -> 0..MaxSerial]
    /\ \A q \in Q :
         /\ seen[q] \subseteq history
         /\ pc[q] \in Active => serial \in seen[q]
         /\ pc[q] \in {"main", "post"} => before[q] >= 1 /\ before[q] <= serial
         /\ pc[q] = "post" =>
              /\ ans[q] \in seen[q]
              /\ before[q] <= ans[q]
              /\ ans[q] <= serial
         /\ pc[q] # "done" => adv[q] = None
         /\ adv[q] # None => adv[q] \in seen[q] /\ adv[q] = ans[q]

\* G1 alone needs no assumption: this one holds with rollbacks and without
\* the bracket (inductive/ZoneVersionSerial_RollbackDuringQuery.cfg).
IndInvG1 ==
    /\ changes \in 0..MaxChanges
    /\ serial \in 1..MaxSerial
    /\ serial <= 1 + changes
    /\ history \in SUBSET (1..MaxSerial)
    /\ serial \in history
    /\ \A h \in history : h <= 1 + changes
    /\ cache \in 0..MaxSerial
    /\ cache = None \/ cache \in history
    /\ pc \in [Q -> {"idle", "pre", "main", "post", "done"}]
    /\ seen \in [Q -> SUBSET (1..MaxSerial)]
    /\ before \in [Q -> 0..MaxSerial]
    /\ ans \in [Q -> 0..MaxSerial]
    /\ adv \in [Q -> 0..MaxSerial]
    /\ \A q \in Q :
         /\ seen[q] \subseteq history
         /\ pc[q] \in Active => serial \in seen[q]
         /\ pc[q] # "done" => adv[q] = None
         /\ adv[q] # None => adv[q] \in seen[q]

=============================================================================

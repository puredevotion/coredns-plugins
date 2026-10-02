--------------------------- MODULE PluginLifecycle ---------------------------
(***************************************************************************)
(* How caddy (github.com/coredns/caddy v1.1.4, caddy.go) drives the        *)
(* lifecycle callbacks of a plugin that owns a background goroutine, and   *)
(* whether that goroutine can outlive its owner.                           *)
(*                                                                         *)
(* Both background-goroutine plugins here register the same four hooks:    *)
(*                                                                         *)
(*   sni_tls (setup.go)            radnr (setup.go)                        *)
(*   OnStartup       live.OnStartup     r.OnStartup     -- start goroutine *)
(*   OnRestart       live.OnShutdown    r.OnShutdown    -- cancel it       *)
(*   OnFinalShutdown live.OnShutdown    r.OnShutdown                       *)
(*   OnRestartFailed live.OnStartup     r.OnStartup     -- start again     *)
(*                                                                         *)
(* In v0.4.1 OnStartup was `ctx, cancel := ...; p.cancel = cancel;        *)
(* go run(ctx)`, overwriting p.cancel without looking at it.              *)
(*                                                                         *)
(* The caddy contract this models, from Instance.Restart and               *)
(* startWithListenerFds:                                                   *)
(*                                                                         *)
(*   1. run the old instance's OnRestart callbacks IN ORDER; the first     *)
(*      error aborts the restart and, via a deferred func, runs the old    *)
(*      instance's OnRestartFailed callbacks -- ALL of them, including     *)
(*      for plugins whose OnRestart never ran;                             *)
(*   2. build the new instance and run its OnStartup callbacks in order;   *)
(*      an error aborts;                                                   *)
(*   3. start its servers (bind sockets); an error aborts;                 *)
(*   4. on an abort in 2 or 3, the new instance is simply dropped: none of *)
(*      its shutdown callbacks run; the old instance gets OnRestartFailed; *)
(*   5. on success the old instance stops and the new one is live.         *)
(*                                                                         *)
(* "X" stands for any other plugin in the same Corefile whose callbacks    *)
(* can fail (one that binds a port in OnStartup, or returns an error from  *)
(* OnRestart). XFirst says whether it registered before ours.             *)
(*                                                                         *)
(* Variant picks the plugin's OnStartup:                                   *)
(*   "original"   -- v0.4.1: overwrite cancel, start a goroutine;          *)
(*   "idempotent" -- now: cancel what this instance already runs, first;   *)
(*   "registry"   -- now: also stop every goroutine a DIFFERENT instance   *)
(*                   started (the process-wide registry in radnr.go and    *)
(*                   reload.go), so OnRestartFailed reclaims what an       *)
(*                   instance caddy dropped without telling it left behind.*)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    \* @type: Int;
    MaxRestarts,  \* bound on reloads explored
    \* @type: Bool;
    XFirst,       \* the failing plugin's callbacks run before ours
    \* @type: Str;
    Variant       \* "original" | "idempotent" | "registry"

MaxInst == MaxRestarts + 1
Insts   == 1..MaxInst
\* Each instance can start at most two goroutines (OnStartup, then
\* OnRestartFailed), so ids are drawn from a bounded pool.
Gs      == 1..(2 * MaxInst)

VARIABLES
    \* @type: Int;
    live,      \* the instance caddy is serving with
    \* @type: Int;
    nInst,     \* instances created so far
    \* @type: Int -> Int;
    cancel,    \* cancel[i]: goroutine instance i's plugin can cancel, or 0
    \* @type: Set(Int);
    running,   \* goroutines that are running
    \* @type: Int -> Int;
    owner,     \* owner[g]: instance whose OnStartup started g
    \* @type: Int;
    nextG,     \* next unused goroutine id
    \* @type: Int;
    restarts,  \* reloads attempted
    \* @type: Str;
    phase      \* "serving" | "done"

vars == <<live, nInst, cancel, running, owner, nextG, restarts, phase>>

TypeOK ==
    /\ live \in Insts /\ nInst \in Insts
    /\ cancel \in [Insts -> Gs \cup {0}]
    /\ running \subseteq Gs
    /\ owner \in [Gs -> Insts \cup {0}]
    /\ nextG \in 1..(2 * MaxInst + 1)
    /\ restarts \in 0..MaxRestarts
    /\ phase \in {"serving", "done"}

-----------------------------------------------------------------------------
(* The plugin's callbacks, as state transformers on                        *)
(* s = [cancel, running, owner, nextG].                                   *)

\* The plugin-visible state, as one record. (Apalache type alias.)
\* @typeAlias: st = { cancel: Int -> Int, running: Set(Int), owner: Int -> Int, nextG: Int };
PluginLifecycle_typedefs == TRUE

\* @type: ($st, Int) => $st;
Stop(s, g) == [s EXCEPT !.running = @ \ {g}]

\* @type: ($st, Int) => $st;
OnStartup(s, i) ==
    LET g  == s.nextG
        s1 == IF Variant # "original" /\ s.cancel[i] # 0
                THEN Stop(s, s.cancel[i]) ELSE s
        \* registry: for h := range registry { if h.owner != r.owner ... }
        s2 == IF Variant = "registry"
                THEN [s1 EXCEPT !.running = {x \in @ : s1.owner[x] = i}]
                ELSE s1
    IN [s2 EXCEPT !.cancel  = [@ EXCEPT ![i] = g],
                  !.running = @ \cup {g},
                  !.owner   = [@ EXCEPT ![g] = i],
                  !.nextG   = @ + 1]

\* @type: ($st, Int) => $st;
OnShutdown(s, i) ==
    IF s.cancel[i] = 0 THEN s
    ELSE LET g == s.cancel[i] IN
         [Stop(s, g) EXCEPT !.cancel = [@ EXCEPT ![i] = 0]]

St == [cancel |-> cancel, running |-> running, owner |-> owner, nextG |-> nextG]

\* @type: ($st) => Bool;
SetSt(s) ==
    /\ cancel' = s.cancel /\ running' = s.running /\ owner' = s.owner
    /\ nextG' = s.nextG

-----------------------------------------------------------------------------
(* caddy. A restart is sequential on one goroutine and nothing observes    *)
(* the plugin halfway through it, so each outcome is one atomic step.      *)

Empty == [cancel |-> [i \in Insts |-> 0], running |-> {},
          owner |-> [g \in Gs |-> 0], nextG |-> 1]

\* First startup. Any failure there exits the process, so only success is
\* interesting.
Init ==
    LET s == OnStartup(Empty, 1) IN
    /\ live = 1 /\ nInst = 1
    /\ cancel = s.cancel /\ running = s.running /\ owner = s.owner
    /\ nextG = s.nextG
    /\ restarts = 0 /\ phase = "serving"

CanRestart == phase = "serving" /\ restarts < MaxRestarts

Bump == restarts' = restarts + 1 /\ UNCHANGED phase

\* Every callback succeeds.
RestartOK ==
    /\ CanRestart
    /\ LET n  == nInst + 1
           s1 == OnShutdown(St, live)   \* old OnRestart
           s2 == OnStartup(s1, n)       \* new OnStartup
       IN /\ SetSt(s2) /\ live' = n /\ nInst' = n
    /\ Bump

\* X's OnRestart returns an error. If X runs first, ours never ran; either
\* way caddy runs our OnRestartFailed (= OnStartup) on the old instance.
FailXOnRestart ==
    /\ CanRestart
    /\ LET s1 == IF XFirst THEN St ELSE OnShutdown(St, live)
           s2 == OnStartup(s1, live)
       IN SetSt(s2)
    /\ UNCHANGED <<live, nInst>>
    /\ Bump

\* X's OnStartup in the NEW instance returns an error. If ours ran first,
\* its goroutine was already started on an instance caddy now drops.
FailXOnStartup ==
    /\ CanRestart
    /\ LET n  == nInst + 1
           s1 == OnShutdown(St, live)
           s2 == IF XFirst THEN s1 ELSE OnStartup(s1, n)
           s3 == OnStartup(s2, live)    \* old OnRestartFailed
       IN SetSt(s3) /\ nInst' = n
    /\ UNCHANGED live
    /\ Bump

\* Every OnStartup succeeded but startServers failed (e.g. the new
\* Corefile's listen address is already in use).
FailStartServers ==
    /\ CanRestart
    /\ LET n  == nInst + 1
           s1 == OnShutdown(St, live)
           s2 == OnStartup(s1, n)
           s3 == OnStartup(s2, live)
       IN SetSt(s3) /\ nInst' = n
    /\ UNCHANGED live
    /\ Bump

\* Process exit: ShutdownCallbacks runs OnShutdown and OnFinalShutdown.
FinalShutdown ==
    /\ phase = "serving"
    /\ SetSt(OnShutdown(St, live))
    /\ phase' = "done"
    /\ UNCHANGED <<live, nInst, restarts>>

\* The process has exited; nothing further happens.
Exited == phase = "done" /\ UNCHANGED vars

Next ==
    \/ RestartOK \/ FailXOnRestart \/ FailXOnStartup \/ FailStartServers
    \/ FinalShutdown \/ Exited

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* Properties.                                                             *)

\* Every running goroutine is the one the LIVE instance will cancel on its
\* next OnRestart or OnFinalShutdown. A goroutine whose cancel func was
\* overwritten, or that belongs to an instance caddy dropped, is an orphan:
\* nothing will ever stop it before the process exits.
NoOrphans ==
    \A g \in running : owner[g] = live /\ cancel[live] = g

\* At most one goroutine per instance. Two sni_tls pollers on one liveStore
\* is the precondition for SniTlsReload_TwoLoops.cfg's stuck certificate.
OnePerInstance ==
    \A i \in Insts : Cardinality({g \in running : owner[g] = i}) <= 1

\* At most one goroutine in the process. For radnr this is the property
\* that matters on the wire: each goroutine is an advertiser holding its own
\* raw ICMPv6 socket and sending RAs, possibly from an older Corefile.
OneInProcess == Cardinality(running) <= 1

\* Nothing survives final shutdown.
CleanShutdown == phase = "done" => running = {}

-----------------------------------------------------------------------------
(* Inductive invariant for the "registry" variant, checked by Apalache in  *)
(* inductive/ for many more restarts than TLC explores: while serving,     *)
(* exactly one goroutine runs, the live instance started it, and the live  *)
(* instance holds its cancel func.                                         *)

IndInv ==
    /\ live \in Insts /\ nInst \in Insts
    /\ cancel \in [Insts -> Gs \cup {0}]
    /\ running \in SUBSET Gs
    /\ owner \in [Gs -> Insts \cup {0}]
    /\ nextG \in 1..(2 * MaxInst + 1)
    /\ restarts \in 0..MaxRestarts
    /\ phase \in {"serving", "done"}
    \* Fresh ids: instances and goroutines are numbered in creation order.
    /\ live <= nInst /\ nInst <= restarts + 1
    /\ nextG <= 2 + 2 * restarts
    /\ phase = "serving" =>
         /\ cancel[live] # 0 /\ cancel[live] < nextG
         /\ running = {cancel[live]}
         /\ owner[cancel[live]] = live
    /\ phase = "done" => running = {}

=============================================================================

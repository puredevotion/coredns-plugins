------------------------- MODULE DynUpdateAtomicity -------------------------
(***************************************************************************)
(* RFC 2136 §3.4.2.1 atomicity in dynupdate (update.go, dynupdate.go)      *)
(* when the zone rebuild fails.                                            *)
(*                                                                         *)
(* serveUpdate in v0.4.1, under d.mu.Lock():                              *)
(*                                                                         *)
(*   out := append(make([]dns.RR, 0, n), d.rrs...)  -- copies the SLICE;   *)
(*                                                     the RRs are shared  *)
(*   out[i].Header().Ttl = h.Ttl                      -- applyAdd refresh  *)
(*   bumpSerial(updated)                              -- soa.Serial++      *)
(*   if err := d.swap(updated); err != nil {          -- file.Zone.Insert  *)
(*       return SERVFAIL                                 rejected a record *)
(*   }                                                                     *)
(*                                                                         *)
(* d.rrs is "the source of truth"; d.view is what queries and AXFR see.    *)
(* An RR is modelled as a heap cell holding the two fields the update      *)
(* path writes in place (TTL, serial); d.rrs and d.view hold references    *)
(* and snapshots respectively, as they do in Go (build() inserts           *)
(* dns.Copy(rr), so the view never aliases d.rrs).                         *)
(*                                                                         *)
(* DeepCopy = TRUE models the repair dynupdate now carries: applyAdd and  *)
(* bumpSerial copy a record before writing to it.                         *)
(***************************************************************************)
EXTENDS Naturals, Sequences

CONSTANTS
    \* @type: Int;
    MaxUpdates,  \* bound on UPDATE messages explored
    \* @type: Bool;
    DeepCopy

Addrs == 1..(2 * (MaxUpdates + 1))
TTLs  == {300, 60}

VARIABLES
    \* @type: Int -> { ttl: Int, serial: Int };
    heap,      \* heap[a]: [ttl, serial] of the RR at address a
    \* @type: Int;
    nextAddr,  \* allocator
    \* @type: Int -> Int;
    rrs,       \* d.rrs: soa at 1, www at 2, as addresses
    \* @type: Int -> { ttl: Int, serial: Int };
    view,      \* d.view: the served snapshot
    \* @type: Int -> { ttl: Int, serial: Int };
    committed, \* ghost: the record contents as of the last successful swap
    \* @type: Int -> Int;
    out,       \* the working copy while an UPDATE is in progress
    \* @type: Str;
    pc,        \* "idle" | "applied" | "bumped"
    \* @type: Int;
    done       \* UPDATEs handled

vars == <<heap, nextAddr, rrs, view, committed, out, pc, done>>

Cell(t, s) == [ttl |-> t, serial |-> s]

\* Two records, so each slice is a function on 1..2 (a tuple, to TLC).
Pair(a, b) == [i \in 1..2 |-> IF i = 1 THEN a ELSE b]
NoRefs == Pair(0, 0)

\* @type: (Int -> Int) => (Int -> { ttl: Int, serial: Int });
Content(refs) == [i \in DOMAIN refs |-> heap[refs[i]]]

Init ==
    /\ heap = [a \in Addrs |-> IF a = 1 THEN Cell(300, 100)
                               ELSE IF a = 2 THEN Cell(300, 0)
                               ELSE Cell(0, 0)]
    /\ nextAddr = 3
    /\ rrs = Pair(1, 2)
    /\ view = Pair(Cell(300, 100), Cell(300, 0))
    /\ committed = view
    /\ out = NoRefs
    /\ pc = "idle"
    /\ done = 0

\* applyAdd: www re-added with a different TTL, so its TTL is refreshed in
\* place. With DeepCopy the two records are first copied to fresh cells.
Apply(newTTL) ==
    /\ pc = "idle" /\ done < MaxUpdates
    /\ newTTL # heap[rrs[2]].ttl
    /\ IF DeepCopy
         THEN LET s == nextAddr
                  w == nextAddr + 1
              IN /\ heap' = [heap EXCEPT ![s] = heap[rrs[1]],
                                         ![w] = [heap[rrs[2]] EXCEPT !.ttl = newTTL]]
                 /\ out' = Pair(s, w)
                 /\ nextAddr' = nextAddr + 2
         ELSE /\ heap' = [heap EXCEPT ![rrs[2]].ttl = newTTL]
              /\ out' = rrs
              /\ UNCHANGED nextAddr
    /\ pc' = "applied"
    /\ UNCHANGED <<rrs, view, committed, done>>

\* changed == true, so bumpSerial(updated).
Bump ==
    /\ pc = "applied"
    /\ heap' = [heap EXCEPT ![out[1]].serial = @ + 1]
    /\ pc' = "bumped"
    /\ UNCHANGED <<nextAddr, rrs, view, committed, out, done>>

\* d.swap(updated): the rebuild either succeeds and installs out, or fails
\* (an update section carrying a record file.Zone.Insert rejects, e.g. an
\* NSEC3 when `mutable` is unset) and the client gets SERVFAIL.
SwapOK ==
    /\ pc = "bumped"
    /\ rrs' = out
    /\ view' = Content(out)
    /\ committed' = Content(out)
    /\ out' = NoRefs /\ pc' = "idle" /\ done' = done + 1
    /\ UNCHANGED <<heap, nextAddr>>

SwapFails ==
    /\ pc = "bumped"
    /\ out' = NoRefs /\ pc' = "idle" /\ done' = done + 1
    /\ UNCHANGED <<heap, nextAddr, rrs, view, committed>>

Finished == done = MaxUpdates /\ pc = "idle" /\ UNCHANGED vars

Next == (\E t \in TTLs : Apply(t)) \/ Bump \/ SwapOK \/ SwapFails \/ Finished

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------

\* An UPDATE answered SERVFAIL left the zone exactly as it was. (RFC 2136
\* §3.4.2.1: either all of an update lands, or none of it.)
FailedUpdateChangesNothing == pc = "idle" => Content(rrs) = committed

\* Between UPDATEs, the records prerequisites are checked against are the
\* records being served. Otherwise a later UPDATE's prerequisites and serial
\* are computed from data no client has ever seen.
RecordsMatchView == pc = "idle" => Content(rrs) = view

-----------------------------------------------------------------------------
(* Inductive invariant (DeepCopy = TRUE), checked by Apalache in           *)
(* inductive/ for many more UPDATEs than TLC explores. The argument: the   *)
(* working copy lives at the two most recently allocated addresses, and    *)
(* d.rrs only ever points below them, so nothing an UPDATE writes before   *)
(* its swap can reach the records d.rrs or the view hold.                  *)

IndInv ==
    /\ heap \in [Addrs -> [ttl: TTLs \cup {0}, serial: 0..(100 + MaxUpdates)]]
    /\ rrs \in [1..2 -> Addrs]
    /\ out \in [1..2 -> Addrs \cup {0}]
    /\ pc \in {"idle", "applied", "bumped"}
    /\ done \in 0..MaxUpdates
    /\ nextAddr = 3 + 2 * done + (IF pc = "idle" THEN 0 ELSE 2)
    /\ committed = Content(rrs)
    /\ view = committed
    /\ pc = "idle" =>
         /\ out = NoRefs
         /\ rrs[1] < nextAddr /\ rrs[2] < nextAddr
    /\ pc # "idle" =>
         /\ done < MaxUpdates
         /\ out = Pair(nextAddr - 2, nextAddr - 1)
         /\ rrs[1] < nextAddr - 2 /\ rrs[2] < nextAddr - 2
    \* Serials stay inside the range the heap is typed over.
    /\ heap[rrs[1]].serial <= 100 + done
    /\ pc = "applied" => heap[out[1]].serial <= 100 + done
    /\ pc = "bumped" => heap[out[1]].serial <= 101 + done

=============================================================================

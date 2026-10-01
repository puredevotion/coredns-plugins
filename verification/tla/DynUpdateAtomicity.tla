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
    MaxUpdates,  \* bound on UPDATE messages explored
    DeepCopy

Addrs == 1..(2 * (MaxUpdates + 1))
TTLs  == {300, 60}

VARIABLES
    heap,      \* heap[a]: [ttl, serial] of the RR at address a
    nextAddr,  \* allocator
    rrs,       \* d.rrs: <<soa, www>> as addresses
    view,      \* d.view: the served snapshot
    committed, \* ghost: the record contents as of the last successful swap
    out,       \* the working copy while an UPDATE is in progress
    pc,        \* "idle" | "applied" | "bumped"
    done       \* UPDATEs handled

vars == <<heap, nextAddr, rrs, view, committed, out, pc, done>>

Cell(t, s) == [ttl |-> t, serial |-> s]

Content(seq) == [i \in DOMAIN seq |-> heap[seq[i]]]

Init ==
    /\ heap = [a \in Addrs |-> IF a = 1 THEN Cell(300, 100)
                               ELSE IF a = 2 THEN Cell(300, 0)
                               ELSE Cell(0, 0)]
    /\ nextAddr = 3
    /\ rrs = <<1, 2>>
    /\ view = <<Cell(300, 100), Cell(300, 0)>>
    /\ committed = view
    /\ out = <<>>
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
                 /\ out' = <<s, w>>
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
    /\ out' = <<>> /\ pc' = "idle" /\ done' = done + 1
    /\ UNCHANGED <<heap, nextAddr>>

SwapFails ==
    /\ pc = "bumped"
    /\ out' = <<>> /\ pc' = "idle" /\ done' = done + 1
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

=============================================================================

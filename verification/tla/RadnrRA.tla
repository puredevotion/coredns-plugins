------------------------------ MODULE RadnrRA ------------------------------
(***************************************************************************)
(* The radnr advertiser's send scheduling (radnr/internal/advertiser,      *)
(* Advertiser.Run) against the RFC 4861 timing rules it cites.             *)
(*                                                                         *)
(* In v0.4.1, Run sent once at start, then selected on:                    *)
(*   t.C   -- periodic timer, re-armed to nextInterval() in [Min, Max]:    *)
(*            send() unconditionally;                                      *)
(*   rs    -- a Router Solicitation: if time.Since(lastSent) < MinDelay    *)
(*            the RS is dropped, otherwise send().                         *)
(*                                                                         *)
(* RFC 4861 §6.2.6: "consecutive Router Advertisements sent to the         *)
(* all-nodes multicast address MUST be rate limited to no more than one    *)
(* advertisement every MIN_DELAY_BETWEEN_RAS seconds", and an RS arriving  *)
(* inside that window is to be answered by scheduling the RA for           *)
(* MIN_DELAY_BETWEEN_RAS after the previous one -- not dropped.            *)
(*                                                                         *)
(* Time is discrete (one tick = one second at the model's scale). The      *)
(* random MAX_RA_DELAY_TIME jitter is not modelled: it only ever delays a  *)
(* send, so it cannot repair a gap that is already too short.              *)
(*                                                                         *)
(* Fixed = TRUE models Run now: a timer firing inside the window is       *)
(* pushed to lastSent + MinDelay, and an RS inside the window pulls the    *)
(* timer in to the same instant instead of being discarded.                *)
(***************************************************************************)
EXTENDS Naturals

CONSTANTS
    MinDelay,     \* MIN_DELAY_BETWEEN_RAS (3s)
    MinInterval,  \* nextInterval() lower bound
    MaxInterval,  \* nextInterval() upper bound (a.Interval)
    Horizon,      \* how far time is explored
    Fixed

ASSUME MinInterval >= MinDelay /\ MaxInterval >= MinInterval

NoRS == Horizon + MaxInterval + MinDelay + 1  \* "no RS outstanding"

VARIABLES
    now,       \* current time
    lastSent,  \* time of the previous RA
    timerAt,   \* when the periodic timer fires
    pendingRS, \* arrival time of the oldest unanswered RS, or NoRS
    gapOK      \* history: every pair of consecutive RAs was >= MinDelay apart

vars == <<now, lastSent, timerAt, pendingRS, gapOK>>

Intervals == MinInterval..MaxInterval
Min(a, b) == IF a < b THEN a ELSE b

Init ==
    /\ now = 0 /\ lastSent = 0          \* send() // Initial advertisement.
    /\ timerAt \in Intervals
    /\ pendingRS = NoRS
    /\ gapOK = TRUE

\* send() at the current instant: record the gap, answer any waiting RS.
Send ==
    /\ lastSent' = now
    /\ gapOK' = (gapOK /\ now - lastSent >= MinDelay)
    /\ pendingRS' = NoRS

TimerFires ==
    /\ now = timerAt
    /\ IF Fixed /\ now - lastSent < MinDelay
         THEN /\ timerAt' = lastSent + MinDelay
              /\ UNCHANGED <<lastSent, pendingRS, gapOK>>
         ELSE /\ Send
              /\ \E d \in Intervals : timerAt' = now + d
    /\ UNCHANGED now

RSArrives ==
    /\ IF now - lastSent >= MinDelay
         THEN Send /\ UNCHANGED timerAt
         ELSE /\ pendingRS' = Min(pendingRS, now)
              /\ timerAt' = IF Fixed THEN Min(timerAt, lastSent + MinDelay)
                                     ELSE timerAt
              /\ UNCHANGED <<lastSent, gapOK>>
    /\ UNCHANGED now

\* Time only passes once a due timer has been handled.
Tick ==
    /\ now < Horizon /\ now < timerAt
    /\ now' = now + 1
    /\ UNCHANGED <<lastSent, timerAt, pendingRS, gapOK>>

Done == now = Horizon /\ UNCHANGED vars

Next == TimerFires \/ RSArrives \/ Tick \/ Done

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* Properties.                                                             *)

\* RFC 4861 §6.2.6 rate limit, and what the Run doc comment promises
\* ("rate-limited to at most one send per minDelayBetweenRAs regardless of
\* trigger").
MinGapBetweenRAs == gapOK

\* RFC 4861 §6.2.6: an RS is answered no later than MinDelay after the RA
\* that made it wait. (A dropped RS waits for the periodic timer instead --
\* up to MaxInterval, or until the host's own RS retransmission.)
SolicitationAnswered == now - pendingRS <= MinDelay

\* Sanity: the model can actually reach a send from each trigger.
TypeOK ==
    /\ now \in 0..Horizon
    /\ lastSent \in 0..Horizon
    /\ timerAt \in 0..(Horizon + MaxInterval)
    /\ gapOK \in BOOLEAN

=============================================================================

------------------------------ MODULE RadnrRA ------------------------------
(***************************************************************************)
(* The radnr advertiser's send scheduling (radnr/internal/advertiser,      *)
(* Advertiser.Run) against the rules of RFC 4861 §6.2.4 and §6.2.6.        *)
(*                                                                         *)
(* RFC 4861 §6.2.6, the MUSTs checked here:                                *)
(*                                                                         *)
(*   "Router Advertisements sent in response to a Router Solicitation MUST *)
(*    be delayed by a random time between 0 and MAX_RA_DELAY_TIME          *)
(*    seconds. ... In addition, consecutive Router Advertisements sent to  *)
(*    the all-nodes multicast address MUST be rate limited to no more than *)
(*    one advertisement every MIN_DELAY_BETWEEN_RAS seconds."              *)
(*                                                                         *)
(*   "In all cases, however, unsolicited multicast advertisements MUST NOT *)
(*    be sent more frequently than indicated by MinRtrAdvInterval."        *)
(*                                                                         *)
(* and the procedure it gives for meeting them: answer an RS after its     *)
(* random delay, or "MIN_DELAY_BETWEEN_RAS plus the random value after the *)
(* previous advertisement" if one was sent within the window, or at the    *)
(* already-scheduled multicast RA if that comes first; and after a         *)
(* multicast response "the interface's interval timer is reset to a new    *)
(* random value, as if an unsolicited advertisement had just been sent".   *)
(*                                                                         *)
(* Time is discrete; one tick is MAX_RA_DELAY_TIME (0.5s), the smallest     *)
(* constant involved. The random choices (the §6.2.4 interval, the §6.2.6  *)
(* delay) are nondeterministic, so every possible draw is checked.         *)
(*                                                                         *)
(* Fixed selects the scheduler:                                            *)
(*   FALSE -- v0.4.1: the timer sends unconditionally and re-arms; an RS   *)
(*            gets an immediate RA if MIN_DELAY_BETWEEN_RAS has passed     *)
(*            (no random delay, timer left alone), and is dropped if not;  *)
(*   TRUE  -- current: every RA goes out when the interval timer fires; an *)
(*            RS only moves the timer in, per the §6.2.6 procedure.        *)
(***************************************************************************)
EXTENDS Naturals

CONSTANTS
    \* @type: Int;
    MinDelay,     \* MIN_DELAY_BETWEEN_RAS, in ticks
    \* @type: Int;
    MaxRADelay,   \* MAX_RA_DELAY_TIME, in ticks
    \* @type: Int;
    MinInterval,  \* MinRtrAdvInterval: nextInterval() lower bound, in ticks
    \* @type: Int;
    MaxInterval,  \* MaxRtrAdvInterval: nextInterval() upper bound, in ticks
    \* @type: Int;
    Horizon,      \* how far time is explored, in ticks
    \* @type: Bool;
    Fixed

\* RFC 4861 §6.2.1: "MinRtrAdvInterval ... MUST be no less than 3 seconds",
\* which is MIN_DELAY_BETWEEN_RAS.
ASSUME MinInterval >= MinDelay /\ MaxInterval >= MinInterval /\ MaxRADelay >= 0

NoRS == Horizon + MaxInterval + MinDelay + MaxRADelay + 1  \* "no RS waiting"

VARIABLES
    \* @type: Int;
    now,       \* current time
    \* @type: Int;
    lastSent,  \* time of the previous RA
    \* @type: Int;
    timerAt,   \* when the interval timer fires
    \* @type: Int;
    pendingRS, \* arrival time of the oldest unanswered RS, or NoRS
    \* @type: Bool;
    gapOK,     \* history: consecutive RAs were always >= MinDelay apart
    \* @type: Bool;
    unsolOK    \* history: unsolicited RAs were always >= MinInterval after the previous RA

vars == <<now, lastSent, timerAt, pendingRS, gapOK, unsolOK>>

Intervals == MinInterval..MaxInterval
Delays    == 0..MaxRADelay
Min(a, b) == IF a < b THEN a ELSE b
Max(a, b) == IF a > b THEN a ELSE b

Init ==
    /\ now = 0 /\ lastSent = 0          \* send() // Initial advertisement.
    /\ timerAt \in Intervals
    /\ pendingRS = NoRS
    /\ gapOK = TRUE
    /\ unsolOK = TRUE

\* send() at the current instant. It answers every waiting RS; it is
\* unsolicited if none was waiting.
Send ==
    /\ lastSent' = now
    /\ gapOK' = (gapOK /\ now - lastSent >= MinDelay)
    /\ unsolOK' = (unsolOK /\ (pendingRS = NoRS => now - lastSent >= MinInterval))
    /\ pendingRS' = NoRS

TimerFires ==
    /\ now = timerAt
    /\ IF Fixed /\ now - lastSent < MinDelay
         THEN /\ timerAt' = lastSent + MinDelay   \* held: wait out the window
              /\ UNCHANGED <<lastSent, pendingRS, gapOK, unsolOK>>
         ELSE /\ Send
              /\ \E d \in Intervals : timerAt' = now + d
    /\ UNCHANGED now

RSArrives ==
    /\ IF Fixed
         THEN \E delay \in Delays :
                LET at == IF now - lastSent < MinDelay
                            THEN lastSent + MinDelay + delay
                            ELSE now + delay
                IN /\ timerAt' = Min(timerAt, at)
                   /\ pendingRS' = Min(pendingRS, now)
                   /\ UNCHANGED <<lastSent, gapOK, unsolOK>>
         ELSE IF now - lastSent >= MinDelay
                THEN /\ lastSent' = now                  \* answered at once
                     /\ gapOK' = (gapOK /\ now - lastSent >= MinDelay)
                     /\ pendingRS' = NoRS
                     /\ UNCHANGED <<timerAt, unsolOK>>
                ELSE /\ pendingRS' = Min(pendingRS, now)         \* dropped
                     /\ UNCHANGED <<lastSent, timerAt, gapOK, unsolOK>>
    /\ UNCHANGED now

\* Time only passes once a due timer has been handled.
Tick ==
    /\ now < Horizon /\ now < timerAt
    /\ now' = now + 1
    /\ UNCHANGED <<lastSent, timerAt, pendingRS, gapOK, unsolOK>>

Done == now = Horizon /\ UNCHANGED vars

Next == TimerFires \/ RSArrives \/ Tick \/ Done

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* Properties.                                                             *)

\* §6.2.6: "consecutive Router Advertisements sent to the all-nodes
\* multicast address MUST be rate limited to no more than one advertisement
\* every MIN_DELAY_BETWEEN_RAS seconds". Checked for every RA, multicast or
\* not, which is stricter than the RFC.
MinGapBetweenRAs == gapOK

\* §6.2.6: "unsolicited multicast advertisements MUST NOT be sent more
\* frequently than indicated by MinRtrAdvInterval". With the timer reset
\* after every multicast RA ("as if an unsolicited advertisement had just
\* been sent"), an unsolicited RA is never sooner than MinInterval after any
\* RA at all.
UnsolicitedNotTooFrequent == unsolOK

\* §6.2.6: a solicitation is answered by the procedure's deadline: its
\* random delay after it arrives, or after the rate-limit window if it
\* arrived inside one, whichever is later. (The already-scheduled RA can
\* only make the answer earlier.) In v0.4.1 a solicitation inside the window
\* is dropped and waits for the next periodic RA.
SolicitationAnswered ==
    pendingRS = NoRS \/ now <= Max(pendingRS, lastSent + MinDelay) + MaxRADelay

TypeOK ==
    /\ now \in 0..Horizon
    /\ lastSent \in 0..Horizon
    /\ timerAt \in 0..(Horizon + MaxInterval)
    /\ gapOK \in BOOLEAN
    /\ unsolOK \in BOOLEAN

-----------------------------------------------------------------------------
(* Inductive invariant (Fixed = TRUE), checked by Apalache in              *)
(* inductive/: it holds initially, every step preserves it, and it implies *)
(* the properties above, so they hold in every reachable state of the      *)
(* instance checked, which can be far too large for TLC to enumerate.      *)
(*                                                                         *)
(* The argument: the timer is never earlier than MinDelay after the last   *)
(* RA, and never earlier than MinInterval after it unless an RS moved it   *)
(* in; it is never later than MaxInterval after it, nor, while an RS       *)
(* waits, later than that RS's §6.2.6 deadline.                            *)

IndInv ==
    /\ now \in Nat /\ lastSent \in Nat /\ timerAt \in Nat /\ pendingRS \in Nat
    /\ gapOK \in BOOLEAN /\ unsolOK \in BOOLEAN
    /\ gapOK /\ unsolOK
    /\ now <= Horizon
    /\ lastSent <= now
    /\ now <= timerAt
    /\ timerAt <= lastSent + MaxInterval
    /\ timerAt >= lastSent + MinDelay
    /\ pendingRS = NoRS => timerAt >= lastSent + MinInterval
    /\ pendingRS # NoRS =>
         /\ lastSent <= pendingRS /\ pendingRS <= now
         /\ timerAt <= Max(pendingRS, lastSent + MinDelay) + MaxRADelay

=============================================================================

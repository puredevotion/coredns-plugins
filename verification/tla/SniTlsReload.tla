---------------------------- MODULE SniTlsReload ----------------------------
(***************************************************************************)
(* The sni_tls certificate poller (sni_tls/reload.go) racing an operator   *)
(* who rotates the cert/key files underneath it.                           *)
(*                                                                         *)
(* What the Go code does, one step per atomic read or write:               *)
(*                                                                         *)
(*   reloadOnce:                                                           *)
(*     newDigest := digestPairs(pairs)     -- reads cert file, then key    *)
(*     if newDigest == *digest.Load() { return }                           *)
(*     store, err := buildCertStore(...)   -- reads cert file, then key    *)
(*     if err != nil { return }            -- e.g. cert/key mismatch       *)
(*     current.Store(store)                -- two SEPARATE atomic stores   *)
(*     digest.Store(&newDigest)                                            *)
(*                                                                         *)
(* A file "version" stands for its content. A cert and key only form a     *)
(* loadable pair when both are at the same version; anything else is the  *)
(* mid-rotation state tls.LoadX509KeyPair rejects. The digest is modelled  *)
(* as the exact pair of versions it hashed (an idealised, collision-free   *)
(* SHA-256).                                                               *)
(*                                                                         *)
(* Loops is the set of poll goroutines writing the SAME liveStore. The Go  *)
(* code assumes exactly one; PluginLifecycle.tla shows caddy can start a   *)
(* second. Serialized models a mutex held across reloadOnce.               *)
(***************************************************************************)
EXTENDS Naturals

CONSTANTS
    MaxVersion,   \* how many rotations the operator performs
    Loops,        \* poll goroutines sharing one liveStore
    Serialized    \* TRUE: reloadOnce runs under a mutex

Versions == 0..MaxVersion
None     == "none"

VARIABLES
    cert, key,    \* version of each file on disk
    current,      \* version of the certStore GetCertificate is serving
    digest,       \* the <<cert, key>> digest last stored
    lock,         \* holder of the reloadOnce mutex, or None
    pc,           \* per-loop program counter
    dcert,        \* per-loop: cert version digestPairs read
    ldig,         \* per-loop: complete digest digestPairs computed
    bcert         \* per-loop: cert version buildCertStore read

vars == <<cert, key, current, digest, lock, pc, dcert, ldig, bcert>>

TypeOK ==
    /\ cert \in Versions /\ key \in Versions
    /\ current \in Versions
    /\ digest \in Versions \X Versions
    /\ lock \in Loops \cup {None}
    /\ pc \in [Loops -> {"idle", "dkey", "bcert", "bkey", "storeCur", "storeDig"}]
    /\ dcert \in [Loops -> Versions]
    /\ ldig \in [Loops -> Versions \X Versions]
    /\ bcert \in [Loops -> Versions]

Init ==
    /\ cert = 0 /\ key = 0
    /\ current = 0
    /\ digest = <<0, 0>>
    /\ lock = None
    /\ pc = [l \in Loops |-> "idle"]
    /\ dcert = [l \in Loops |-> 0]
    /\ ldig = [l \in Loops |-> <<0, 0>>]
    /\ bcert = [l \in Loops |-> 0]

-----------------------------------------------------------------------------
(* The operator. Either file may be replaced first (two independent writes *)
(* to two paths), or both at once (the k8s Secret ..data symlink swap).    *)
(* Versions only move forward and the two files never drift more than one *)
(* rotation apart.                                                         *)

WriteCert ==
    /\ cert <= key /\ cert < MaxVersion
    /\ cert' = cert + 1
    /\ UNCHANGED <<key, current, digest, lock, pc, dcert, ldig, bcert>>

WriteKey ==
    /\ key <= cert /\ key < MaxVersion
    /\ key' = key + 1
    /\ UNCHANGED <<cert, current, digest, lock, pc, dcert, ldig, bcert>>

SwapBoth ==
    /\ cert = key /\ cert < MaxVersion
    /\ cert' = cert + 1 /\ key' = key + 1
    /\ UNCHANGED <<current, digest, lock, pc, dcert, ldig, bcert>>

Operator == WriteCert \/ WriteKey \/ SwapBoth

-----------------------------------------------------------------------------
(* One poll goroutine, l.                                                  *)

Goto(l, s) == pc' = [pc EXCEPT ![l] = s]

\* Ticker fires: take the mutex if there is one, read the cert file.
DigestCert(l) ==
    /\ pc[l] = "idle"
    /\ IF Serialized THEN lock = None /\ lock' = l ELSE UNCHANGED lock
    /\ dcert' = [dcert EXCEPT ![l] = cert]
    /\ Goto(l, "dkey")
    /\ UNCHANGED <<cert, key, current, digest, ldig, bcert>>

Release == IF Serialized THEN lock' = None ELSE UNCHANGED lock

\* Read the key file, finish the digest, compare against the stored one.
DigestKey(l) ==
    /\ pc[l] = "dkey"
    /\ LET d == <<dcert[l], key>> IN
         /\ ldig' = [ldig EXCEPT ![l] = d]
         /\ IF d = digest
              THEN Goto(l, "idle") /\ Release
              ELSE Goto(l, "bcert") /\ UNCHANGED lock
    /\ UNCHANGED <<cert, key, current, digest, dcert, bcert>>

\* buildCertStore -> tls.LoadX509KeyPair reads the cert file...
BuildCert(l) ==
    /\ pc[l] = "bcert"
    /\ bcert' = [bcert EXCEPT ![l] = cert]
    /\ Goto(l, "bkey")
    /\ UNCHANGED <<cert, key, current, digest, lock, dcert, ldig>>

\* ...then the key file. A mismatched pair is a load error: log, keep the
\* previous store, return.
BuildKey(l) ==
    /\ pc[l] = "bkey"
    /\ IF bcert[l] = key
         THEN Goto(l, "storeCur") /\ UNCHANGED lock
         ELSE Goto(l, "idle") /\ Release
    /\ UNCHANGED <<cert, key, current, digest, dcert, ldig, bcert>>

StoreCurrent(l) ==
    /\ pc[l] = "storeCur"
    /\ current' = bcert[l]
    /\ Goto(l, "storeDig")
    /\ UNCHANGED <<cert, key, digest, lock, dcert, ldig, bcert>>

StoreDigest(l) ==
    /\ pc[l] = "storeDig"
    /\ digest' = ldig[l]
    /\ Goto(l, "idle")
    /\ Release
    /\ UNCHANGED <<cert, key, current, dcert, ldig, bcert>>

Loop(l) ==
    \/ DigestCert(l) \/ DigestKey(l) \/ BuildCert(l)
    \/ BuildKey(l) \/ StoreCurrent(l) \/ StoreDigest(l)

Next == Operator \/ \E l \in Loops : Loop(l)

\* The ticker fires forever, so every loop keeps getting scheduled; the
\* operator eventually finishes the rotations it started.
Spec ==
    /\ Init /\ [][Next]_vars
    /\ WF_vars(Operator)
    /\ \A l \in Loops : WF_vars(Loop(l))

-----------------------------------------------------------------------------
(* Properties.                                                             *)

\* The poller only ever installs a store built from a matching pair, and
\* never blanks the listener: there is always a version being served. (In
\* the Go code: current is never set to nil, and a failed build never
\* reaches current.Store.)
ServesLoadedPair == current \in Versions

\* A served certificate never goes backwards. A rollback would put an
\* already-replaced certificate (possibly one rotated out because it was
\* compromised) back in front of clients.
NoRollback == [][current' >= current]_current

\* Once the operator stops rotating, the listener ends up serving what is on
\* disk. This is the property a rotation-at-the-same-path deployment depends
\* on, and the reason the poller exists at all.
EventuallyServesDisk == <>[](current = MaxVersion)

=============================================================================

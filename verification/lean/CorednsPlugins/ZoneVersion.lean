import CorednsPlugins.Serial

/-!
# RFC 9660 ZONEVERSION — `zoneversion/version.go`, `request.go`, `cache.go`

A byte is a `Nat`; a byte slice a `List Nat`; a `uint32` a `Nat` below
`2^32`. Each Go function has a model that follows it statement by
statement, error returns becoming `none`.

Requirement ids (R…) refer to docs/zoneversion-plugin.md.

* **Codec (R3, R4, R14, R15).** `encode` is `Version.Encode`: LABELCOUNT,
  TYPE 0 (SOA-SERIAL), then the serial big-endian (RFC 9660 §2.1 Figure 1,
  §4). `decode` is `Decode`. Proved: the option is always 6 octets
  (`encode_length`, §4 "MUST be set to "6""), `decode (encode v) = v` for
  every valid version (`decode_encode`), `encode (decode b) = b` for every
  byte string `decode` accepts (`encode_decode`), and `decode` refuses every
  other length and every other TYPE. The §5 example is checked by
  evaluation (`rfc9660_example`).
* **Request classification (R11, R12).** `classify` is the Go loop over the
  OPT RR's options, as (code, length) pairs. Proved: it answers "version"
  exactly when the request carries one ZONEVERSION option and it is empty
  (`classify_version_iff`), "none" exactly when it carries none
  (`classify_none_iff`), and FORMERR otherwise — §3.2.1.
* **Cache update (D3).** `update` is `cache.go`'s rule. It reuses
  `Serial.serialGreater`, which `Serial.lean` proves is exactly RFC 1982
  §3.2. Proved: the stored serial is always the old one or the observed one
  (`update_observed`: the cache never invents a serial); a fresh entry never
  moves backwards in RFC 1982 order (`update_fresh_monotone`); a regression
  leaves the entry alone (`update_regression_keeps`); a stale entry is
  replaced (`update_stale_replaces`).
* **Why a bracket is sound, and its limit (G2, A1).** A zone serial that
  only moves forward by RFC 1982 additions (§3.1, each step in
  `[1, 2^31 - 1]`, each a `serialGreater` step by `Serial.add_is_greater`)
  and that has moved by less than `2^32` in total since an observation can
  only show the same serial again if it has not moved at all
  (`bracket_sound`). Without the bound the bracket is unsound: three
  maximal increments bring a serial back to itself (`aba_possible`). That is
  what `maxEntryAge` bounds, and what TLA+ ZoneVersionSerial_Rollback shows
  for a rollback.

Not modelled: DNS names (LABELCOUNT is taken as given; `NewVersion`'s name
checks are tested in Go, `TestNewVersion` and `FuzzNewVersion`), time, and
concurrency (that is ZoneVersionSerial.tla).
-/

namespace ZoneVersion

/-- `2^32`, the serial space. -/
local notation "M" => 4294967296
/-- `2^31`. -/
local notation "H" => 2147483648

/-! ## Codec -/

/-- `binary.BigEndian.PutUint32`. -/
def be32 (n : Nat) : List Nat :=
  [n / 16777216 % 256, n / 65536 % 256, n / 256 % 256, n % 256]

/-- `binary.BigEndian.Uint32`. -/
def unbe32 (a b c d : Nat) : Nat := a * 16777216 + b * 65536 + c * 256 + d

/-- `Version.Validate`: 1 ≤ LABELCOUNT ≤ 127 (R4: never the root, never more
labels than a 255-octet name can have). -/
def valid (lc : Nat) : Prop := 1 ≤ lc ∧ lc ≤ 127

instance (lc : Nat) : Decidable (valid lc) := by unfold valid; infer_instance

/-- `Version.Encode`. -/
def encode (lc serial : Nat) : List Nat := lc :: 0 :: be32 serial

/-- `Decode`: exactly six octets, TYPE 0, a valid LABELCOUNT. -/
def decode : List Nat → Option (Nat × Nat)
  | [lc, ty, a, b, c, d] =>
    if ty = 0 ∧ valid lc then some (lc, unbe32 a b c d) else none
  | _ => none

/-- R14: an SOA-SERIAL option is always six octets. -/
theorem encode_length (lc s : Nat) : (encode lc s).length = 6 := rfl

theorem unbe32_be32 (s : Nat) (h : s < M) :
    unbe32 (s / 16777216 % 256) (s / 65536 % 256) (s / 256 % 256) (s % 256) = s := by
  unfold unbe32; omega

/-- Round trip one way: whatever valid version is encoded decodes back to
itself (R3, R15: the serial is copied exactly). -/
theorem decode_encode (lc s : Nat) (hv : valid lc) (hs : s < M) :
    decode (encode lc s) = some (lc, s) := by
  simp [encode, be32, decode, hv, unbe32_be32 s hs]

/-- Round trip the other way: every byte string `decode` accepts is exactly
the encoding of what it decoded to. So there is one wire form per version,
and nothing `decode` accepts is lost or altered by re-encoding. -/
theorem encode_decode (bs : List Nat) (hb : ∀ x ∈ bs, x < 256) (lc s : Nat)
    (h : decode bs = some (lc, s)) : encode lc s = bs := by
  match bs, h with
  | [l, ty, a, b, c, d], h =>
    simp only [decode] at h
    split at h
    · rename_i hc
      simp only [Option.some.injEq, Prod.mk.injEq] at h
      obtain ⟨rfl, rfl⟩ := h
      have ha := hb a (by simp)
      have hb' := hb b (by simp)
      have hc' := hb c (by simp)
      have hd := hb d (by simp)
      simp only [encode, be32, unbe32, hc.1, List.cons.injEq, and_true, true_and]
      omega
    · exact absurd h (by simp)

/-- A decoded serial fits 32 bits: nothing `decode` returns overflows the Go
`uint32`. -/
theorem decode_serial_lt (bs : List Nat) (hb : ∀ x ∈ bs, x < 256) (lc s : Nat)
    (h : decode bs = some (lc, s)) : s < M := by
  match bs, h with
  | [l, ty, a, b, c, d], h =>
    simp only [decode] at h
    split at h
    · simp only [Option.some.injEq, Prod.mk.injEq] at h
      obtain ⟨_, rfl⟩ := h
      have := hb a (by simp); have := hb b (by simp)
      have := hb c (by simp); have := hb d (by simp)
      unfold unbe32; omega
    · exact absurd h (by simp)

/-- Any length other than six is refused, the empty query form included. -/
theorem decode_length (bs : List Nat) (h : bs.length ≠ 6) : decode bs = none := by
  match bs with
  | [_, _, _, _, _, _] => exact absurd rfl h
  | [] | [_] | [_, _] | [_, _, _] | [_, _, _, _] | [_, _, _, _, _] => rfl
  | _ :: _ :: _ :: _ :: _ :: _ :: _ :: _ => rfl

/-- Any TYPE other than SOA-SERIAL (0) is refused, private-use ones included. -/
theorem decode_type (lc ty a b c d : Nat) (h : ty ≠ 0) :
    decode [lc, ty, a, b, c, d] = none := by
  simp [decode, h]

/-- LABELCOUNT 0 (the root zone) is refused (R4). -/
theorem decode_root (a b c d : Nat) : decode [0, 0, a, b, c, d] = none := by
  simp [decode, valid]

/-- RFC 9660 §5, Figure 2: www.example.com in example.com (2 labels) at
serial 2023073001 is `02 00 78 95 a4 e9`. -/
theorem rfc9660_example :
    encode 2 2023073001 = [0x02, 0x00, 0x78, 0x95, 0xa4, 0xe9] ∧
      decode [0x02, 0x00, 0x78, 0x95, 0xa4, 0xe9] = some (2, 2023073001) := by
  decide

/-! ## Request classification -/

/-- The ZONEVERSION option code (R1). -/
def code : Nat := 19

/-- The lengths of the request's ZONEVERSION options, in order. -/
def zvLens : List (Nat × Nat) → List Nat
  | [] => []
  | o :: os => if o.1 = code then o.2 :: zvLens os else zvLens os

/-- The Go loop in `classify`: count ZONEVERSION options, remember whether
the last one was empty. -/
def loop : List (Nat × Nat) → Nat → Bool → Nat × Bool
  | [], seen, empty => (seen, empty)
  | o :: os, seen, empty =>
    if o.1 = code then loop os (seen + 1) (o.2 = 0) else loop os seen empty

inductive Ask where
  | none
  | version
  | malformed
  deriving DecidableEq, Repr

/-- `classify`'s switch. -/
def classify (opts : List (Nat × Nat)) : Ask :=
  let (seen, empty) := loop opts 0 false
  if seen = 0 then .none else if seen = 1 ∧ empty = true then .version else .malformed

theorem loop_seen (os : List (Nat × Nat)) (s : Nat) (e : Bool) :
    (loop os s e).1 = s + (zvLens os).length := by
  induction os generalizing s e with
  | nil => simp [loop, zvLens]
  | cons o os ih =>
    simp only [loop, zvLens]
    split
    · rw [ih]; simp; omega
    · exact ih s e

theorem loop_empty_nil (os : List (Nat × Nat)) (s : Nat) (e : Bool)
    (h : zvLens os = []) : (loop os s e).2 = e := by
  induction os generalizing s e with
  | nil => rfl
  | cons o os ih =>
    simp only [zvLens] at h
    simp only [loop]
    split
    · rename_i hc; rw [if_pos hc] at h; exact absurd h (by simp)
    · rename_i hc; rw [if_neg hc] at h; exact ih s e h

theorem loop_empty_single (os : List (Nat × Nat)) (s : Nat) (e : Bool) (l : Nat)
    (h : zvLens os = [l]) : (loop os s e).2 = decide (l = 0) := by
  induction os generalizing s e with
  | nil => simp [zvLens] at h
  | cons o os ih =>
    simp only [zvLens] at h
    simp only [loop]
    split
    · rename_i hc
      rw [if_pos hc] at h
      simp only [List.cons.injEq] at h
      obtain ⟨rfl, hrest⟩ := h
      exact loop_empty_nil os _ _ hrest
    · rename_i hc; rw [if_neg hc] at h; exact ih s e h

/-- R11/R12: the plugin answers with a version exactly when the request
carries one ZONEVERSION option and it is empty (§3.1). -/
theorem classify_version_iff (opts : List (Nat × Nat)) :
    classify opts = .version ↔ zvLens opts = [0] := by
  have hs := loop_seen opts 0 false
  simp only [Nat.zero_add] at hs
  unfold classify
  constructor
  · intro h
    revert h
    generalize hl : loop opts 0 false = r
    obtain ⟨seen, empty⟩ := r
    rw [hl] at hs
    simp only at hs ⊢
    intro h
    split at h
    · exact absurd h (by decide)
    · split at h
      · rename_i h1
        obtain ⟨h1, he⟩ := h1
        match hz : zvLens opts, hs with
        | [l], _ =>
          have := loop_empty_single opts 0 false l hz
          rw [hl] at this
          simp only at this
          rw [he] at this
          simp at this
          rw [this]
        | [], hs' => simp at hs'; omega
        | _ :: _ :: _, hs' => simp at hs'; omega
      · exact absurd h (by decide)
  · intro hz
    have he := loop_empty_single opts 0 false 0 hz
    rw [hz] at hs
    generalize hl : loop opts 0 false = r at hs he
    obtain ⟨seen, empty⟩ := r
    simp only at hs he ⊢
    rw [hs, he]
    rfl

/-- §3.2.2: no ZONEVERSION option in the request, no version. -/
theorem classify_none_iff (opts : List (Nat × Nat)) :
    classify opts = .none ↔ zvLens opts = [] := by
  have hs := loop_seen opts 0 false
  simp only [Nat.zero_add] at hs
  unfold classify
  generalize hl : loop opts 0 false = r at hs
  obtain ⟨seen, empty⟩ := r
  simp only at hs ⊢
  constructor
  · intro h
    split at h
    · rename_i h0; rw [h0] at hs; exact List.eq_nil_of_length_eq_zero hs.symm
    · split at h <;> exact absurd h (by decide)
  · intro hz
    rw [hz] at hs
    simp at hs
    rw [if_pos hs]

/-- §3.2.1: two ZONEVERSION options are FORMERR whatever their lengths. -/
theorem classify_two_malformed (a b : Nat) (opts : List (Nat × Nat))
    (h : zvLens opts = a :: b :: []) : classify opts = .malformed := by
  have hv : classify opts ≠ .version := by
    rw [Ne, classify_version_iff, h]; simp
  have hn : classify opts ≠ .none := by
    rw [Ne, classify_none_iff, h]; simp
  cases hc : classify opts <;> simp_all

/-- §3.2.1: one non-empty option is FORMERR. -/
theorem classify_nonempty_malformed (l : Nat) (hl : l ≠ 0) (opts : List (Nat × Nat))
    (h : zvLens opts = [l]) : classify opts = .malformed := by
  have hv : classify opts ≠ .version := by
    rw [Ne, classify_version_iff, h]; simp [hl]
  have hn : classify opts ≠ .none := by
    rw [Ne, classify_none_iff, h]; simp
  cases hc : classify opts <;> simp_all

/-! ## Cache update -/

/-- A cache entry: the zone had `serial` at time `time` (`entry.at` in Go). -/
structure Entry where
  serial : Nat
  time : Nat
  deriving DecidableEq, Repr

/-- `cache.go`'s `update`. `fresh` is `fresh(e, now)`, decided by the caller. -/
def update (e : Entry) (fresh : Bool) (s now : Nat) : Entry :=
  if fresh = false then ⟨s, now⟩
  else if s = e.serial then ⟨s, now⟩
  else if Serial.serialGreater s e.serial = true then ⟨s, now⟩
  else e

/-- The cache never stores a serial nobody observed. -/
theorem update_observed (e : Entry) (f : Bool) (s now : Nat) :
    (update e f s now).serial = e.serial ∨ (update e f s now).serial = s := by
  unfold update
  split
  · exact Or.inr rfl
  · split
    · exact Or.inr rfl
    · split
      · exact Or.inr rfl
      · exact Or.inl rfl

/-- A fresh entry never moves backwards in RFC 1982 order: it stays, or the
zone advanced. -/
theorem update_fresh_monotone (e : Entry) (s now : Nat) :
    (update e true s now).serial = e.serial ∨
      Serial.serialGreater (update e true s now).serial e.serial = true := by
  unfold update
  simp only [Bool.true_eq_false, if_false]
  split
  · rename_i h; exact Or.inl h
  · split
    · rename_i h; exact Or.inr h
    · exact Or.inl rfl

/-- A regression (or an antipodal, undefined, serial) leaves a fresh entry
exactly as it was, time included: it is not refreshed, so it goes stale. -/
theorem update_regression_keeps (e : Entry) (s now : Nat) (hne : s ≠ e.serial)
    (hng : Serial.serialGreater s e.serial = false) : update e true s now = e := by
  simp [update, hne, hng]

/-- A stale entry is replaced by the observation, whatever it is. -/
theorem update_stale_replaces (e : Entry) (s now : Nat) :
    update e false s now = ⟨s, now⟩ := by
  simp [update]

/-- In particular an RFC 1982 increment (§3.1) always replaces a fresh entry. -/
theorem update_advance (e : Entry) (n now : Nat) (he : e.serial < M)
    (hn1 : 1 ≤ n) (hn2 : n < H) :
    (update e true ((e.serial + n) % M) now).serial = (e.serial + n) % M := by
  have hg := Serial.add_is_greater e.serial n he hn1 hn2
  unfold update
  simp [hg]

/-! ## The bracket -/

/-- The serial a zone shows after moving forward by `ds` from `s0`. -/
def after (s0 : Nat) (ds : List Nat) : Nat := (s0 + ds.sum) % M

/-- G2's core under assumption A1. Observe `s0`; the zone then moves forward
by RFC 1982 additions `ds`, each at least 1, by less than `2^32` in all;
observe again. If the second observation equals the first, the zone did not
move at all, so an answer produced between the two observations came from
the zone at `s0`. -/
theorem bracket_sound (s0 : Nat) (ds : List Nat)
    (hpos : ∀ d ∈ ds, 1 ≤ d) (hsum : ds.sum < M) (heq : after s0 ds = s0) :
    ds = [] := by
  unfold after at heq
  have h0 : ds.sum = 0 := by omega
  match ds, hpos, h0 with
  | [], _, _ => rfl
  | d :: rest, hpos, h0 =>
    have := hpos d (by simp)
    simp only [List.sum_cons] at h0
    omega

/-- Without the bound, a serial can come back: three RFC 1982 increments,
each a legal `serialGreater` step, wrap it round to where it was. A bracket
spanning them would attribute an answer from another version to this
serial. Hence `maxEntryAge`, and A1 in the design. -/
theorem aba_possible :
    ∃ ds : List Nat, ds ≠ [] ∧ (∀ d ∈ ds, 1 ≤ d ∧ d < H) ∧ after 5 ds = 5 :=
  ⟨[2147483647, 2147483647, 2], by decide, by decide, by decide⟩

end ZoneVersion

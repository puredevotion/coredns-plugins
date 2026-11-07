/-!
# RESINFO RDATA and answer selection — `resinfo/rdata.go`, `resinfo/exterr.go`, `resinfo/resinfo.go`

RFC 9606 §4: "The resolver information record uses the same format as DNS
TXT records", i.e. one or more character-strings, each "a single length byte,
followed by 0-255 bytes of text data" (RFC 6763 §6.1, RFC 1035 §3.3). Each
string is one key/value pair: "Everything up to the first '=' character is the
key ... Everything after the first '=' character to the end of the string
(including subsequent '=' characters, if any) is the value" (RFC 6763 §6.3);
"If there is no '=' in a DNS-SD TXT record string, then it is a boolean
attribute" (§6.4).

Bytes are `Nat`s; `=` is 61. Requirement ids (R…) are those of
`docs/resinfo-plugin.md`.

Wire codec (R7):
* `unpack_pack`, `pack_unpack`: `unpackStrings` (Go `unpackStrings`) and
  `packStrings` (Go `AppendWire`) are inverse on every input either accepts;
  `pack_length`: the RDATA is one octet per string plus its text.
* `pack_bytes`: with every string at most 255 octets of bytes, every octet
  `packStrings` writes is a byte (the length octet fits).

Key/value split (R9, R10):
* `split_render`: a key without `=` splits back off its rendering exactly,
  whatever the value holds, `=` included (`split_render_eq_in_value`).
* `render_split`: rendering the split of *any* string gives the string back,
  so a string has exactly one reading.
* `keyOk_no_eq`: the plugin's key syntax (a-z, 0-9, `-`) never contains `=`.

Canonical form (R6, R7, R12):
* `lexLt` is Go's string `<` on bytes; `lexLt_irrefl`, `lexLt_trans`,
  `lexLt_total` make it a strict total order.
* `valid_nodup`: keys strictly increasing implies no key repeats.
* `canonical_unique`: two strictly increasing lists with the same members are
  equal. `New` sorts and then validates, so its output depends only on the
  set of pairs given (`new_order_independent`): servers sharing a name and
  configuration publish byte-identical RDATA (RFC 9606 §3: "these instances
  SHOULD expose a consistent RESINFO").
* `decode_encode`: `Decode(Strings(i)) = i` for every valid `i`;
  `encode_decode`: whatever `Decode` accepts is valid and re-encodes to the
  exact input octets, so the decoder admits only canonical RDATA.
* `encode_length`: the encoded RDATA is `wireLen` octets, at most 65535.

exterr (R15):
* `ranges_unique`: a canonical range list (each `lo ≤ hi`, and a missing code
  between neighbours: `hi + 1 < next lo`) is determined by the set of codes
  it covers, so a given EDE set has exactly one canonical `exterr` value.
  Decimal rendering is not modelled; the Go tests check it.

Answer selection (R1, R2, R3, R20, R22):
* `eqFoldLoop_iff`: Go's byte loop `equalFoldASCII` is equality after ASCII
  lower-casing (RFC 4343 §3).
* `handle_answers_iff`: the plugin answers exactly a QUERY with one question,
  QTYPE 261, QCLASS IN, whose name folds to a configured name; everything else
  is passed on (`only_type_261`, `only_class_IN`, `only_configured_names`).
* `answer_shape`: an answer is AA, NOERROR, and an RRset of exactly one
  RESINFO record carrying exactly the configured RDATA, owned by the query
  name as sent (RFC 9606 §3: "the RRset MUST have exactly one record"; "MUST
  discard the response if the AA flag in the response is set to 0").
* `handle_case_insensitive`, `handle_names_as_set`: the decision ignores
  ASCII case and the order and repetition of configured names.

What is abstracted: the value shape per key (`valOk`, an arbitrary decidable
predicate: the exterr grammar and the https URL check live in Go and are
property-tested there), the registry contents (`reg`, an arbitrary list), and
the presentation-format escaping miekg/dns needs (`escapeTXT`, Go-tested
against the wire).
-/

namespace Resinfo

/-! ## Character-strings on the wire -/

/-- `Info.AppendWire`: a length octet, then the text, for each string. -/
def packStrings : List (List Nat) → List Nat
  | [] => []
  | s :: ss => s.length :: (s ++ packStrings ss)

/-- `unpackStrings`: split RDATA into strings; a length running past the end
fails. -/
def unpackStrings : List Nat → Option (List (List Nat))
  | [] => some []
  | n :: rest =>
    if n ≤ rest.length then
      match unpackStrings (rest.drop n) with
      | some ss => some (rest.take n :: ss)
      | none => none
    else none
termination_by l => l.length
decreasing_by simp; omega

theorem unpack_pack (ss : List (List Nat)) : unpackStrings (packStrings ss) = some ss := by
  induction ss with
  | nil => simp [packStrings, unpackStrings]
  | cons s ss ih =>
    rw [packStrings, unpackStrings, if_pos (by simp)]
    simp [ih]

theorem pack_unpack (w : List Nat) (ss : List (List Nat)) (h : unpackStrings w = some ss) :
    packStrings ss = w := by
  induction w using unpackStrings.induct generalizing ss with
  | case1 => simp [unpackStrings] at h; subst h; rfl
  | case2 n rest hle ss' hrec ih =>
    rw [unpackStrings, if_pos hle, hrec] at h
    simp only [Option.some.injEq] at h
    subst h
    rw [packStrings, ih ss' hrec, List.length_take, Nat.min_eq_left hle, List.take_append_drop]
  | case3 n rest hle hrec =>
    rw [unpackStrings, if_pos hle, hrec] at h
    cases h
  | case4 n rest hle =>
    rw [unpackStrings, if_neg hle] at h
    cases h

theorem pack_length (ss : List (List Nat)) :
    (packStrings ss).length = (ss.map (fun s => s.length + 1)).sum := by
  induction ss with
  | nil => rfl
  | cons s ss ih => simp [packStrings, ih]; omega

/-- Every octet written is a byte when every string is at most 255 octets of
bytes: the length octet cannot overflow. -/
theorem pack_bytes (ss : List (List Nat)) (h : ∀ s ∈ ss, s.length ≤ 255 ∧ ∀ b ∈ s, b < 256) :
    ∀ b ∈ packStrings ss, b < 256 := by
  induction ss with
  | nil => simp [packStrings]
  | cons s ss ih =>
    intro b hb
    simp only [packStrings, List.mem_cons, List.mem_append] at hb
    have hs := h s (by simp)
    rcases hb with rfl | hb | hb
    · omega
    · exact hs.2 b hb
    · exact ih (fun t ht => h t (by simp [ht])) b hb

/-! ## Key/value pairs -/

/-- `Pair`: `val = none` is a boolean attribute (no `=`); `some v` is `key=v`. -/
structure Pair where
  key : List Nat
  val : Option (List Nat)
  deriving DecidableEq

/-- `Pair.String`. -/
def render : Pair → List Nat
  | ⟨k, none⟩ => k
  | ⟨k, some v⟩ => k ++ 61 :: v

/-- `splitPair` (`strings.Cut(s, "=")`): key up to the first `=`, the rest is
the value. -/
def splitPair : List Nat → Pair
  | [] => ⟨[], none⟩
  | c :: cs => if c = 61 then ⟨[], some cs⟩ else ⟨c :: (splitPair cs).key, (splitPair cs).val⟩

theorem split_render (p : Pair) (h : 61 ∉ p.key) : splitPair (render p) = p := by
  obtain ⟨k, v⟩ := p
  induction k with
  | nil => cases v <;> simp [render, splitPair]
  | cons c cs ih =>
    have hc : c ≠ 61 := fun e => h (by simp [e])
    have hcs : 61 ∉ cs := fun m => h (by simp [m])
    have := ih hcs
    cases v with
    | none =>
      simp only [render] at this ⊢
      rw [splitPair, if_neg hc, this]
    | some v =>
      simp only [render, List.cons_append] at this ⊢
      rw [splitPair, if_neg hc, this]

/-- RFC 6763 §6.3: "including subsequent '=' characters" — a value full of
`=` still round-trips. -/
theorem split_render_eq_in_value (k v : List Nat) (h : 61 ∉ k) :
    splitPair (k ++ 61 :: v) = ⟨k, some v⟩ :=
  split_render ⟨k, some v⟩ h

theorem render_split (s : List Nat) : render (splitPair s) = s := by
  induction s with
  | nil => rfl
  | cons c cs ih =>
    by_cases hc : c = 61
    · subst hc; simp [splitPair, render]
    · rw [splitPair, if_neg hc]
      revert ih
      cases splitPair cs with
      | mk k v => cases v <;> simp [render]

/-- The plugin's key alphabet (`keyKind`): a-z, 0-9 and `-`. -/
def keyChar (b : Nat) : Bool := (97 ≤ b && b ≤ 122) || (48 ≤ b && b ≤ 57) || b == 45

/-- `temp-` as bytes. -/
def tempPrefix : List Nat := [116, 101, 109, 112, 45]

/-- `keyKind` succeeds: non-empty, the alphabet, and registered or `temp-`
plus at least one more character (RFC 9606 §4). -/
def keyOk (reg : List (List Nat)) (k : List Nat) : Bool :=
  !k.isEmpty && k.all keyChar && (reg.contains k || (tempPrefix.isPrefixOf k && 5 < k.length))

theorem keyOk_no_eq {reg k} (h : keyOk reg k = true) : 61 ∉ k := by
  intro m
  simp only [keyOk, Bool.and_eq_true, List.all_eq_true] at h
  have := h.1.2 61 m
  simp [keyChar] at this

/-! ## Byte order on keys -/

/-- Go's `<` on strings, bytewise; a proper prefix is smaller. -/
def lexLt : List Nat → List Nat → Bool
  | [], [] => false
  | [], _ :: _ => true
  | _ :: _, [] => false
  | a :: as, b :: bs => a < b || (a == b && lexLt as bs)

theorem lexLt_irrefl (a : List Nat) : lexLt a a = false := by
  induction a with
  | nil => rfl
  | cons x xs ih => simp [lexLt, ih]

theorem lexLt_trans : ∀ (a b c : List Nat), lexLt a b = true → lexLt b c = true → lexLt a c = true
  | [], [], _, h, _ => by simp [lexLt] at h
  | [], _ :: _, [], _, h => by simp [lexLt] at h
  | [], _ :: _, _ :: _, _, _ => rfl
  | _ :: _, [], _, h, _ => by simp [lexLt] at h
  | _ :: _, _ :: _, [], _, h => by simp [lexLt] at h
  | x :: xs, y :: ys, z :: zs, h1, h2 => by
    simp only [lexLt, Bool.or_eq_true, Bool.and_eq_true, decide_eq_true_eq, beq_iff_eq] at h1 h2 ⊢
    rcases h1 with h1 | ⟨rfl, h1⟩ <;> rcases h2 with h2 | ⟨rfl, h2⟩
    · left; omega
    · left; exact h1
    · left; exact h2
    · right; exact ⟨rfl, lexLt_trans xs ys zs h1 h2⟩

theorem lexLt_asymm (a b : List Nat) (h : lexLt a b = true) : lexLt b a = false := by
  cases h' : lexLt b a
  · rfl
  · have := lexLt_trans a b a h h'; rw [lexLt_irrefl] at this; cases this

theorem lexLt_total : ∀ (a b : List Nat), a ≠ b → lexLt a b = true ∨ lexLt b a = true
  | [], [], h => absurd rfl h
  | [], _ :: _, _ => Or.inl rfl
  | _ :: _, [], _ => Or.inr rfl
  | x :: xs, y :: ys, h => by
    simp only [lexLt, Bool.or_eq_true, Bool.and_eq_true, decide_eq_true_eq, beq_iff_eq]
    by_cases hxy : x = y
    · subst hxy
      have : xs ≠ ys := fun e => h (by rw [e])
      rcases lexLt_total xs ys this with h' | h'
      · exact Or.inl (Or.inr ⟨rfl, h'⟩)
      · exact Or.inr (Or.inr ⟨rfl, h'⟩)
    · rcases Nat.lt_or_gt_of_ne hxy with h' | h'
      · exact Or.inl (Or.inl h')
      · exact Or.inr (Or.inl h')

/-! ## Validity, the one definition `New` and `Decode` share -/

/-- `validate`'s order check: each key strictly above the one before. -/
def increasing : List Pair → Bool
  | [] => true
  | [_] => true
  | p :: q :: rest => lexLt p.key q.key && increasing (q :: rest)

/-- RDLENGTH. -/
def wireLen (ps : List Pair) : Nat := (ps.map (fun p => (render p).length + 1)).sum

/-- `validate`: at least one pair, strictly increasing keys, every pair's key
and value acceptable and its string at most 255 octets, RDATA at most 65535
octets. `reg` is the IANA registry; `valOk` is the per-key value rule. -/
def valid (reg : List (List Nat)) (valOk : List Nat → Option (List Nat) → Bool)
    (ps : List Pair) : Bool :=
  !ps.isEmpty && increasing ps &&
    ps.all (fun p => keyOk reg p.key && valOk p.key p.val && decide ((render p).length ≤ 255)) &&
    decide (wireLen ps ≤ 65535)

theorem increasing_pairwise : ∀ (ps : List Pair), increasing ps = true →
    ps.Pairwise (fun p q => lexLt p.key q.key = true)
  | [], _ => List.Pairwise.nil
  | [_], _ => List.pairwise_singleton _ _
  | p :: q :: rest, h => by
    simp only [increasing, Bool.and_eq_true] at h
    have ih := increasing_pairwise (q :: rest) h.2
    refine List.Pairwise.cons ?_ ih
    intro r hr
    rcases List.mem_cons.1 hr with rfl | hr
    · exact h.1
    · exact lexLt_trans _ _ _ h.1 (List.rel_of_pairwise_cons ih hr)

theorem pairwise_lt_nodup (ps : List Pair) (h : ps.Pairwise (fun p q => lexLt p.key q.key = true)) :
    (ps.map Pair.key).Nodup := by
  induction ps with
  | nil => exact List.nodup_nil
  | cons p ps ih =>
    rw [List.map_cons, List.nodup_cons]
    refine ⟨?_, ih (List.Pairwise.of_cons h)⟩
    intro hm
    obtain ⟨q, hq, hk⟩ := List.mem_map.1 hm
    have := List.rel_of_pairwise_cons h hq
    rw [hk, lexLt_irrefl] at this
    cases this

/-- No key repeats (RFC 6763 §6.4: "A given key SHOULD NOT appear more than
once"; enforced here). -/
theorem valid_nodup {reg valOk ps} (h : valid reg valOk ps = true) : (ps.map Pair.key).Nodup := by
  simp only [valid, Bool.and_eq_true] at h
  exact pairwise_lt_nodup ps (increasing_pairwise ps h.1.1.2)

/-- Strictly increasing lists with the same members are equal. -/
theorem canonical_unique : ∀ (a b : List Pair),
    a.Pairwise (fun p q => lexLt p.key q.key = true) →
    b.Pairwise (fun p q => lexLt p.key q.key = true) →
    (∀ p, p ∈ a ↔ p ∈ b) → a = b
  | [], [], _, _, _ => rfl
  | [], q :: _, _, _, h => absurd ((h q).2 (by simp)) (by simp)
  | p :: _, [], _, _, h => absurd ((h p).1 (by simp)) (by simp)
  | p :: as, q :: bs, ha, hb, h => by
    have hpq : p = q := by
      refine Classical.byContradiction fun hne => ?_
      have hp : p ∈ bs := by
        rcases List.mem_cons.1 ((h p).1 (by simp)) with e | m
        · exact absurd e hne
        · exact m
      have hq : q ∈ as := by
        rcases List.mem_cons.1 ((h q).2 (by simp)) with e | m
        · exact absurd e.symm hne
        · exact m
      have h1 := List.rel_of_pairwise_cons ha hq
      have h2 := List.rel_of_pairwise_cons hb hp
      rw [lexLt_asymm _ _ h1] at h2
      cases h2
    subst hpq
    have notin_a : p ∉ as := fun m => by
      have := List.rel_of_pairwise_cons ha m; rw [lexLt_irrefl] at this; cases this
    have notin_b : p ∉ bs := fun m => by
      have := List.rel_of_pairwise_cons hb m; rw [lexLt_irrefl] at this; cases this
    have tails : ∀ r, r ∈ as ↔ r ∈ bs := by
      intro r
      constructor
      · intro m
        rcases List.mem_cons.1 ((h r).1 (List.mem_cons_of_mem _ m)) with e | m'
        · subst e; exact absurd m notin_a
        · exact m'
      · intro m
        rcases List.mem_cons.1 ((h r).2 (List.mem_cons_of_mem _ m)) with e | m'
        · subst e; exact absurd m notin_b
        · exact m'
    rw [canonical_unique as bs (List.Pairwise.of_cons ha) (List.Pairwise.of_cons hb) tails]

/-- `New` sorts its input (any permutation, here: any list with the same
members) and then `validate`s it. Whatever two orders of the same pairs it is
given, the validated outputs are identical. -/
theorem new_order_independent {reg valOk} (in1 in2 out1 out2 : List Pair)
    (hin : ∀ p, p ∈ in1 ↔ p ∈ in2)
    (hs1 : ∀ p, p ∈ out1 ↔ p ∈ in1) (hs2 : ∀ p, p ∈ out2 ↔ p ∈ in2)
    (hv1 : valid reg valOk out1 = true) (hv2 : valid reg valOk out2 = true) : out1 = out2 := by
  simp only [valid, Bool.and_eq_true] at hv1 hv2
  exact canonical_unique out1 out2 (increasing_pairwise _ hv1.1.1.2)
    (increasing_pairwise _ hv2.1.1.2) (fun p => by rw [hs1, hs2, hin])

/-! ## Encode and decode -/

/-- `Info.AppendWire` of the pairs. -/
def encode (ps : List Pair) : List Nat := packStrings (ps.map render)

/-- `DecodeWire`: unpack, split each string, accept only if `validate` does. -/
def decode (reg : List (List Nat)) (valOk : List Nat → Option (List Nat) → Bool)
    (w : List Nat) : Option (List Pair) :=
  match unpackStrings w with
  | none => none
  | some ss => if valid reg valOk (ss.map splitPair) then some (ss.map splitPair) else none

theorem map_split_render (ps : List Pair) (h : ∀ p ∈ ps, 61 ∉ p.key) :
    (ps.map render).map splitPair = ps := by
  induction ps with
  | nil => rfl
  | cons p ps ih =>
    simp only [List.map_cons, List.cons.injEq]
    exact ⟨split_render p (h p (by simp)), ih (fun q hq => h q (by simp [hq]))⟩

theorem valid_keys_no_eq {reg valOk ps} (h : valid reg valOk ps = true) : ∀ p ∈ ps, 61 ∉ p.key := by
  intro p hp
  simp only [valid, Bool.and_eq_true, List.all_eq_true] at h
  exact keyOk_no_eq (h.1.2 p hp).1.1

/-- `Decode(Strings(i)) = i` for every valid `i`. -/
theorem decode_encode {reg valOk} (ps : List Pair) (h : valid reg valOk ps = true) :
    decode reg valOk (encode ps) = some ps := by
  rw [decode, encode, unpack_pack]
  simp only
  rw [map_split_render ps (valid_keys_no_eq h), if_pos h]

/-- Whatever `DecodeWire` accepts is valid and re-encodes to the very same
octets: only canonical RDATA is accepted. -/
theorem encode_decode {reg valOk} (w : List Nat) (ps : List Pair)
    (h : decode reg valOk w = some ps) : valid reg valOk ps = true ∧ encode ps = w := by
  unfold decode at h
  split at h
  · cases h
  · rename_i ss hss
    split at h
    · rename_i hv
      simp only [Option.some.injEq] at h
      subst h
      refine ⟨hv, ?_⟩
      rw [encode, List.map_map]
      have : (render ∘ splitPair) = id := funext render_split
      rw [this, List.map_id]
      exact pack_unpack w ss hss
    · cases h

theorem encode_length {reg valOk} (ps : List Pair) (h : valid reg valOk ps = true) :
    (encode ps).length = wireLen ps ∧ wireLen ps ≤ 65535 := by
  refine ⟨?_, ?_⟩
  · rw [encode, pack_length, List.map_map]; rfl
  · simp only [valid, Bool.and_eq_true, decide_eq_true_eq] at h; exact h.2

/-- Every string of a valid RDATA is at most 255 octets. -/
theorem valid_strings_short {reg valOk ps} (h : valid reg valOk ps = true) :
    ∀ s ∈ ps.map render, s.length ≤ 255 := by
  intro s hs
  obtain ⟨p, hp, rfl⟩ := List.mem_map.1 hs
  simp only [valid, Bool.and_eq_true, List.all_eq_true, decide_eq_true_eq] at h
  exact (h.1.2 p hp).2

/-! ## exterr ranges -/

/-- Code `n` is covered by one of the ranges. -/
def covers (rs : List (Nat × Nat)) (n : Nat) : Prop := ∃ r ∈ rs, r.1 ≤ n ∧ n ≤ r.2

/-- The canonical shape `CanonicalRanges` produces. -/
def canon : List (Nat × Nat) → Prop
  | [] => True
  | [r] => r.1 ≤ r.2
  | r :: s :: rest => r.1 ≤ r.2 ∧ r.2 + 1 < s.1 ∧ canon (s :: rest)

theorem canon_tail {r : Nat × Nat} {rest} (h : canon (r :: rest)) : canon rest := by
  cases rest with
  | nil => trivial
  | cons s rest => exact h.2.2

theorem canon_head {r : Nat × Nat} {rest} (h : canon (r :: rest)) : r.1 ≤ r.2 := by
  cases rest with
  | nil => exact h
  | cons s rest => exact h.1

/-- Every code of a canonical list is at least its first `lo`. -/
theorem canon_lower : ∀ (r : Nat × Nat) (rest : List (Nat × Nat)) (n : Nat),
    canon (r :: rest) → covers (r :: rest) n → r.1 ≤ n
  | r, rest, n, hc, ⟨x, hx, hlo, _⟩ => by
    rcases List.mem_cons.1 hx with rfl | hx
    · exact hlo
    · cases rest with
      | nil => cases hx
      | cons s rest' =>
        have := canon_lower s rest' n hc.2.2 ⟨x, hx, hlo, by omega⟩
        have := hc.2.1; have := canon_head hc; omega

/-- Codes of the tail lie beyond the head's `hi + 1`. -/
theorem canon_tail_beyond {r : Nat × Nat} {rest n} (hc : canon (r :: rest)) (h : covers rest n) :
    r.2 + 1 < n := by
  cases rest with
  | nil => obtain ⟨x, hx, _⟩ := h; cases hx
  | cons s rest' =>
    have := canon_lower s rest' n hc.2.2 h
    have := hc.2.1
    omega

theorem covers_cons {r : Nat × Nat} {rest n} :
    covers (r :: rest) n ↔ (r.1 ≤ n ∧ n ≤ r.2) ∨ covers rest n := by
  simp [covers]

/-- A canonical range list is determined by the codes it covers. -/
theorem ranges_unique : ∀ (a b : List (Nat × Nat)), canon a → canon b →
    (∀ n, covers a n ↔ covers b n) → a = b
  | [], [], _, _, _ => rfl
  | [], s :: sb, _, hb, h => by
    have : covers (s :: sb) s.1 := ⟨s, by simp, Nat.le_refl _, canon_head hb⟩
    obtain ⟨_, hx, _⟩ := (h s.1).2 this; cases hx
  | r :: ra, [], ha, _, h => by
    have : covers (r :: ra) r.1 := ⟨r, by simp, Nat.le_refl _, canon_head ha⟩
    obtain ⟨_, hx, _⟩ := (h r.1).1 this; cases hx
  | r :: ra, s :: rb, ha, hb, h => by
    have rlo := canon_head ha
    have slo := canon_head hb
    -- Same first code.
    have h1 : r.1 = s.1 := by
      have x := canon_lower s rb r.1 hb ((h r.1).1 ⟨r, by simp, Nat.le_refl _, rlo⟩)
      have y := canon_lower r ra s.1 ha ((h s.1).2 ⟨s, by simp, Nat.le_refl _, slo⟩)
      omega
    -- Same last code of the first run: the code after the shorter run is a
    -- gap in one list and covered in the other.
    have h2 : r.2 = s.2 := by
      rcases Nat.lt_trichotomy r.2 s.2 with lt | eq | gt
      · exfalso
        have hb' : covers (s :: rb) (r.2 + 1) := ⟨s, by simp, by omega, by omega⟩
        rcases covers_cons.1 ((h (r.2 + 1)).2 hb') with ⟨_, hi⟩ | ht
        · omega
        · have := canon_tail_beyond ha ht; omega
      · exact eq
      · exfalso
        have ha' : covers (r :: ra) (s.2 + 1) := ⟨r, by simp, by omega, by omega⟩
        rcases covers_cons.1 ((h (s.2 + 1)).1 ha') with ⟨_, hi⟩ | ht
        · omega
        · have := canon_tail_beyond hb ht; omega
    have hrs : r = s := Prod.ext h1 h2
    subst hrs
    have tails : ∀ n, covers ra n ↔ covers rb n := by
      intro n
      constructor
      · intro hn
        have := canon_tail_beyond ha hn
        rcases covers_cons.1 ((h n).1 (covers_cons.2 (Or.inr hn))) with ⟨_, hi⟩ | ht
        · omega
        · exact ht
      · intro hn
        have := canon_tail_beyond hb hn
        rcases covers_cons.1 ((h n).2 (covers_cons.2 (Or.inr hn))) with ⟨_, hi⟩ | ht
        · omega
        · exact ht
    rw [ranges_unique ra rb (canon_tail ha) (canon_tail hb) tails]

/-! ## Answer selection -/

/-- `lowerASCII`. -/
def lower (b : Nat) : Nat := if 65 ≤ b ∧ b ≤ 90 then b + 32 else b

def lowerAll (s : List Nat) : List Nat := s.map lower

/-- Go's `equalFoldASCII`: equal length, then byte by byte after folding. -/
def eqFoldLoop : List Nat → List Nat → Bool
  | [], [] => true
  | a :: as, b :: bs => lower a == lower b && eqFoldLoop as bs
  | _, _ => false

theorem eqFoldLoop_iff : ∀ (a b : List Nat), eqFoldLoop a b = true ↔ lowerAll a = lowerAll b
  | [], [] => by simp [eqFoldLoop, lowerAll]
  | [], _ :: _ => by simp [eqFoldLoop, lowerAll]
  | _ :: _, [] => by simp [eqFoldLoop, lowerAll]
  | a :: as, b :: bs => by
    have := eqFoldLoop_iff as bs
    simp only [lowerAll] at this
    simp [eqFoldLoop, lowerAll, this]

/-- The parts of a request `answers` reads. -/
structure Query where
  opcode : Nat
  qdcount : Nat
  name : List Nat
  qtype : Nat
  qclass : Nat

/-- A RESINFO record as the reply carries it. -/
structure RR where
  owner : List Nat
  rrtype : Nat
  rrclass : Nat
  ttl : Nat
  rdata : List Nat
  deriving DecidableEq

inductive Outcome where
  /-- Written by this plugin. -/
  | answer (aa : Bool) (rcode : Nat) (rrset : List RR)
  /-- Handed to the next plugin. -/
  | pass
  deriving DecidableEq

/-- `answers` and `reply`: `names` are the configured names (lowercase),
`rdata` the configured RDATA. QUERY is opcode 0, IN is class 1, RESINFO is
type 261, NOERROR is rcode 0. -/
def handle (names : List (List Nat)) (rdata : List Nat) (ttl : Nat) (q : Query) : Outcome :=
  if q.opcode = 0 ∧ q.qdcount = 1 ∧ q.qtype = 261 ∧ q.qclass = 1 ∧
      names.any (fun n => eqFoldLoop q.name n) = true then
    .answer true 0 [⟨q.name, 261, 1, ttl, rdata⟩]
  else .pass

theorem handle_answers_iff (names : List (List Nat)) (rdata : List Nat) (ttl : Nat) (q : Query) :
    handle names rdata ttl q ≠ .pass ↔
      q.opcode = 0 ∧ q.qdcount = 1 ∧ q.qtype = 261 ∧ q.qclass = 1 ∧
        ∃ n ∈ names, lowerAll q.name = lowerAll n := by
  unfold handle
  split
  · rename_i hc
    simp only [ne_eq, reduceCtorEq, not_false_eq_true, true_iff]
    obtain ⟨h1, h2, h3, h4, h5⟩ := hc
    obtain ⟨n, hn, he⟩ := List.any_eq_true.1 h5
    exact ⟨h1, h2, h3, h4, n, hn, (eqFoldLoop_iff _ _).1 he⟩
  · rename_i hc
    simp only [ne_eq, not_true_eq_false, false_iff]
    rintro ⟨h1, h2, h3, h4, n, hn, he⟩
    exact hc ⟨h1, h2, h3, h4, List.any_eq_true.2 ⟨n, hn, (eqFoldLoop_iff _ _).2 he⟩⟩

theorem only_type_261 {names rdata ttl} (q : Query) (h : q.qtype ≠ 261) :
    handle names rdata ttl q = .pass := by
  unfold handle; rw [if_neg (by omega)]

theorem only_class_IN {names rdata ttl} (q : Query) (h : q.qclass ≠ 1) :
    handle names rdata ttl q = .pass := by
  unfold handle; rw [if_neg (by omega)]

theorem only_configured_names {names rdata ttl} (q : Query)
    (h : ∀ n ∈ names, lowerAll q.name ≠ lowerAll n) : handle names rdata ttl q = .pass := by
  refine Classical.byContradiction fun hne => ?_
  obtain ⟨_, _, _, _, n, hn, he⟩ := (handle_answers_iff names rdata ttl q).1 hne
  exact h n hn he

/-- An answer is AA, NOERROR, exactly one RESINFO/IN record with exactly the
configured RDATA and TTL, owned by the query name as sent. -/
theorem answer_shape {names rdata ttl} (q : Query) {aa rcode rrset}
    (h : handle names rdata ttl q = .answer aa rcode rrset) :
    aa = true ∧ rcode = 0 ∧ rrset = [⟨q.name, 261, 1, ttl, rdata⟩] := by
  unfold handle at h
  split at h
  · cases h; exact ⟨rfl, rfl, rfl⟩
  · cases h

theorem answer_exactly_one {names rdata ttl} (q : Query) {aa rcode rrset}
    (h : handle names rdata ttl q = .answer aa rcode rrset) : rrset.length = 1 := by
  rw [(answer_shape q h).2.2]; rfl

/-- Whether to answer ignores ASCII case (RFC 4343 §3; 0x20 randomisation). -/
theorem handle_case_insensitive (names : List (List Nat)) (rdata : List Nat) (ttl : Nat)
    (q q' : Query) (hn : lowerAll q.name = lowerAll q'.name) (ho : q.opcode = q'.opcode)
    (hd : q.qdcount = q'.qdcount) (ht : q.qtype = q'.qtype) (hc : q.qclass = q'.qclass) :
    (handle names rdata ttl q = .pass ↔ handle names rdata ttl q' = .pass) := by
  have e := handle_answers_iff names rdata ttl q
  have e' := handle_answers_iff names rdata ttl q'
  rw [hn, ho, hd, ht, hc] at e
  constructor
  · intro hp; exact Classical.byContradiction fun hq => (e.2 (e'.1 hq)) hp
  · intro hp; exact Classical.byContradiction fun hq => (e'.2 (e.1 hq)) hp

/-- Only the set of configured names matters, not their order or repetition. -/
theorem handle_names_as_set (n1 n2 : List (List Nat)) (rdata : List Nat) (ttl : Nat) (q : Query)
    (h : ∀ n, n ∈ n1 ↔ n ∈ n2) : handle n1 rdata ttl q = handle n2 rdata ttl q := by
  have : n1.any (fun n => eqFoldLoop q.name n) = n2.any (fun n => eqFoldLoop q.name n) := by
    rw [Bool.eq_iff_iff, List.any_eq_true, List.any_eq_true]
    exact ⟨fun ⟨n, hn, he⟩ => ⟨n, (h n).1 hn, he⟩, fun ⟨n, hn, he⟩ => ⟨n, (h n).2 hn, he⟩⟩
  unfold handle
  rw [this]

/-! ## RFC 9606 §6, Figure 1, by evaluation -/

/-- "exterr=15-17" -/
def figExterr : List Nat := [101, 120, 116, 101, 114, 114, 61, 49, 53, 45, 49, 55]

example : splitPair figExterr = ⟨[101, 120, 116, 101, 114, 114], some [49, 53, 45, 49, 55]⟩ := by decide

/-- "qnamemin": a boolean attribute. -/
example : splitPair [113, 110, 97, 109, 101, 109, 105, 110] = ⟨[113, 110, 97, 109, 101, 109, 105, 110], none⟩ := by
  decide

/-- 15-17 has one canonical spelling. -/
example : canon [(15, 17)] := by simp [canon]
example : ¬ canon [(15, 15), (16, 17)] := by simp [canon]

end Resinfo

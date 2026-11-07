/-!
# geoscore endpoint selection — `geoscore/selection.go`, `geoscore/entry.go`

The pure part of the `geoscore` plugin: given the validated candidate set of
one address family (configuration order, which is also the tie-break order),
each candidate's score entry as last read from the store, and the time, pick
the endpoint to answer with, or apply the configured fallback.

Model of the Go code (docs/geoscore-plugin.md, requirement ids in brackets):

* A score is a float in [0, 1] in the store; the validator turns it into the
  fixed-point weight `round(score * 10000)`, a natural number. Everything the
  selection does is on that integer, so the model uses `Nat` and loses
  nothing (`Entry.Weight`, `weightScale`).
* `valid` abstracts "the key exists and the entry passed `ParseEntry`"
  (NaN, infinities, negative and >1 scores, missing or unknown fields are
  rejected there and never reach selection) [R14].
* `fresh` is the stale and future checks of `classify` in Go: the writer's own timestamp `updated` is at most
  `skew` seconds in the future and at most `maxStale` seconds in the past
  [R15, R21].
* `eligible` = valid ∧ healthy ∧ fresh ∧ weight > 0 [R15].
* `best` is `pickBest`: the eligible candidate with the highest weight, the
  earliest in configuration order on a tie [R18].
* `pick` is `pickWeighted`: walk the cumulative effective weights with a
  draw `r < total` [R19].
* `outcome` is `instance.decide`: selection, then the fallback when nothing is
  eligible [R20].

Proved:

* `best_sound`, `pick_sound`, `decide_mem`: whatever is selected is a member
  of the candidate set [R16].
* `decide_eligible_or_fallback`: an answered endpoint is eligible, unless no
  candidate is eligible and the fallback is `static`, in which case it is the
  first-listed candidate [R17, R20].
* `best_max`, `best_first`, `best_unique`, `best_complete`, `best_none_iff`:
  best mode is exactly "maximal weight among eligible, earliest on a tie";
  that property picks out a single candidate, so best mode is a function of
  the weights, the eligibility and the order and of nothing else [R18].
* `pick_some`, `pick_none_iff`: a draw below the total always selects; there
  is nothing to select exactly when no candidate is eligible [R19, R20].
* `pick_count`: over the draws `0 ≤ r < total`, a candidate (in a list
  without duplicates) is selected exactly `ew c` times: the selection
  probability is `ew c / total` [R19].
* `pick_monotone`: raising one candidate's weight, everything else equal,
  never lowers its selection probability (stated without division:
  `n·T' ≤ n'·T`) [R19].
-/

namespace GeoScore

/-- One candidate as selection sees it. -/
structure Cand where
  id : Nat
  w : Nat
  valid : Bool
  healthy : Bool
  updated : Nat
deriving DecidableEq, Repr

/-- The clock and the two time bounds, in seconds. -/
structure Params where
  now : Nat
  maxStale : Nat
  skew : Nat

/-- `freshAt`: not too far in the future, not older than `maxStale`. -/
def fresh (p : Params) (c : Cand) : Bool :=
  decide (c.updated ≤ p.now + p.skew) && decide (p.now ≤ c.updated + p.maxStale)

def eligible (p : Params) (c : Cand) : Bool :=
  c.valid && c.healthy && fresh p c && decide (0 < c.w)

/-- Effective weight: the weight if eligible, 0 otherwise. -/
def ew (p : Params) (c : Cand) : Nat := if eligible p c then c.w else 0

theorem ew_pos_eligible {p : Params} {c : Cand} (h : 0 < ew p c) : eligible p c = true := by
  unfold ew at h
  split at h
  · assumption
  · exact absurd h (Nat.lt_irrefl 0)

theorem eligible_w_pos {p : Params} {c : Cand} (h : eligible p c = true) : 0 < c.w := by
  simp [eligible] at h
  exact h.2

theorem ew_of_eligible {p : Params} {c : Cand} (h : eligible p c = true) : ew p c = c.w := by
  simp [ew, h]

theorem ew_of_not_eligible {p : Params} {c : Cand} (h : eligible p c = false) : ew p c = 0 := by
  simp [ew, h]

/-! ## Best mode -/

/-- `pickBest`: keep the first strictly better eligible candidate. -/
def bestAux (p : Params) : Option Cand → List Cand → Option Cand
  | acc, [] => acc
  | acc, c :: cs =>
    if eligible p c then
      match acc with
      | none => bestAux p (some c) cs
      | some b => if b.w < c.w then bestAux p (some c) cs else bestAux p (some b) cs
    else bestAux p acc cs

def best (p : Params) (cs : List Cand) : Option Cand := bestAux p none cs

theorem bestAux_sound (p : Params) :
    ∀ (cs : List Cand) (acc : Option Cand) (c : Cand),
      bestAux p acc cs = some c → acc = some c ∨ (c ∈ cs ∧ eligible p c = true) := by
  intro cs
  induction cs with
  | nil => intro acc c h; exact Or.inl h
  | cons x xs ih =>
    intro acc c h
    simp only [bestAux] at h
    by_cases hx : eligible p x = true
    · rw [if_pos hx] at h
      cases acc with
      | none =>
        dsimp only at h
        rcases ih _ _ h with h1 | ⟨h1, h2⟩
        · cases h1; exact Or.inr ⟨List.mem_cons_self .., hx⟩
        · exact Or.inr ⟨List.mem_cons_of_mem _ h1, h2⟩
      | some b =>
        dsimp only at h
        by_cases hw : b.w < x.w
        · rw [if_pos hw] at h
          rcases ih _ _ h with h1 | ⟨h1, h2⟩
          · cases h1; exact Or.inr ⟨List.mem_cons_self .., hx⟩
          · exact Or.inr ⟨List.mem_cons_of_mem _ h1, h2⟩
        · rw [if_neg hw] at h
          rcases ih _ _ h with h1 | ⟨h1, h2⟩
          · exact Or.inl h1
          · exact Or.inr ⟨List.mem_cons_of_mem _ h1, h2⟩
    · rw [if_neg hx] at h
      rcases ih _ _ h with h1 | ⟨h1, h2⟩
      · exact Or.inl h1
      · exact Or.inr ⟨List.mem_cons_of_mem _ h1, h2⟩

/-- [R16, R17] Best mode only ever selects an eligible member of the set. -/
theorem best_sound {p : Params} {cs : List Cand} {c : Cand} (h : best p cs = some c) :
    c ∈ cs ∧ eligible p c = true := by
  rcases bestAux_sound p cs none c h with h1 | h1
  · cases h1
  · exact h1

theorem bestAux_ge (p : Params) :
    ∀ (cs : List Cand) (acc : Option Cand) (c b : Cand),
      bestAux p acc cs = some c → acc = some b → b.w ≤ c.w := by
  intro cs
  induction cs with
  | nil => intro acc c b h hb; rw [hb] at h; cases h; exact Nat.le_refl _
  | cons x xs ih =>
    intro acc c b h hb
    subst hb
    simp only [bestAux] at h
    by_cases hx : eligible p x = true
    · rw [if_pos hx] at h
      by_cases hw : b.w < x.w
      · rw [if_pos hw] at h
        exact Nat.le_trans (Nat.le_of_lt hw) (ih _ c x h rfl)
      · rw [if_neg hw] at h
        exact ih _ c b h rfl
    · rw [if_neg hx] at h
      exact ih _ c b h rfl

theorem bestAux_max (p : Params) :
    ∀ (cs : List Cand) (acc : Option Cand) (c : Cand),
      bestAux p acc cs = some c → ∀ d ∈ cs, eligible p d = true → d.w ≤ c.w := by
  intro cs
  induction cs with
  | nil => intro _ _ _ d hd; cases hd
  | cons x xs ih =>
    intro acc c h d hd hde
    simp only [bestAux] at h
    by_cases hx : eligible p x = true
    · rw [if_pos hx] at h
      cases acc with
      | none =>
        dsimp only at h
        cases hd with
        | head => exact bestAux_ge p xs _ c x h rfl
        | tail _ hd' => exact ih _ c h d hd' hde
      | some b =>
        dsimp only at h
        by_cases hw : b.w < x.w
        · rw [if_pos hw] at h
          cases hd with
          | head => exact bestAux_ge p xs _ c x h rfl
          | tail _ hd' => exact ih _ c h d hd' hde
        · rw [if_neg hw] at h
          cases hd with
          | head =>
            have := bestAux_ge p xs _ c b h rfl
            exact Nat.le_trans (Nat.le_of_not_lt hw) this
          | tail _ hd' => exact ih _ c h d hd' hde
    · rw [if_neg hx] at h
      cases hd with
      | head => exact absurd hde hx
      | tail _ hd' => exact ih _ c h d hd' hde

/-- [R18] The selected weight is maximal among the eligible candidates. -/
theorem best_max {p : Params} {cs : List Cand} {c : Cand} (h : best p cs = some c) :
    ∀ d ∈ cs, eligible p d = true → d.w ≤ c.w :=
  bestAux_max p cs none c h

/-- The specification of best mode at a position: `c` sits at `pre ++ c :: post`,
is eligible, has maximal weight, and every eligible candidate before it is
strictly lighter (the tie-break: earliest wins). -/
def BestAt (p : Params) (cs pre : List Cand) (c : Cand) (post : List Cand) : Prop :=
  cs = pre ++ c :: post ∧ eligible p c = true ∧
  (∀ d ∈ cs, eligible p d = true → d.w ≤ c.w) ∧
  (∀ d ∈ pre, eligible p d = true → d.w < c.w)

/-- Accumulator invariant for the tie-break: the accumulator, if any, is
eligible, sits in the prefix already walked, and is strictly heavier than
every eligible candidate walked before its own position. -/
theorem bestAux_first (p : Params) :
    ∀ (cs : List Cand) (walked : List Cand) (acc : Option Cand) (c : Cand),
      bestAux p acc cs = some c →
      (acc = none → ∀ d ∈ walked, eligible p d = false) →
      (∀ b, acc = some b → eligible p b = true ∧
          ∃ pre post, walked = pre ++ b :: post ∧
            (∀ d ∈ pre, eligible p d = true → d.w < b.w) ∧
            (∀ d ∈ walked, eligible p d = true → d.w ≤ b.w)) →
      ∃ pre post, walked ++ cs = pre ++ c :: post ∧
        (∀ d ∈ pre, eligible p d = true → d.w < c.w) := by
  intro cs
  induction cs with
  | nil =>
    intro walked acc c h _ hsome
    simp only [bestAux] at h
    obtain ⟨_, pre, post, hw, hpre, _⟩ := hsome c h
    exact ⟨pre, post, by simp [hw], hpre⟩
  | cons x xs ih =>
    intro walked acc c h hnone hsome
    simp only [bestAux] at h
    by_cases hx : eligible p x = true
    · rw [if_pos hx] at h
      cases acc with
      | none =>
        dsimp only at h
        have hall := hnone rfl
        have := ih (walked ++ [x]) (some x) c h (by intro h'; cases h') (by
          intro b hb; cases hb
          refine ⟨hx, walked, [], by simp, ?_, ?_⟩
          · intro d hd hde; rw [hall d hd] at hde; cases hde
          · intro d hd hde
            rcases List.mem_append.mp hd with hd | hd
            · rw [hall d hd] at hde; cases hde
            · simp at hd; subst hd; exact Nat.le_refl _)
        simpa using this
      | some b =>
        obtain ⟨hbe, pre, post, hwk, hpre, hmax⟩ := hsome b rfl
        dsimp only at h
        by_cases hw : b.w < x.w
        · rw [if_pos hw] at h
          have := ih (walked ++ [x]) (some x) c h (by intro h'; cases h') (by
            intro b' hb'; cases hb'
            refine ⟨hx, walked, [], by simp, ?_, ?_⟩
            · intro d hd hde; exact Nat.lt_of_le_of_lt (hmax d hd hde) hw
            · intro d hd hde
              rcases List.mem_append.mp hd with hd | hd
              · exact Nat.le_trans (hmax d hd hde) (Nat.le_of_lt hw)
              · simp at hd; subst hd; exact Nat.le_refl _)
          simpa using this
        · rw [if_neg hw] at h
          have := ih (walked ++ [x]) (some b) c h (by intro h'; cases h') (by
            intro b' hb'; cases hb'
            refine ⟨hbe, pre, post ++ [x], by simp [hwk], hpre, ?_⟩
            intro d hd hde
            rcases List.mem_append.mp hd with hd | hd
            · exact hmax d hd hde
            · simp at hd; subst hd; exact Nat.le_of_not_lt hw)
          simpa using this
    · rw [if_neg hx] at h
      have hxf : eligible p x = false := by simpa using hx
      have := ih (walked ++ [x]) acc c h
        (by intro hn d hd
            rcases List.mem_append.mp hd with hd | hd
            · exact hnone hn d hd
            · simp at hd; subst hd; exact hxf)
        (by intro b hb
            obtain ⟨hbe, pre, post, hwk, hpre, hmax⟩ := hsome b hb
            refine ⟨hbe, pre, post ++ [x], by simp [hwk], hpre, ?_⟩
            intro d hd hde
            rcases List.mem_append.mp hd with hd | hd
            · exact hmax d hd hde
            · simp at hd; subst hd; rw [hxf] at hde; cases hde)
      simpa using this

/-- [R18] Tie-break: every eligible candidate listed before the selected one
is strictly lighter, so on equal weights the earliest-listed one wins. -/
theorem best_first {p : Params} {cs : List Cand} {c : Cand} (h : best p cs = some c) :
    ∃ pre post, cs = pre ++ c :: post ∧ (∀ d ∈ pre, eligible p d = true → d.w < c.w) := by
  have := bestAux_first p cs [] none c h (by intro _ d hd; cases hd) (by intro b hb; cases hb)
  simpa using this

/-- [R18] `best` meets its specification. -/
theorem best_spec {p : Params} {cs : List Cand} {c : Cand} (h : best p cs = some c) :
    ∃ pre post, BestAt p cs pre c post := by
  obtain ⟨pre, post, hcs, hpre⟩ := best_first h
  exact ⟨pre, post, hcs, (best_sound h).2, best_max h, hpre⟩

/-- [R18] The specification picks out one candidate: two positions that both
meet it hold the same candidate. Hence best mode is a function of
(weights, eligibility, order) and nothing else. -/
theorem best_unique {p : Params} {cs pre₁ post₁ pre₂ post₂ : List Cand} {c₁ c₂ : Cand}
    (h₁ : BestAt p cs pre₁ c₁ post₁) (h₂ : BestAt p cs pre₂ c₂ post₂) : c₁ = c₂ := by
  obtain ⟨e₁, el₁, mx₁, pr₁⟩ := h₁
  obtain ⟨e₂, el₂, mx₂, pr₂⟩ := h₂
  have heq : pre₁ ++ c₁ :: post₁ = pre₂ ++ c₂ :: post₂ := e₁.symm.trans e₂
  have hc₁ : c₁ ∈ cs := by rw [e₁]; simp
  have hc₂ : c₂ ∈ cs := by rw [e₂]; simp
  rcases List.append_eq_append_iff.mp heq with ⟨a', hpre, hrest⟩ | ⟨c', hpre, hrest⟩
  · -- pre₂ = pre₁ ++ a', c₁ :: post₁ = a' ++ c₂ :: post₂
    cases a' with
    | nil => simp at hrest; exact hrest.1
    | cons y ys =>
      simp at hrest
      obtain ⟨hy, _⟩ := hrest
      subst hy
      have hin : c₁ ∈ pre₂ := by rw [hpre]; simp
      have h1 := pr₂ c₁ hin el₁
      have h2 := mx₁ c₂ hc₂ el₂
      exact absurd h1 (Nat.not_lt_of_le h2)
  · -- pre₁ = pre₂ ++ c', c₂ :: post₂ = c' ++ c₁ :: post₁
    cases c' with
    | nil => simp at hrest; exact hrest.1.symm
    | cons y ys =>
      simp at hrest
      obtain ⟨hy, _⟩ := hrest
      subst hy
      have hin : c₂ ∈ pre₁ := by rw [hpre]; simp
      have h1 := pr₁ c₂ hin el₂
      have h2 := mx₂ c₁ hc₁ el₁
      exact absurd h1 (Nat.not_lt_of_le h2)

theorem bestAux_none (p : Params) :
    ∀ (cs : List Cand) (acc : Option Cand),
      bestAux p acc cs = none → acc = none ∧ ∀ d ∈ cs, eligible p d = false := by
  intro cs
  induction cs with
  | nil => intro acc h; exact ⟨h, by intro d hd; cases hd⟩
  | cons x xs ih =>
    intro acc h
    simp only [bestAux] at h
    by_cases hx : eligible p x = true
    · rw [if_pos hx] at h
      cases acc with
      | none => dsimp only at h; exact absurd (ih _ h).1 (by simp)
      | some b =>
        dsimp only at h
        by_cases hw : b.w < x.w
        · rw [if_pos hw] at h; exact absurd (ih _ h).1 (by simp)
        · rw [if_neg hw] at h; exact absurd (ih _ h).1 (by simp)
    · rw [if_neg hx] at h
      obtain ⟨h1, h2⟩ := ih _ h
      refine ⟨h1, ?_⟩
      intro d hd
      cases hd with
      | head => simpa using hx
      | tail _ hd' => exact h2 d hd'

/-- [R20] Best mode selects nothing exactly when no candidate is eligible. -/
theorem best_none_iff {p : Params} {cs : List Cand} :
    best p cs = none ↔ ∀ d ∈ cs, eligible p d = false := by
  constructor
  · intro h; exact (bestAux_none p cs none h).2
  · intro hall
    cases h : best p cs with
    | none => rfl
    | some c =>
      have := (best_sound h)
      rw [hall c this.1] at this
      cases this.2

/-- [R18] Completeness: a candidate meeting the specification is what `best`
returns. -/
theorem best_complete {p : Params} {cs pre post : List Cand} {c : Cand}
    (h : BestAt p cs pre c post) : best p cs = some c := by
  cases hb : best p cs with
  | none =>
    have hc : c ∈ cs := by rw [h.1]; simp
    have := best_none_iff.mp hb c hc
    rw [h.2.1] at this; cases this
  | some c' =>
    obtain ⟨pre', post', h'⟩ := best_spec hb
    rw [best_unique h' h]

/-! ## Weighted mode -/

def total (p : Params) : List Cand → Nat
  | [] => 0
  | c :: cs => ew p c + total p cs

/-- `pickWeighted`: the candidate whose cumulative-weight interval holds `r`. -/
def pick (p : Params) : List Cand → Nat → Option Cand
  | [], _ => none
  | c :: cs, r => if r < ew p c then some c else pick p cs (r - ew p c)

/-- [R16, R17, R19] Weighted mode only ever selects an eligible member of the
set with a positive weight: never outside the support of the weights. -/
theorem pick_sound {p : Params} :
    ∀ {cs : List Cand} {r : Nat} {c : Cand}, pick p cs r = some c →
      c ∈ cs ∧ eligible p c = true ∧ 0 < ew p c := by
  intro cs
  induction cs with
  | nil => intro r c h; cases h
  | cons x xs ih =>
    intro r c h
    simp only [pick] at h
    by_cases hr : r < ew p x
    · rw [if_pos hr] at h
      cases h
      have hpos : 0 < ew p x := Nat.lt_of_le_of_lt (Nat.zero_le r) hr
      exact ⟨List.mem_cons_self .., ew_pos_eligible hpos, hpos⟩
    · rw [if_neg hr] at h
      obtain ⟨h1, h2, h3⟩ := ih h
      exact ⟨List.mem_cons_of_mem _ h1, h2, h3⟩

/-- [R19] Every draw below the total selects something. -/
theorem pick_some {p : Params} :
    ∀ {cs : List Cand} {r : Nat}, r < total p cs → ∃ c, pick p cs r = some c := by
  intro cs
  induction cs with
  | nil => intro r h; simp [total] at h
  | cons x xs ih =>
    intro r h
    simp only [pick]
    by_cases hr : r < ew p x
    · exact ⟨x, by rw [if_pos hr]⟩
    · rw [if_neg hr]
      apply ih
      simp only [total] at h
      omega

theorem total_zero_iff {p : Params} :
    ∀ {cs : List Cand}, total p cs = 0 ↔ ∀ d ∈ cs, eligible p d = false := by
  intro cs
  induction cs with
  | nil => simp [total]
  | cons x xs ih =>
    simp only [total]
    constructor
    · intro h d hd
      cases hd with
      | head =>
        cases he : eligible p x with
        | false => rfl
        | true =>
          have := eligible_w_pos he
          rw [ew_of_eligible he] at h; omega
      | tail _ hd' => exact ih.mp (by omega) d hd'
    · intro h
      have hx := ew_of_not_eligible (h x (List.mem_cons_self ..))
      have := ih.mpr (fun d hd => h d (List.mem_cons_of_mem _ hd))
      omega

/-- [R20] Weighted mode selects nothing for any draw exactly when no candidate
is eligible. -/
theorem pick_none_iff {p : Params} {cs : List Cand} :
    (∀ r, pick p cs r = none) ↔ ∀ d ∈ cs, eligible p d = false := by
  constructor
  · intro h
    apply total_zero_iff.mp
    cases ht : total p cs with
    | zero => rfl
    | succ n =>
      obtain ⟨c, hc⟩ := pick_some (p := p) (cs := cs) (r := 0) (by omega)
      rw [h 0] at hc; cases hc
  · intro h r
    cases hp : pick p cs r with
    | none => rfl
    | some c =>
      have := pick_sound hp
      rw [h c this.1] at this; cases this.2.1

/-! ### The distribution

`cnt f n` counts the draws `r < n` with `f r`. -/

def cnt (f : Nat → Bool) : Nat → Nat
  | 0 => 0
  | n + 1 => cnt f n + (if f n then 1 else 0)

theorem cnt_add (f : Nat → Bool) (a : Nat) :
    ∀ b, cnt f (a + b) = cnt f a + cnt (fun r => f (a + r)) b := by
  intro b
  induction b with
  | zero => simp [cnt]
  | succ b ih =>
    rw [← Nat.add_assoc, cnt, ih, cnt]
    omega

theorem cnt_const_true (f : Nat → Bool) :
    ∀ n, (∀ r, r < n → f r = true) → cnt f n = n := by
  intro n
  induction n with
  | zero => intro _; rfl
  | succ n ih =>
    intro h
    rw [cnt, ih (fun r hr => h r (by omega)), h n (by omega)]
    rfl

theorem cnt_const_false (f : Nat → Bool) :
    ∀ n, (∀ r, r < n → f r = false) → cnt f n = 0 := by
  intro n
  induction n with
  | zero => intro _; rfl
  | succ n ih =>
    intro h
    rw [cnt, ih (fun r hr => h r (by omega)), h n (by omega)]
    rfl

theorem cnt_congr (f g : Nat → Bool) :
    ∀ n, (∀ r, r < n → f r = g r) → cnt f n = cnt g n := by
  intro n
  induction n with
  | zero => intro _; rfl
  | succ n ih =>
    intro h
    rw [cnt, cnt, ih (fun r hr => h r (by omega)), h n (by omega)]

/-- How many of the draws `0 ≤ r < total` select `c`. -/
def selCount (p : Params) (cs : List Cand) (c : Cand) : Nat :=
  cnt (fun r => decide (pick p cs r = some c)) (total p cs)

theorem selCount_not_mem {p : Params} {cs : List Cand} {c : Cand} (h : c ∉ cs) :
    selCount p cs c = 0 := by
  unfold selCount
  apply cnt_const_false
  intro r _
  cases hp : pick p cs r with
  | none => simp
  | some c' =>
    have := (pick_sound hp).1
    simp only [decide_eq_false_iff_not, Option.some.injEq]
    intro he; subst he; exact h this

/-- [R19] The distribution: over the `total` equally likely draws, a candidate
is selected exactly `ew c` times, so with probability `ew c / total`. -/
theorem pick_count {p : Params} :
    ∀ {cs : List Cand}, cs.Nodup → ∀ {c : Cand}, c ∈ cs → selCount p cs c = ew p c := by
  intro cs
  induction cs with
  | nil => intro _ c hc; cases hc
  | cons x xs ih =>
    intro hnd c hc
    have hx : x ∉ xs := (List.nodup_cons.mp hnd).1
    have hnd' : xs.Nodup := (List.nodup_cons.mp hnd).2
    unfold selCount
    simp only [total]
    rw [cnt_add]
    -- First block: draws below ew x all select x.
    have hfirst : ∀ r, r < ew p x → pick p (x :: xs) r = some x := by
      intro r hr; simp only [pick]; rw [if_pos hr]
    -- Second block: draws shifted past ew x walk on into xs.
    have hsecond : ∀ r, pick p (x :: xs) (ew p x + r) = pick p xs r := by
      intro r; simp only [pick]
      rw [if_neg (by omega)]; congr 1; omega
    have h2 : cnt (fun r => decide (pick p (x :: xs) (ew p x + r) = some c)) (total p xs)
        = selCount p xs c := by
      unfold selCount
      apply cnt_congr; intro r _; rw [hsecond]
    rw [h2]
    by_cases hcx : c = x
    · subst hcx
      rw [selCount_not_mem hx]
      rw [cnt_const_true _ _ (fun r hr => by simp [hfirst r hr])]
      omega
    · have hc' : c ∈ xs := by
        cases hc with
        | head => exact absurd rfl hcx
        | tail _ h => exact h
      rw [ih hnd' hc']
      rw [cnt_const_false _ _ (fun r hr => by
        simp only [hfirst r hr, decide_eq_false_iff_not, Option.some.injEq]
        exact fun h => hcx h.symm)]
      omega

theorem total_append (p : Params) (a b : List Cand) :
    total p (a ++ b) = total p a + total p b := by
  induction a with
  | nil => simp [total]
  | cons x xs ih => simp only [List.cons_append, total, ih]; omega

/-- Raising `c`'s weight by `d`, nothing else changed. -/
def raise (c : Cand) (d : Nat) : Cand := { c with w := c.w + d }

theorem ew_raise_ge (p : Params) (c : Cand) (d : Nat) : ew p c ≤ ew p (raise c d) := by
  cases he : eligible p c with
  | false => rw [ew_of_not_eligible he]; exact Nat.zero_le _
  | true =>
    have he' : eligible p (raise c d) = true := by
      simp only [eligible, fresh, raise, Bool.and_eq_true, decide_eq_true_eq] at he ⊢
      exact ⟨he.1, by omega⟩
    rw [ew_of_eligible he, ew_of_eligible he']
    simp [raise]

/-- [R19] Monotonicity: in `pre ++ c :: post`, raising `c`'s score never lowers
its selection probability. With `n = selCount` and `T = total` before, and
`n'`, `T'` after: `n / T ≤ n' / T'`, i.e. `n · T' ≤ n' · T`. -/
theorem pick_monotone (p : Params) (pre post : List Cand) (c : Cand) (d : Nat)
    (h₁ : (pre ++ c :: post).Nodup) (h₂ : (pre ++ raise c d :: post).Nodup) :
    selCount p (pre ++ c :: post) c * total p (pre ++ raise c d :: post)
      ≤ selCount p (pre ++ raise c d :: post) (raise c d) * total p (pre ++ c :: post) := by
  rw [pick_count h₁ (by simp), pick_count h₂ (by simp)]
  simp only [total_append, total]
  have hle := ew_raise_ge p c d
  -- a·(P + a' + Q) ≤ a'·(P + a + Q) with a ≤ a'.
  generalize ew p c = a at *
  generalize ew p (raise c d) = a' at *
  generalize total p pre = P
  generalize total p post = Q
  have : a * (P + Q) ≤ a' * (P + Q) := Nat.mul_le_mul_right _ hle
  have e1 : a * (P + (a' + Q)) = a * (P + Q) + a * a' := by
    rw [Nat.add_comm a' Q, ← Nat.add_assoc, Nat.mul_add]
  have e2 : a' * (P + (a + Q)) = a' * (P + Q) + a * a' := by
    rw [Nat.add_comm a Q, ← Nat.add_assoc, Nat.mul_add, Nat.mul_comm a' a]
  rw [e1, e2]
  omega

/-! ## The decision, with fallback -/

inductive Mode | best | weighted
deriving DecidableEq

inductive Fallback | static | servfail | nodata
deriving DecidableEq

inductive Outcome | answer (c : Cand) | servfail | nodata
deriving DecidableEq

/-- `instance.decide`: `r` is the random draw, reduced below the total as
`rand.Uint64N(total)` does. -/
def select (p : Params) (m : Mode) (cs : List Cand) (r : Nat) : Option Cand :=
  match m with
  | .best => best p cs
  | .weighted => pick p cs (r % total p cs)

def outcome (p : Params) (m : Mode) (fb : Fallback) (cs : List Cand) (r : Nat) : Outcome :=
  match select p m cs r with
  | some c => .answer c
  | none =>
    match fb with
    | .static =>
      match cs with
      | [] => .servfail
      | c :: _ => .answer c
    | .servfail => .servfail
    | .nodata => .nodata

theorem select_sound {p : Params} {m : Mode} {cs : List Cand} {r : Nat} {c : Cand}
    (h : select p m cs r = some c) : c ∈ cs ∧ eligible p c = true := by
  cases m with
  | best => exact best_sound h
  | weighted => exact ⟨(pick_sound h).1, (pick_sound h).2.1⟩

/-- [R20] The fallback applies exactly when nothing is eligible, in either mode. -/
theorem select_none_iff {p : Params} {m : Mode} {cs : List Cand} {r : Nat} :
    select p m cs r = none ↔ ∀ d ∈ cs, eligible p d = false := by
  cases m with
  | best => exact best_none_iff
  | weighted =>
    constructor
    · intro h
      apply total_zero_iff.mp
      cases ht : total p cs with
      | zero => rfl
      | succ n =>
        have hr : r % total p cs < total p cs := Nat.mod_lt _ (by omega)
        obtain ⟨c, hc⟩ := pick_some hr
        simp only [select] at h; rw [h] at hc; cases hc
    · intro h; exact pick_none_iff.mpr h _

/-- [R16] The answered endpoint is always a member of the candidate set. -/
theorem decide_mem {p : Params} {m : Mode} {fb : Fallback} {cs : List Cand} {r : Nat} {c : Cand}
    (h : outcome p m fb cs r = .answer c) : c ∈ cs := by
  unfold outcome at h
  cases hs : select p m cs r with
  | some c' => rw [hs] at h; cases h; exact (select_sound hs).1
  | none =>
    rw [hs] at h
    cases fb <;> simp at h
    cases cs with
    | nil => simp at h
    | cons x xs => simp at h; subst h; exact List.mem_cons_self ..

/-- [R17, R20] An answered endpoint is eligible, unless nothing is eligible and
the fallback is `static`: then it is the first-listed candidate. Unhealthy,
stale, invalid and zero-weight endpoints are never selected otherwise. -/
theorem decide_eligible_or_fallback {p : Params} {m : Mode} {fb : Fallback} {cs : List Cand}
    {r : Nat} {c : Cand} (h : outcome p m fb cs r = .answer c) :
    eligible p c = true ∨
      ((∀ d ∈ cs, eligible p d = false) ∧ fb = .static ∧ cs.head? = some c) := by
  unfold outcome at h
  cases hs : select p m cs r with
  | some c' => rw [hs] at h; cases h; exact Or.inl (select_sound hs).2
  | none =>
    rw [hs] at h
    right
    refine ⟨select_none_iff.mp hs, ?_⟩
    cases fb <;> simp at h
    cases cs with
    | nil => simp at h
    | cons x xs => simp at h; subst h; simp

/-- [R20] With `servfail` or `nodata`, nothing is ever answered unless
something is eligible. -/
theorem decide_strict_fallback {p : Params} {m : Mode} {fb : Fallback} {cs : List Cand}
    {r : Nat} {c : Cand} (hfb : fb ≠ .static) (h : outcome p m fb cs r = .answer c) :
    eligible p c = true := by
  rcases decide_eligible_or_fallback h with h1 | ⟨_, h2, _⟩
  · exact h1
  · exact absurd h2 hfb

/-! ## Evaluated examples (kernel-checked by `decide`) -/

private def pNow : Params := { now := 1000, maxStale := 300, skew := 30 }
private def eu : Cand := { id := 1, w := 8300, valid := true, healthy := true, updated := 990 }
private def us : Cand := { id := 2, w := 8300, valid := true, healthy := true, updated := 995 }
private def ap : Cand := { id := 3, w := 9900, valid := true, healthy := true, updated := 600 }

/-- `ap` scores highest but is 400 s old (stale); `eu` and `us` tie, and `eu`
is listed first. -/
example : best pNow [eu, us, ap] = some eu := by decide
example : best pNow [us, eu, ap] = some us := by decide
/-- Stale and future-dated entries are ineligible. -/
example : eligible pNow ap = false := by decide
example : eligible pNow { eu with updated := 1031 } = false := by decide
example : eligible pNow { eu with updated := 1030 } = true := by decide
/-- Weighted: draws 0..8299 select eu, 8300..16599 select us, ap never. -/
example : pick pNow [eu, us, ap] 8299 = some eu := by decide
example : pick pNow [eu, us, ap] 8300 = some us := by decide
example : total pNow [eu, us, ap] = 16600 := by decide
/-- Nothing eligible: the fallbacks. -/
example : outcome pNow .best .static [ap] 0 = .answer ap := by decide
example : outcome pNow .weighted .servfail [ap] 7 = .servfail := by decide

end GeoScore

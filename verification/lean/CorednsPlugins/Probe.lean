/-!
# Probe query names — `probe/labels.go`, `probe/keytag.go`

Labels are byte strings; a byte is a `Nat`. `.` is 46, `-` 45, `_` 95.

* `parseQuery_case_insensitive`: `ParseQuery` gives the same answer for any
  ASCII case of the same name. Resolvers using 0x20 encoding randomise the
  case of every query they send, so anything else would make a measurement
  depend on a coin flip.
* `parseKeyTag_format`: `ParseKeyTagQuery(FormatKeyTagQuery(tags))` returns
  the tags (sorted, as the format requires) for every legal tag list, i.e.
  the RFC 8145 §5.2 label the server emits is the label it accepts.

The modifier table and the conflict check are parameters (`names`, `okMods`):
the case-insensitivity result holds whatever they contain.
-/

namespace Probe

/-! ## Bytes and labels -/

/-- `toLowerASCII`, per byte. -/
def lower (b : Nat) : Nat := if 65 ≤ b ∧ b ≤ 90 then b + 32 else b

def lowerAll (s : List Nat) : List Nat := s.map lower

theorem lower_idem (b : Nat) : lower (lower b) = lower b := by
  unfold lower
  by_cases h : 65 ≤ b ∧ b ≤ 90
  · rw [if_pos h, if_neg (by omega)]
  · rw [if_neg h, if_neg h]

theorem lowerAll_idem (s : List Nat) : lowerAll (lowerAll s) = lowerAll s := by
  simp [lowerAll, Function.comp_def, lower_idem]

/-- Lower-casing never creates or removes a punctuation byte. -/
theorem lower_eq_punct {b p : Nat} (hp : ¬ (65 ≤ p ∧ p ≤ 90)) (hp' : ¬ (97 ≤ p ∧ p ≤ 122)) :
    lower b = p ↔ b = p := by
  unfold lower; split <;> omega

/-- `strings.Split(s, sep)`. -/
def splitOn (sep : Nat) : List Nat → List (List Nat)
  | [] => [[]]
  | c :: cs =>
    if c = sep then [] :: splitOn sep cs
    else match splitOn sep cs with
      | l :: ls => (c :: l) :: ls
      | [] => [[c]]

/-- `strings.Join(ls, sep)`. -/
def joinWith (sep : Nat) : List (List Nat) → List Nat
  | [] => []
  | [l] => l
  | l :: l' :: ls => l ++ sep :: joinWith sep (l' :: ls)

theorem splitOn_ne_nil (sep : Nat) (s : List Nat) : splitOn sep s ≠ [] := by
  cases s with
  | nil => simp [splitOn]
  | cons c cs =>
    unfold splitOn
    split
    · simp
    · split <;> simp

theorem splitOn_lower {sep : Nat} (hs : ∀ b, lower b = sep ↔ b = sep) (s : List Nat) :
    splitOn sep (lowerAll s) = (splitOn sep s).map lowerAll := by
  induction s with
  | nil => rfl
  | cons c cs ih =>
    simp only [lowerAll, List.map_cons] at ih ⊢
    by_cases hc : c = sep
    · subst hc
      have hl : lower c = c := (hs c).2 rfl
      rw [splitOn, splitOn, hl, if_pos rfl, if_pos rfl, ih]
      rfl
    · have : lower c ≠ sep := fun h => hc ((hs c).1 h)
      rw [splitOn, splitOn]
      simp only [this, hc, if_false, ih]
      cases h : splitOn sep cs with
      | nil => exact absurd h (splitOn_ne_nil sep cs)
      | cons l ls => simp [lowerAll]

/-- `split ∘ join` is the identity when no piece contains the separator. -/
theorem splitOn_joinWith (sep : Nat) (ls : List (List Nat)) (hne : ls ≠ [])
    (h : ∀ l ∈ ls, sep ∉ l) : splitOn sep (joinWith sep ls) = ls := by
  -- Splitting a separator-free piece followed by more input.
  have piece : ∀ (l rest : List Nat) (r : List (List Nat)), sep ∉ l →
      splitOn sep rest = r → r ≠ [] →
      splitOn sep (l ++ rest) = match r with | x :: xs => (l ++ x) :: xs | [] => [] := by
    intro l
    induction l with
    | nil => intro rest r _ hr hrn; cases r with
      | nil => exact absurd rfl hrn
      | cons x xs => simpa using hr
    | cons c cs ih =>
      intro rest r hl hr hrn
      have hc : c ≠ sep := fun e => hl (e ▸ List.mem_cons_self)
      have hcs : sep ∉ cs := fun m => hl (List.mem_cons_of_mem _ m)
      rw [List.cons_append, splitOn, if_neg hc, ih rest r hcs hr hrn]
      cases r with
      | nil => exact absurd rfl hrn
      | cons x xs => simp
  induction ls with
  | nil => exact absurd rfl hne
  | cons l ls ih =>
    cases ls with
    | nil =>
      have := piece l [] [[]] (h l (by simp)) rfl (by simp)
      simpa [joinWith] using this
    | cons l' ls' =>
      have hrest := ih (by simp) (fun x hx => h x (by simp [hx]))
      have hsep : splitOn sep (sep :: joinWith sep (l' :: ls')) = [] :: (l' :: ls') := by
        rw [splitOn, if_pos rfl, hrest]
      have := piece l _ _ (h l (by simp)) hsep (by simp)
      simpa [joinWith] using this


/-- `strings.TrimSuffix(s, ".")`. -/
def trimDot (s : List Nat) : List Nat := if s.getLast? = some 46 then s.dropLast else s

theorem trimDot_lower (s : List Nat) : trimDot (lowerAll s) = lowerAll (trimDot s) := by
  unfold trimDot lowerAll
  rw [List.getLast?_map]
  cases h : s.getLast? with
  | none => simp
  | some b =>
    have e := lower_eq_punct (b := b) (p := 46) (by omega) (by omega)
    by_cases hb : b = 46
    · simp [hb, lower, List.map_dropLast]
    · have : lower b ≠ 46 := fun x => hb (e.1 x)
      simp [hb, this]

/-! ## `ParseQuery` -/

def isHex (b : Nat) : Bool := (48 ≤ b && b ≤ 57) || (97 ≤ b && b ≤ 102)

/-- `parseToken`: 8–32 bytes, hex after lower-casing; returns it lowered. -/
def parseToken (l : List Nat) : Option (List Nat) :=
  if l.length < 8 ∨ l.length > 32 then none
  else if (lowerAll l).all isHex then some (lowerAll l) else none

/-- The modifier loop: each label must be `_` then a known name (looked up
lower-cased), with no repeats. -/
def parseMods (names : List Nat → Option Nat) : List (List Nat) → Nat → Option Nat
  | [], acc => some acc
  | (95 :: name) :: ls, acc =>
    match names (lowerAll name) with
    | none => none
    | some m => if acc &&& m = m then none else parseMods names ls (acc ||| m)
  | _ :: _, _ => none

/-- `ParseQuery`. `okMods` is the conflict-group check. -/
def parseQuery (names : List Nat → Option Nat) (okMods : Nat → Bool) (sub : List Nat) :
    Option (List Nat × Nat) :=
  let s := trimDot sub
  if s = [] then none
  else
    let labels := splitOn 46 s
    match parseToken (labels.getLast?.getD []) with
    | none => none
    | some tok =>
      match parseMods names labels.dropLast 0 with
      | none => none
      | some mods => if okMods mods then some (tok, mods) else none

theorem parseToken_lower (l : List Nat) : parseToken (lowerAll l) = parseToken l := by
  simp [parseToken, lowerAll, lower_idem, Function.comp_def]

theorem parseMods_lower (names : List Nat → Option Nat) (ls : List (List Nat)) (acc : Nat) :
    parseMods names (ls.map lowerAll) acc = parseMods names ls acc := by
  induction ls generalizing acc with
  | nil => rfl
  | cons l ls ih =>
    have e : ∀ b, lower b = 95 ↔ b = 95 := fun _ => lower_eq_punct (by omega) (by omega)
    cases l with
    | nil => simp [lowerAll, parseMods]
    | cons b name =>
      by_cases hb : b = 95
      · subst hb
        simp only [List.map_cons, lowerAll]
        show parseMods names ((lower 95 :: name.map lower) :: ls.map lowerAll) acc = _
        rw [show lower 95 = 95 by decide]
        simp only [parseMods]
        rw [show lowerAll (name.map lower) = lowerAll (lowerAll name) from rfl, lowerAll_idem]
        cases names (lowerAll name) with
        | none => rfl
        | some m => simp only; split
                    · rfl
                    · exact ih _
      · have hl : lower b ≠ 95 := fun x => hb ((e b).1 x)
        simp only [List.map_cons, lowerAll]
        rw [parseMods.eq_def, parseMods.eq_def]
        simp [hl, hb]

/-- **0x20 safety.** `ParseQuery` cannot tell two ASCII casings of a name
apart: same token (lower-cased), same modifiers, same accept/refuse. -/
theorem parseQuery_case_insensitive (names : List Nat → Option Nat) (okMods : Nat → Bool)
    (sub : List Nat) : parseQuery names okMods (lowerAll sub) = parseQuery names okMods sub := by
  have hdot : ∀ b, lower b = 46 ↔ b = 46 := fun _ => lower_eq_punct (by omega) (by omega)
  unfold parseQuery
  simp only [trimDot_lower]
  by_cases he : trimDot sub = []
  · simp [he, lowerAll]
  · have he' : lowerAll (trimDot sub) ≠ [] := by simpa [lowerAll] using he
    simp only [he, he', if_false, splitOn_lower hdot]
    rw [List.getLast?_map, ← List.map_dropLast, parseMods_lower]
    cases h : (splitOn 46 (trimDot sub)).getLast? with
    | none => simp
    | some l => simp [parseToken_lower]

/-- Hence any two names equal up to ASCII case get the same answer. -/
theorem parseQuery_same_up_to_case (names : List Nat → Option Nat) (okMods : Nat → Bool)
    (a b : List Nat) (h : lowerAll a = lowerAll b) :
    parseQuery names okMods a = parseQuery names okMods b := by
  rw [← parseQuery_case_insensitive names okMods a, h, parseQuery_case_insensitive]

/-! ## RFC 8145 key tag labels -/

/-- One hex digit as `%04x` renders it (lower case). -/
def hexDigit (d : Nat) : Nat := if d < 10 then 48 + d else 87 + d

/-- `strconv.ParseUint(_, 16, _)` for one digit: either case. -/
def hexVal (b : Nat) : Option Nat :=
  if 48 ≤ b ∧ b ≤ 57 then some (b - 48)
  else if 97 ≤ b ∧ b ≤ 102 then some (b - 87)
  else if 65 ≤ b ∧ b ≤ 70 then some (b - 55)
  else none

theorem hexVal_hexDigit (d : Nat) (h : d < 16) : hexVal (hexDigit d) = some d := by
  unfold hexVal hexDigit; split <;> split <;> (try split) <;> (try split) <;> simp <;> omega

/-- `%04x`. -/
def formatTag (n : Nat) : List Nat :=
  [hexDigit (n / 4096 % 16), hexDigit (n / 256 % 16), hexDigit (n / 16 % 16), hexDigit (n % 16)]

/-- "Exactly four hex digits", then `ParseUint`. -/
def parseTag : List Nat → Option Nat
  | [a, b, c, d] => do
    let a ← hexVal a; let b ← hexVal b; let c ← hexVal c; let d ← hexVal d
    pure (((a * 16 + b) * 16 + c) * 16 + d)
  | _ => none

theorem parseTag_formatTag (n : Nat) (h : n < 65536) : parseTag (formatTag n) = some n := by
  simp only [formatTag, parseTag, hexVal_hexDigit _ (Nat.mod_lt _ (by decide)),
    Option.bind_eq_bind, Option.bind_some, Option.pure_def, Option.some.injEq]
  omega

/-- `_ta-`. -/
def prefix_ : List Nat := [95, 116, 97, 45]

/-- `FormatKeyTagQuery`, on the already-sorted copy it renders. -/
def formatLabel (ts : List Nat) : List Nat := prefix_ ++ joinWith 45 (ts.map formatTag)

/-- `ParseKeyTagQuery`. -/
def parseKeyTag (label : List Nat) : Option (List Nat) :=
  if 46 ∈ label then none                                    -- not the only label
  else if lowerAll (label.take 4) ≠ prefix_ then none        -- not `_ta-`
  else
    let rest := label.drop 4
    if rest = [] then none
    else
      let parts := splitOn 45 rest
      if parts.length > 16 then none
      else parts.mapM parseTag

/-- `%04x` only ever emits hex digit bytes. -/
theorem formatTag_hex {n p : Nat} (h : p ∈ formatTag n) :
    (48 ≤ p ∧ p ≤ 57) ∨ (97 ≤ p ∧ p ≤ 102) := by
  have hd : ∀ d, d < 16 → (48 ≤ hexDigit d ∧ hexDigit d ≤ 57) ∨ (97 ≤ hexDigit d ∧ hexDigit d ≤ 102) := by
    intro d hd; unfold hexDigit; split <;> omega
  simp only [formatTag, List.mem_cons, List.not_mem_nil, or_false] at h
  rcases h with rfl | rfl | rfl | rfl <;> exact hd _ (Nat.mod_lt _ (by decide))

theorem not_mem_joinWith {sep p : Nat} (hp : p ≠ sep) (ls : List (List Nat))
    (h : ∀ l ∈ ls, p ∉ l) : p ∉ joinWith sep ls := by
  induction ls with
  | nil => simp [joinWith]
  | cons l ls ih =>
    cases ls with
    | nil => simpa [joinWith] using h l (by simp)
    | cons l' ls' =>
      simp only [joinWith, List.mem_append, List.mem_cons, not_or]
      exact ⟨h l (by simp), fun e => hp e, ih (fun x hx => h x (by simp [hx]))⟩

theorem mapM_parseTag (ts : List Nat) (h : ∀ t ∈ ts, t < 65536) :
    (ts.map formatTag).mapM parseTag = some ts := by
  induction ts with
  | nil => rfl
  | cons t ts ih =>
    simp only [List.map_cons, List.mapM_cons, parseTag_formatTag t (h t (by simp)),
      ih (fun x hx => h x (by simp [hx]))]
    rfl

/-- `_TA-4444` (any case): one tag, 0x4444. -/
example : parseKeyTag [95, 84, 65, 45, 52, 52, 52, 52] = some [0x4444] := by decide
/-- `_ta-635` is refused: RFC 8145 says MUST zero-pad. -/
example : parseKeyTag [95, 116, 97, 45, 54, 51, 53] = none := by decide
/-- `_ta-0635-7aae-aa1b`, the docstring example. -/
example : parseKeyTag (formatLabel [0x0635, 0x7aae, 0xaa1b]) = some [0x0635, 0x7aae, 0xaa1b] := by
  decide

/-- **Round trip.** For every list of 1 to 16 key tags (`maxKeyTagsPerQuery`)
the label `FormatKeyTagQuery` renders is one `ParseKeyTagQuery` accepts, and
it decodes to exactly the tags rendered. -/
theorem parseKeyTag_format (ts : List Nat) (h1 : ts ≠ []) (h16 : ts.length ≤ 16)
    (hr : ∀ t ∈ ts, t < 65536) : parseKeyTag (formatLabel ts) = some ts := by
  have hne : ts.map formatTag ≠ [] := by simpa using h1
  have hnodash : ∀ l ∈ ts.map formatTag, 45 ∉ l := by
    intro l hl m
    obtain ⟨t, _, rfl⟩ := List.mem_map.1 hl
    have := formatTag_hex m; omega
  have hnodot : 46 ∉ formatLabel ts := by
    simp only [formatLabel, prefix_, List.cons_append, List.nil_append, List.mem_cons,
      not_or]
    refine ⟨by decide, by decide, by decide, by decide, ?_⟩
    apply not_mem_joinWith (by decide)
    intro l hl m
    obtain ⟨t, _, rfl⟩ := List.mem_map.1 hl
    have := formatTag_hex m; omega
  have hrest : (formatLabel ts).drop 4 = joinWith 45 (ts.map formatTag) := by
    simp [formatLabel, prefix_]
  have hpre : (formatLabel ts).take 4 = prefix_ := by simp [formatLabel, prefix_]
  have hrestne : joinWith 45 (ts.map formatTag) ≠ [] := by
    cases ts with
    | nil => exact absurd rfl h1
    | cons t ts' =>
      cases ts' with
      | nil => simp [joinWith, formatTag]
      | cons _ _ => simp [joinWith, formatTag]
  unfold parseKeyTag
  rw [if_neg hnodot, hpre, if_neg (by decide), hrest, if_neg hrestne,
    splitOn_joinWith 45 _ hne hnodash, if_neg (by simpa using h16)]
  exact mapM_parseTag ts hr

end Probe

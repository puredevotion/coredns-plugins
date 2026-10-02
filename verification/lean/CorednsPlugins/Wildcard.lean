/-!
# SNI certificate selection — `sni_tls/sni_tls.go`

```go
func (s *certStore) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if hello.ServerName == "" {
		switch s.noSNI { // The `no_sni` option.
		case noSNIRefuse:      return nil, nil
		case noSNIFallback:    return s.fallback, nil
		case noSNICertificate: return s.noSNICert, nil
		case noSNIAsUnmatched: // The default: fall through.
		}
	} else {
		name := asciiLower(hello.ServerName)
		if cert, ok := s.byName[name]; ok { return cert, nil }
		if wildcard, ok := wildcardOf(name); ok {
			if cert, ok := s.byName[wildcard]; ok { return cert, nil }
		}
	}
	if s.strict { return nil, nil } // crypto/tls sends unrecognized_name(112)
	return s.fallback, nil
}

func wildcardOf(name string) (string, bool) {
	i := strings.IndexByte(name, '.')
	if i <= 0 { return "", false }
	return "*" + name[i:], true
}
```

Names are modelled as `List Char` already lower-cased, and `byName` as a
partial function, and the refusal `(nil, nil)` as `none`. The rule formalised is RFC 9525 §6.3 (which obsoletes
RFC 6125): "A wildcard in a presented identifier can only match one label
in a reference identifier", with "the wildcard character [appearing] only as
the complete content of the left-most label". RFC 9525 states it for the
client; the server applies it so as never to select a certificate a client
would reject.

Case folding is modelled separately, per byte, at the end (`foldByte`):
`asciiLower` folds A-Z only, as RFC 9525 §6.3 ("case-insensitive ASCII
comparison") and RFC 4343 §3 require. The Go code used Unicode
`strings.ToLower` until this change, under which a non-ASCII SNI (U+212A
KELVIN SIGN, say) folded onto an ASCII SAN; `fold_nonascii_fixed` and
`kelvin_not_k` show it no longer can.
-/

namespace Wildcard

/-- `"*" + name[i:]` for the first `.` at `i`, whatever `i` is. -/
def fromFirstDot : List Char → Option (List Char)
  | [] => none
  | c :: cs => if c = '.' then some ('*' :: '.' :: cs) else fromFirstDot cs

/-- `wildcardOf`: replace the first label with `*`, provided there is a
first label, i.e. `i > 0`. -/
def wildcardOf : List Char → Option (List Char)
  | [] => none
  | c :: cs => if c = '.' then none else fromFirstDot cs

theorem fromFirstDot_shape {s w : List Char} (h : fromFirstDot s = some w) :
    ∃ d, w = '*' :: '.' :: d := by
  induction s with
  | nil => simp [fromFirstDot] at h
  | cons c cs ih =>
    unfold fromFirstDot at h
    split at h
    · exact ⟨cs, (Option.some.inj h).symm⟩
    · exact ih h

/-- The result, when there is one, always has the shape `*.<suffix>`. -/
theorem wildcardOf_shape {s w : List Char} (h : wildcardOf s = some w) :
    ∃ d, w = '*' :: '.' :: d := by
  cases s with
  | nil => simp [wildcardOf] at h
  | cons c cs =>
    unfold wildcardOf at h
    by_cases hc : c = '.'
    · simp [hc] at h
    · simp only [hc, if_false] at h; exact fromFirstDot_shape h

theorem fromFirstDot_eq_iff (s d : List Char) :
    fromFirstDot s = some ('*' :: '.' :: d) ↔ ∃ l, '.' ∉ l ∧ s = l ++ '.' :: d := by
  induction s with
  | nil => simp [fromFirstDot]
  | cons c cs ih =>
    unfold fromFirstDot
    by_cases hc : c = '.'
    · subst hc
      simp only [if_true, Option.some.injEq, List.cons.injEq, true_and]
      constructor
      · intro h; exact ⟨[], by simp, by simp [h]⟩
      · rintro ⟨l, hl, he⟩
        cases l with
        | nil => simpa using he
        | cons x xs =>
          simp only [List.cons_append, List.cons.injEq] at he
          exact absurd (he.1 ▸ List.mem_cons_self) hl
    · simp only [if_neg hc]
      rw [ih]
      constructor
      · rintro ⟨l, hl, he⟩
        exact ⟨c :: l, by simp [hl, Ne.symm hc], by simp [he]⟩
      · rintro ⟨l, hl, he⟩
        cases l with
        | nil => simp at he; exact absurd he.1 hc
        | cons x xs =>
          simp only [List.cons_append, List.cons.injEq] at he
          exact ⟨xs, fun h => hl (List.mem_cons_of_mem _ h), he.2⟩

/-- Exact characterisation: `wildcardOf s` is `*.d` precisely when `s` is a
non-empty, dot-free first label `l`, a dot, then `d`. -/
theorem wildcardOf_eq_iff (s d : List Char) :
    wildcardOf s = some ('*' :: '.' :: d) ↔
      ∃ l, l ≠ [] ∧ '.' ∉ l ∧ s = l ++ '.' :: d := by
  cases s with
  | nil => simp [wildcardOf]
  | cons c cs =>
    unfold wildcardOf
    by_cases hc : c = '.'
    · subst hc
      simp only [if_true, reduceCtorEq, false_iff, not_exists, not_and]
      intro l hne hl he
      cases l with
      | nil => exact hne rfl
      | cons x xs =>
        simp only [List.cons_append, List.cons.injEq] at he
        exact hl (he.1 ▸ List.mem_cons_self)
    · simp only [if_neg hc]
      rw [fromFirstDot_eq_iff]
      constructor
      · rintro ⟨l, hl, he⟩
        exact ⟨c :: l, by simp, by simp [hl, Ne.symm hc], by simp [he]⟩
      · rintro ⟨l, _, hl, he⟩
        cases l with
        | nil => simp at he; exact absurd he.1 hc
        | cons x xs =>
          simp only [List.cons_append, List.cons.injEq] at he
          exact ⟨xs, fun h => hl (List.mem_cons_of_mem _ h), he.2⟩

/-- RFC 9525 §6.3, one label: `*.example.com` must not cover `example.com`
itself (zero labels). -/
theorem wildcard_not_apex (d : List Char) :
    wildcardOf d ≠ some ('*' :: '.' :: d) := by
  intro h
  obtain ⟨l, _, _, he⟩ := (wildcardOf_eq_iff d d).1 h
  have := congrArg List.length he
  simp at this
  omega

/-- RFC 9525 §6.3, one label: `*.example.com` does not cover
`a.b.example.com` (two labels): any name the wildcard covers has exactly one
extra label. -/
theorem wildcard_single_label (l₁ l₂ d : List Char) (h₁ : '.' ∉ l₁) :
    wildcardOf (l₁ ++ '.' :: l₂ ++ '.' :: d) ≠ some ('*' :: '.' :: d) := by
  intro h
  obtain ⟨l, _, hl, he⟩ := (wildcardOf_eq_iff _ d).1 h
  -- Both sides split at their first dot; l₁ and l are dot-free, so l = l₁.
  have key : ∀ (a b : List Char) (x y : List Char), '.' ∉ a → '.' ∉ b →
      a ++ '.' :: x = b ++ '.' :: y → a = b ∧ x = y := by
    intro a
    induction a with
    | nil =>
      intro b x y _ hb e
      cases b with
      | nil => simpa using e
      | cons z zs =>
        simp only [List.nil_append, List.cons_append, List.cons.injEq] at e
        exact absurd (e.1 ▸ List.mem_cons_self) hb
    | cons z zs ih =>
      intro b x y ha hb e
      cases b with
      | nil =>
        simp only [List.nil_append, List.cons_append, List.cons.injEq] at e
        exact absurd (e.1 ▸ List.mem_cons_self) ha
      | cons w ws =>
        simp only [List.cons_append, List.cons.injEq] at e
        have := ih ws x y (fun h => ha (List.mem_cons_of_mem _ h))
          (fun h => hb (List.mem_cons_of_mem _ h)) e.2
        exact ⟨by rw [e.1, this.1], this.2⟩
  have := key l₁ l (l₂ ++ '.' :: d) d h₁ hl (by simpa [List.append_assoc] using he)
  have hlen := congrArg List.length this.2
  simp at hlen
  omega

/-- RFC 9525 §6.3, one label: an empty first label is not a label, so
`.example.com` has no wildcard form. (Before the `i <= 0` check,
`wildcardOf` returned `*.example.com` here.) -/
theorem empty_label_no_wildcard (d : List Char) : wildcardOf ('.' :: d) = none := by
  simp [wildcardOf]

/-- The SAN lookup half of `GetCertificate`: exact key, then wildcard key. -/
def lookup {C : Type} (byName : List Char → Option C) (sni : List Char) : Option C :=
  if sni = [] then none
  else match byName sni with
    | some c => some c
    | none => (wildcardOf sni).bind byName

/-- The `no_sni` option: what a ClientHello without SNI gets. -/
inductive NoSNI
  | asUnmatched  -- default: like an unmatched SNI
  | refuse
  | fallback
  | cert         -- the separately configured `no_sni cert`

/-- `GetCertificate`, with the `byName` map as a partial function. `none`
is the handshake refusal; `noSNICert` is `none` while that cert's files are
missing. -/
def getCertificate {C : Type} (byName : List Char → Option C) (fallback : C)
    (strict : Bool) (noSNI : NoSNI) (noSNICert : Option C) (sni : List Char) : Option C :=
  let unmatched := if strict then none else some fallback
  if sni = [] then
    match noSNI with
    | .refuse => none
    | .fallback => some fallback
    | .cert => noSNICert
    | .asUnmatched => unmatched
  else match lookup byName sni with
    | some c => some c
    | none => unmatched

/-- Strict mode never answers a client that sent SNI with a cert that wasn't
selected by an exact or wildcard SAN key, whatever `no_sni` says, so the
fallback can't leak out to an unmatched name. -/
theorem strict_only_matched {C : Type} (byName : List Char → Option C) (fb : C)
    (p : NoSNI) (nc : Option C) (sni : List Char) (c : C) (hne : sni ≠ [])
    (h : getCertificate byName fb true p nc sni = some c) :
    byName sni = some c ∨ ∃ w, wildcardOf sni = some w ∧ byName w = some c := by
  have hl : lookup byName sni = some c := by
    simp only [getCertificate, hne, if_false] at h
    cases hl : lookup byName sni <;> simp_all
  simp only [lookup, hne, if_false] at hl
  cases hb : byName sni with
  | some c' => simp_all
  | none =>
    simp only [hb] at hl
    cases hw : wildcardOf sni with
    | none => simp [hw] at hl
    | some w => simp only [hw, Option.bind_some] at hl; exact Or.inr ⟨w, rfl, hl⟩

/-- `no_sni` changes nothing for a client that sent SNI. -/
theorem noSNI_irrelevant_with_sni {C : Type} (byName : List Char → Option C) (fb : C)
    (strict : Bool) (p q : NoSNI) (nc nd : Option C) (sni : List Char) (hne : sni ≠ []) :
    getCertificate byName fb strict p nc sni = getCertificate byName fb strict q nd sni := by
  simp [getCertificate, hne]

/-- The default reproduces the behaviour before `no_sni` existed: an absent
SNI is refused in strict mode and gets the fallback otherwise. -/
theorem default_absent {C : Type} (byName : List Char → Option C) (fb : C)
    (strict : Bool) (nc : Option C) :
    getCertificate byName fb strict .asUnmatched nc [] = if strict then none else some fb := by
  simp [getCertificate]

/-- RFC 9462 §6.3 ("present the appropriate TLS certificate when no SNI is
present"), together with strict mode: under `no_sni cert` a client without
SNI gets exactly the configured cert, in either mode, and under `no_sni
fallback` exactly the fallback. -/
theorem noSNI_cert_absent {C : Type} (byName : List Char → Option C) (fb : C)
    (strict : Bool) (nc : Option C) :
    getCertificate byName fb strict .cert nc [] = nc := by
  simp [getCertificate]

theorem noSNI_fallback_absent {C : Type} (byName : List Char → Option C) (fb : C)
    (strict : Bool) (nc : Option C) :
    getCertificate byName fb strict .fallback nc [] = some fb := by
  simp [getCertificate]

theorem noSNI_refuse_absent {C : Type} (byName : List Char → Option C) (fb : C)
    (strict : Bool) (nc : Option C) :
    getCertificate byName fb strict .refuse nc [] = none := by
  simp [getCertificate]

/-- Non-strict mode always produces a certificate for a client that sent
SNI: the handshake never fails for want of one. -/
theorem nonstrict_total {C : Type} (byName : List Char → Option C) (fb : C)
    (p : NoSNI) (nc : Option C) (sni : List Char) (hne : sni ≠ []) :
    (getCertificate byName fb false p nc sni).isSome := by
  simp only [getCertificate, hne, if_false]
  cases lookup byName sni <;> simp

/-- An exact SAN match always wins over a wildcard, in either mode. -/
theorem exact_wins {C : Type} (byName : List Char → Option C) (fb : C) (strict : Bool)
    (p : NoSNI) (nc : Option C) (sni : List Char) (c : C) (hne : sni ≠ [])
    (h : byName sni = some c) :
    getCertificate byName fb strict p nc sni = some c := by
  simp [getCertificate, lookup, hne, h]

/-- So strict mode refuses SNI `.example.com` unless a SAN is literally
`.example.com`, even when a `*.example.com` cert is loaded. -/
theorem strict_refuses_empty_label {C : Type} (byName : List Char → Option C) (fb : C)
    (p : NoSNI) (nc : Option C) (d : List Char) (h : byName ('.' :: d) = none) :
    getCertificate byName fb true p nc ('.' :: d) = none := by
  simp [getCertificate, lookup, h, empty_label_no_wildcard]

/-! ## ASCII case folding (`asciiLower`) -/

/-- `asciiLower`, per byte. -/
def foldByte (b : Nat) : Nat := if 65 ≤ b ∧ b ≤ 90 then b + 32 else b

/-- Every byte of a UTF-8 encoded non-ASCII character is ≥ 0x80, and such
a byte folds to itself. -/
theorem fold_nonascii_fixed {b : Nat} (h : 128 ≤ b) : foldByte b = b := by
  unfold foldByte; split <;> omega

/-- Two bytes fold equal exactly when they are equal or are the two cases
of one ASCII letter: nothing else is case-insensitively equal. -/
theorem fold_eq_iff (a b : Nat) :
    foldByte a = foldByte b ↔
      a = b ∨ (65 ≤ a ∧ a ≤ 90 ∧ b = a + 32) ∨ (65 ≤ b ∧ b ≤ 90 ∧ a = b + 32) := by
  unfold foldByte; split <;> split <;> omega

/-- So an ASCII byte and a non-ASCII byte never fold together. -/
theorem fold_separates_ascii {a b : Nat} (ha : a < 128) (hb : 128 ≤ b) :
    foldByte a ≠ foldByte b := by
  rw [Ne, fold_eq_iff]; omega

/-- SNI `\u212a...` (KELVIN SIGN, UTF-8 `E2 84 AA`) no longer folds onto a
SAN starting `k`, whatever follows either: the first bytes already differ
after folding. -/
theorem kelvin_not_k (s t : List Nat) :
    List.map foldByte (0xE2 :: s) ≠ List.map foldByte (0x6B :: t) := by
  intro h
  simp only [List.map_cons, List.cons.injEq] at h
  exact fold_separates_ascii (a := 0x6B) (b := 0xE2) (by decide) (by decide) h.1.symm

end Wildcard

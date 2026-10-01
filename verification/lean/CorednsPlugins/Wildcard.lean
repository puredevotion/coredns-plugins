/-!
# SNI certificate selection — `sni_tls/sni_tls.go`

```go
func (s *certStore) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if hello.ServerName != "" {
		name := strings.ToLower(hello.ServerName)
		if cert, ok := s.byName[name]; ok { return cert, nil }
		if wildcard, ok := wildcardOf(name); ok {
			if cert, ok := s.byName[wildcard]; ok { return cert, nil }
		}
	}
	if s.strict { return nil, errNoMatchingCert }
	return s.fallback, nil
}

func wildcardOf(name string) (string, bool) {
	i := strings.IndexByte(name, '.')
	if i < 0 { return "", false }
	return "*" + name[i:], true
}
```

Names are modelled as `List Char` already lower-cased (`strings.ToLower`
is applied before any lookup, and SAN keys are lower-cased at load), and
`byName` as a partial function.
-/

namespace Wildcard

/-- `wildcardOf`: replace everything before the first `.` with `*`. -/
def wildcardOf : List Char → Option (List Char)
  | [] => none
  | c :: cs => if c = '.' then some ('*' :: '.' :: cs) else wildcardOf cs

/-- The result, when there is one, always has the shape `*.<suffix>`. -/
theorem wildcardOf_shape {s w : List Char} (h : wildcardOf s = some w) :
    ∃ d, w = '*' :: '.' :: d := by
  induction s with
  | nil => simp [wildcardOf] at h
  | cons c cs ih =>
    unfold wildcardOf at h
    split at h
    · exact ⟨cs, (Option.some.inj h).symm⟩
    · exact ih h

/-- Exact characterisation: `wildcardOf s` is `*.d` precisely when `s` is a
dot-free first label `l`, a dot, then `d`. -/
theorem wildcardOf_eq_iff (s d : List Char) :
    wildcardOf s = some ('*' :: '.' :: d) ↔ ∃ l, '.' ∉ l ∧ s = l ++ '.' :: d := by
  induction s with
  | nil => simp [wildcardOf]
  | cons c cs ih =>
    unfold wildcardOf
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

/-- RFC 6125 §6.4.3: `*.example.com` must not cover `example.com` itself. -/
theorem wildcard_not_apex (d : List Char) :
    wildcardOf d ≠ some ('*' :: '.' :: d) := by
  intro h
  obtain ⟨l, _, he⟩ := (wildcardOf_eq_iff d d).1 h
  have := congrArg List.length he
  simp at this
  omega

/-- RFC 6125 §6.4.3: one label only. `*.example.com` does not cover
`a.b.example.com`: any name the wildcard covers has a single extra label. -/
theorem wildcard_single_label (l₁ l₂ d : List Char) (h₁ : '.' ∉ l₁) :
    wildcardOf (l₁ ++ '.' :: l₂ ++ '.' :: d) ≠ some ('*' :: '.' :: d) := by
  intro h
  obtain ⟨l, hl, he⟩ := (wildcardOf_eq_iff _ d).1 h
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

/-- The empty first label is the one place the implementation is looser than
RFC 6125, which only lets `*` stand for a whole, non-empty label: a
ClientHello with SNI `.example.com` selects the `*.example.com` cert, even
in strict mode. Harmless for authentication (the client then fails to match
the cert against its own name), but it is a non-match that strict mode does
not refuse. -/
theorem empty_label_selects_wildcard (d : List Char) :
    wildcardOf ('.' :: d) = some ('*' :: '.' :: d) := by
  simp [wildcardOf]

/-- The SAN lookup half of `GetCertificate`: exact key, then wildcard key. -/
def lookup {C : Type} (byName : List Char → Option C) (sni : List Char) : Option C :=
  if sni = [] then none
  else match byName sni with
    | some c => some c
    | none => (wildcardOf sni).bind byName

/-- `GetCertificate`, with the `byName` map as a partial function. `none`
is the handshake-aborting error. -/
def getCertificate {C : Type} (byName : List Char → Option C) (fallback : C)
    (strict : Bool) (sni : List Char) : Option C :=
  match lookup byName sni with
  | some c => some c
  | none => if strict then none else some fallback

/-- Strict mode never answers with a cert that wasn't selected by an exact or
wildcard SAN key, so the fallback can't leak out to an unmatched name. -/
theorem strict_only_matched {C : Type} (byName : List Char → Option C) (fb : C)
    (sni : List Char) (c : C) (h : getCertificate byName fb true sni = some c) :
    sni ≠ [] ∧ (byName sni = some c ∨ ∃ w, wildcardOf sni = some w ∧ byName w = some c) := by
  have hl : lookup byName sni = some c := by
    unfold getCertificate at h
    cases hl : lookup byName sni <;> simp_all
  unfold lookup at hl
  by_cases he : sni = []
  · simp [he] at hl
  · refine ⟨he, ?_⟩
    simp only [he, if_false] at hl
    cases hb : byName sni with
    | some c' => simp_all
    | none =>
      simp only [hb] at hl
      cases hw : wildcardOf sni with
      | none => simp [hw] at hl
      | some w => simp only [hw, Option.bind_some] at hl; exact Or.inr ⟨w, rfl, hl⟩

/-- Non-strict mode always produces a certificate: the handshake never fails
for want of one. -/
theorem nonstrict_total {C : Type} (byName : List Char → Option C) (fb : C)
    (sni : List Char) : (getCertificate byName fb false sni).isSome := by
  unfold getCertificate
  cases lookup byName sni <;> simp

/-- An exact SAN match always wins over a wildcard, in either mode. -/
theorem exact_wins {C : Type} (byName : List Char → Option C) (fb : C) (strict : Bool)
    (sni : List Char) (c : C) (hne : sni ≠ []) (h : byName sni = some c) :
    getCertificate byName fb strict sni = some c := by
  simp [getCertificate, lookup, hne, h]

end Wildcard

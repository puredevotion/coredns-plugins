/-!
# RFC 1982 serial number arithmetic — `dynupdate/zone.go`

```go
func serialGreater(a, b uint32) bool {
	return a != b && ((a < b && b-a > 1<<31) || (a > b && a-b < 1<<31))
}
func bumpSerial(rrs []dns.RR) { ... soa.Serial++ }
```

A `uint32` is modelled as a `Nat` below `2^32`. Under the guard `a < b`,
Go's wrapping `b-a` equals natural subtraction, so the model is exact.
-/

namespace Serial

-- Notations rather than definitions so `omega` sees the literals.
/-- `2^32`, the serial space (SERIAL_BITS = 32). -/
local notation "M" => 4294967296
/-- `2^31`, half of it. -/
local notation "H" => 2147483648

/-- The Go function, verbatim. -/
def serialGreater (a b : Nat) : Bool :=
  a != b && ((decide (a < b) && decide (b - a > H)) || (decide (a > b) && decide (a - b < H)))

/-- RFC 1982 §3.2, as written: `i1 < i2` in serial space iff
`(i1 < i2 and i2 - i1 < 2^31) or (i1 > i2 and i1 - i2 > 2^31)`. -/
def rfcLt (i1 i2 : Nat) : Prop :=
  (i1 < i2 ∧ i2 - i1 < H) ∨ (i1 > i2 ∧ i1 - i2 > H)

/-- `serialGreater a b` is exactly RFC 1982's `b < a`. -/
theorem serialGreater_iff_rfc (a b : Nat) :
    serialGreater a b = true ↔ rfcLt b a := by
  unfold serialGreater rfcLt
  simp only [Bool.and_eq_true, Bool.or_eq_true, bne_iff_ne, ne_eq, decide_eq_true_eq]
  omega

/-- Nothing is greater than itself. -/
theorem irrefl (a : Nat) : serialGreater a a = false := by
  simp [serialGreater]

/-- Never both `a > b` and `b > a`: the zone can't be both ahead of and
behind the same serial. -/
theorem asymm (a b : Nat) (h : serialGreater a b = true) :
    serialGreater b a = false := by
  rw [serialGreater_iff_rfc] at h
  cases hb : serialGreater b a
  · rfl
  · rw [serialGreater_iff_rfc] at hb
    unfold rfcLt at h hb
    omega

/-- Two distinct serials are always comparable, except the antipodal pairs
exactly `2^31` apart, which RFC 1982 §3.2 leaves undefined. -/
theorem total_except_antipodes (a b : Nat)
    (hne : a ≠ b) (hfar : (a + M - b) % M ≠ H) :
    serialGreater a b = true ∨ serialGreater b a = true := by
  rw [serialGreater_iff_rfc, serialGreater_iff_rfc]
  unfold rfcLt
  omega

/-- The undefined pairs really are undefined in the implementation: neither
direction is "greater", so an added SOA at the antipode is ignored. -/
theorem antipodes_incomparable (a : Nat) :
    serialGreater (a + H) a = false ∧ serialGreater a (a + H) = false := by
  constructor <;> simp [serialGreater] <;> omega

/-- RFC 1982 §3.1 addition: adding any `n` in `[1, 2^31 - 1]`, with
wrap-around, produces a greater serial. -/
theorem add_is_greater (a n : Nat) (ha : a < M) (hn1 : 1 ≤ n) (hn2 : n < H) :
    serialGreater ((a + n) % M) a = true := by
  rw [serialGreater_iff_rfc]
  unfold rfcLt
  omega

/-- What `bumpSerial` relies on: `soa.Serial++` (Go's wrapping uint32
increment) always moves the serial forward, including at `2^32 - 1`, so a
secondary that was NOTIFYed always sees a newer serial. -/
theorem bump_is_greater (a : Nat) (ha : a < M) :
    serialGreater ((a + 1) % M) a = true :=
  add_is_greater a 1 ha (by decide) (by decide)

/-- The wrap case the Go test pins down, proved for the model. -/
example : serialGreater 0 4294967295 = true := by decide

/-- RFC 1982 serial comparison is NOT transitive, so code must never chain
comparisons (e.g. "newer than the newest I saw, which was newer than X").
`dynupdate` only ever compares against the current SOA, so this is safe. -/
theorem not_transitive :
    ∃ a b c, a < M ∧ b < M ∧ c < M ∧
      serialGreater b a = true ∧ serialGreater c b = true ∧ serialGreater c a = false :=
  ⟨0, 1073741824, 2147483648, by decide, by decide, by decide,
   by decide, by decide, by decide⟩

end Serial

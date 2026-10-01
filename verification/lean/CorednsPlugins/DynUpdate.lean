import CorednsPlugins.Serial

/-!
# RFC 2136 update semantics — `dynupdate/update.go`, `dynupdate/zone.go`

A zone is the flat `[]dns.RR` the plugin keeps. Names are atoms (`Nat`),
already canonicalised; RDATA is an atom too, except that an SOA's RDATA is
its serial. The other SOA fields play no part in any rule below.

`applyAddOriginal` follows `applyAdd` as of v0.4.1 line by line. Run against
a three-record zone it breaks the zone (`original_*` below, all checked by
evaluation):

* an UPDATE adding a higher-serial SOA leaves the zone with **two** SOAs;
* after that, the served serial no longer moves, so a NOTIFYed secondary
  never transfers a later change;
* an UPDATE adding a CNAME where one already exists leaves **two** CNAMEs,
  where RFC 2136 §3.4.2.2 says to replace it.

`applyAddRFC` is RFC 2136 §3.4.2.2, and what `applyAdd` now does: an SOA or CNAME update *replaces* the
existing one, and an SOA anywhere but the apex is ignored. For it,
`apply_preserves_wf` proves that every sequence of update records keeps a
well-formed zone well-formed: exactly one SOA, at the apex; at least one
apex NS; no CNAME next to other data; at most one CNAME per name.

TTL refresh is modelled as rewriting the TTL of every record with the same
key; the Go code rewrites the first one. No property here mentions TTLs, so
the difference cannot matter to them.
-/

namespace DynUpdate

inductive Ty
  | soa | ns | cname | rrsig | nsec
  | other (n : Nat)
  deriving DecidableEq, Repr

structure RR where
  name : Nat
  ty : Ty
  data : Nat
  ttl : Nat
  deriving DecidableEq, Repr

/-- `rdataKey`: name, type and RDATA; not the TTL. -/
def key (r : RR) : Nat × Ty × Nat := (r.name, r.ty, r.data)

def isSOA (r : RR) : Bool := r.ty == .soa
def isApexNS (apex : Nat) (r : RR) : Bool := r.name == apex && r.ty == .ns
def isCNAMEAt (n : Nat) (r : RR) : Bool := r.name == n && r.ty == .cname

/-- `hasNonCNAME`'s test: RRSIG and NSEC may sit beside a CNAME. -/
def nonCNAMEType : Ty → Bool
  | .cname | .rrsig | .nsec => false
  | _ => true

def isNonCNAMEAt (n : Nat) (r : RR) : Bool := r.name == n && nonCNAMEType r.ty

def hasCNAME (z : List RR) (n : Nat) : Bool := z.any (isCNAMEAt n)
def hasNonCNAME (z : List RR) (n : Nat) : Bool := z.any (isNonCNAMEAt n)

/-- `soaOf`: the first SOA. -/
def soaOf (z : List RR) : Option RR := z.find? isSOA

/-- The tail of `applyAdd`: an identical record only has its TTL refreshed
(`indexOfRR`), anything else is appended. -/
def addOrRefresh (z : List RR) (rr : RR) : List RR :=
  if z.any (fun r => key r == key rr) then
    z.map (fun r => if key r == key rr then { r with ttl := rr.ttl } else r)
  else z ++ [rr]

/-- `cur == nil || !serialGreater(newSOA.Serial, cur.Serial)`. -/
def soaIgnored (z : List RR) (rr : RR) : Bool :=
  match soaOf z with
  | none => true
  | some cur => !Serial.serialGreater rr.data cur.data

/-- `applyAdd` as of v0.4.1. -/
def applyAddOriginal (_apex : Nat) (z : List RR) (rr : RR) : List RR :=
  if rr.ty = .soa ∧ soaIgnored z rr = true then z
  else if rr.ty = .cname ∧ hasNonCNAME z rr.name = true then z
  else if rr.ty ≠ .cname ∧ rr.ty ≠ .soa ∧ hasCNAME z rr.name = true then z
  else addOrRefresh z rr

/-- RFC 2136 §3.4.2.2: "For SOA RRs, ... the Zone RR is replaced by Update
RR" (only if its serial is greater), and "otherwise replace the CNAME Zone RR
with the CNAME Update RR". An SOA is only ever the apex's. -/
def applyAddRFC (apex : Nat) (z : List RR) (rr : RR) : List RR :=
  if rr.ty = .soa then
    if rr.name ≠ apex then z
    else match soaOf z with
      | none => z
      | some cur =>
        if Serial.serialGreater rr.data cur.data then z.filter (fun x => !isSOA x) ++ [rr]
        else z
  else if rr.ty = .cname then
    if hasNonCNAME z rr.name then z
    else if z.any (fun r => key r == key rr) then addOrRefresh z rr
    else z.filter (fun x => !isCNAMEAt rr.name x) ++ [rr]
  else if hasCNAME z rr.name then z
  else addOrRefresh z rr

/-- `applyDeleteRRset`; `ty = none` is TypeANY (every RRset at the name). -/
def applyDeleteRRset (apex : Nat) (z : List RR) (name : Nat) (ty : Option Ty) : List RR :=
  match ty with
  | none =>
    z.filter (fun x => !(x.name == name && !(name == apex && (x.ty == .soa || x.ty == .ns))))
  | some t =>
    if name = apex ∧ (t = .soa ∨ t = .ns) then z
    else z.filter (fun x => !(x.name == name && x.ty == t))

/-- `applyDeleteRecord`. -/
def applyDeleteRecord (apex : Nat) (z : List RR) (rr : RR) : List RR :=
  if rr.name = apex ∧ rr.ty = .soa then z
  else if rr.name = apex ∧ rr.ty = .ns ∧ z.countP (isApexNS apex) ≤ 1 then z
  else z.eraseP (fun x => key x == key rr)

/-- One record of the update section, by class: IN adds, ANY deletes an
RRset, NONE deletes one record. -/
inductive Upd
  | add (rr : RR)
  | delRRset (name : Nat) (ty : Option Ty)
  | delRR (rr : RR)
  deriving DecidableEq, Repr

def step (addFn : Nat → List RR → RR → List RR) (apex : Nat) (z : List RR) : Upd → List RR
  | .add rr => addFn apex z rr
  | .delRRset n t => applyDeleteRRset apex z n t
  | .delRR rr => applyDeleteRecord apex z rr

/-- `apply`: the update section, in order. -/
def apply (addFn : Nat → List RR → RR → List RR) (apex : Nat) (z : List RR)
    (us : List Upd) : List RR :=
  us.foldl (step addFn apex) z

/-- `bumpSerial`: increment the first SOA's serial, wrapping. -/
def bumpSerial : List RR → List RR
  | [] => []
  | r :: rs =>
    if isSOA r then { r with data := (r.data + 1) % 4294967296 } :: rs
    else r :: bumpSerial rs

/-- The serial secondaries see. `file.Zone.Insert` stores each SOA it is
given into `z.SOA`, overwriting the last, so the view serves the LAST SOA
of the slice. -/
def servedSerial (z : List RR) : Option Nat := ((z.filter isSOA).getLast?).map (·.data)

/-! ## v0.4.1, on a concrete zone -/

/-- `example.org.` (name 0): SOA serial 100, one NS. `alias` (name 1) is a
CNAME. -/
def seed : List RR :=
  [⟨0, .soa, 100, 300⟩, ⟨0, .ns, 7, 300⟩, ⟨1, .cname, 8, 300⟩]

/-- Adding an SOA with a higher serial appends a second SOA. -/
theorem original_two_soas :
    (apply applyAddOriginal 0 seed [.add ⟨0, .soa, 500, 300⟩]).countP isSOA = 2 := by
  decide

/-- ...after which every successful UPDATE bumps the FIRST SOA while the view
serves the LAST, so the served serial is stuck at 500 and secondaries never
see a newer one. -/
theorem original_serial_frozen :
    let z1 := apply applyAddOriginal 0 seed [.add ⟨0, .soa, 500, 300⟩]
    let z2 := bumpSerial (apply applyAddOriginal 0 z1 [.add ⟨2, .other 16, 9, 60⟩])
    let z3 := bumpSerial (apply applyAddOriginal 0 z2 [.add ⟨3, .other 16, 9, 60⟩])
    servedSerial z1 = some 500 ∧ servedSerial z2 = some 500 ∧ servedSerial z3 = some 500 := by
  decide

/-- Adding a CNAME for a name that already has one appends a second. -/
theorem original_two_cnames :
    (apply applyAddOriginal 0 seed [.add ⟨1, .cname, 9, 300⟩]).countP (isCNAMEAt 1) = 2 := by
  decide

/-- An SOA added below the apex is accepted (its serial beats the apex
SOA's), and since it is inserted last it becomes the zone's SOA. -/
theorem original_soa_below_apex :
    let z := apply applyAddOriginal 0 seed [.add ⟨2, .soa, 500, 300⟩]
    z.countP isSOA = 2 ∧ ((z.filter isSOA).getLast?).map (·.name) = some 2 := by
  decide

/-- The RFC version on the same inputs. -/
example : (apply applyAddRFC 0 seed [.add ⟨0, .soa, 500, 300⟩]).countP isSOA = 1 := by decide
example : (apply applyAddRFC 0 seed [.add ⟨1, .cname, 9, 300⟩]).countP (isCNAMEAt 1) = 1 := by
  decide
example : apply applyAddRFC 0 seed [.add ⟨2, .soa, 500, 300⟩] = seed := by decide

/-! ## Well-formedness and its preservation -/

/-- A zone the plugin may serve. -/
structure WF (apex : Nat) (z : List RR) : Prop where
  oneSOA : z.countP isSOA = 1
  soaAtApex : ∀ r ∈ z, r.ty = .soa → r.name = apex
  apexNS : z.countP (isApexNS apex) ≥ 1
  cnameExcl : ∀ n, ¬ (hasCNAME z n = true ∧ hasNonCNAME z n = true)
  oneCNAME : ∀ n, z.countP (isCNAMEAt n) ≤ 1

/-! ### List lemmas -/

theorem any_of_sublist {p : RR → Bool} {l₁ l₂ : List RR} (h : l₁.Sublist l₂)
    (ha : l₁.any p = true) : l₂.any p = true := by
  rw [List.any_eq_true] at ha ⊢
  obtain ⟨x, hx, hp⟩ := ha
  exact ⟨x, h.subset hx, hp⟩

theorem countP_filter_keep {p q : RR → Bool} {z : List RR} (h : ∀ r ∈ z, p r = true → q r = true) :
    (z.filter q).countP p = z.countP p := by
  induction z with
  | nil => rfl
  | cons a as ih =>
    have ih' := ih (fun r hr => h r (by simp [hr]))
    by_cases hq : q a = true
    · simp [hq, List.countP_cons, ih']
    · have hp : p a = false := by
        cases hpa : p a
        · rfl
        · exact absurd (h a (by simp) hpa) hq
      simp [hq, hp, ih']

theorem countP_filter_drop {p : RR → Bool} (z : List RR) :
    (z.filter (fun x => !p x)).countP p = 0 := by
  induction z with
  | nil => rfl
  | cons a as ih =>
    cases hp : p a <;> simp [hp, ih]

theorem countP_eraseP_keep {p q : RR → Bool} {z : List RR}
    (h : ∀ r ∈ z, p r = true → q r = false) :
    (z.eraseP p).countP q = z.countP q := by
  induction z with
  | nil => rfl
  | cons a as ih =>
    by_cases hp : p a = true
    · simp [hp, h a (by simp) hp]
    · simp [hp, List.countP_cons, ih (fun r hr => h r (by simp [hr]))]

theorem countP_eraseP_ge {p q : RR → Bool} (z : List RR) :
    (z.eraseP p).countP q + 1 ≥ z.countP q := by
  induction z with
  | nil => simp
  | cons a as ih =>
    by_cases hp : p a = true
    · simp only [List.eraseP_cons, hp, cond_true, List.countP_cons]; split <;> omega
    · simp only [List.eraseP_cons, hp, cond_false, List.countP_cons]
      split <;> omega

/-- TTL refresh changes nothing any property looks at. -/
def refresh (rr : RR) (r : RR) : RR := if key r == key rr then { r with ttl := rr.ttl } else r

theorem refresh_name (rr r : RR) : (refresh rr r).name = r.name := by
  unfold refresh; split <;> rfl
theorem refresh_ty (rr r : RR) : (refresh rr r).ty = r.ty := by
  unfold refresh; split <;> rfl

theorem countP_map_refresh {p : RR → Bool} (hp : ∀ r, p (refresh rr r) = p r) (z : List RR) :
    (z.map (refresh rr)).countP p = z.countP p := by
  rw [List.countP_map]
  congr 1
  funext r
  exact hp r

theorem any_map_refresh {p : RR → Bool} (hp : ∀ r, p (refresh rr r) = p r) (z : List RR) :
    (z.map (refresh rr)).any p = z.any p := by
  rw [List.any_map]
  congr 1
  funext r
  exact hp r

theorem wf_refresh {apex : Nat} {z : List RR} (rr : RR) (h : WF apex z) :
    WF apex (z.map (refresh rr)) where
  oneSOA := by
    rw [countP_map_refresh (fun r => by simp [isSOA, refresh_ty])]; exact h.oneSOA
  soaAtApex := by
    intro r hr hs
    obtain ⟨r', hr', rfl⟩ := List.mem_map.1 hr
    rw [refresh_ty] at hs; rw [refresh_name]; exact h.soaAtApex r' hr' hs
  apexNS := by
    rw [countP_map_refresh (fun r => by simp [isApexNS, refresh_ty, refresh_name])]
    exact h.apexNS
  cnameExcl := by
    intro n
    unfold hasCNAME hasNonCNAME
    rw [any_map_refresh (fun r => by simp [isCNAMEAt, refresh_ty, refresh_name]),
      any_map_refresh (fun r => by simp [isNonCNAMEAt, refresh_ty, refresh_name])]
    exact h.cnameExcl n
  oneCNAME := by
    intro n
    rw [countP_map_refresh (fun r => by simp [isCNAMEAt, refresh_ty, refresh_name])]
    exact h.oneCNAME n

/-- Removing records keeps everything except the two lower bounds. -/
theorem wf_sublist {apex : Nat} {z z' : List RR} (h : WF apex z) (hs : z'.Sublist z)
    (hsoa : z'.countP isSOA = 1) (hns : z'.countP (isApexNS apex) ≥ 1) : WF apex z' where
  oneSOA := hsoa
  soaAtApex := fun r hr => h.soaAtApex r (hs.subset hr)
  apexNS := hns
  cnameExcl := fun n ⟨h1, h2⟩ =>
    h.cnameExcl n ⟨any_of_sublist hs h1, any_of_sublist hs h2⟩
  oneCNAME := fun n => Nat.le_trans (hs.countP_le) (h.oneCNAME n)

theorem soa_has_apex_nonCNAME {apex : Nat} {z : List RR} (h : WF apex z) :
    hasNonCNAME z apex = true := by
  have : 0 < z.countP isSOA := by rw [h.oneSOA]; decide
  obtain ⟨r, hr, hs⟩ := List.countP_pos_iff.1 this
  have hty : r.ty = .soa := by simpa [isSOA] using hs
  unfold hasNonCNAME
  rw [List.any_eq_true]
  exact ⟨r, hr, by simp [isNonCNAMEAt, h.soaAtApex r hr hty, hty, nonCNAMEType]⟩

/-! ### Each kind of update record -/

theorem wf_deleteRRset {apex : Nat} {z : List RR} (n : Nat) (t : Option Ty) (h : WF apex z) :
    WF apex (applyDeleteRRset apex z n t) := by
  cases t with
  | none =>
    unfold applyDeleteRRset
    refine wf_sublist h (List.filter_sublist) ?_ ?_
    · rw [countP_filter_keep (fun r hr hs => by
          have hty : r.ty = .soa := by simpa [isSOA] using hs
          simp [h.soaAtApex r hr hty, hty]; omega)]
      exact h.oneSOA
    · rw [countP_filter_keep (fun r _ hs => by
          simp only [isApexNS, Bool.and_eq_true, beq_iff_eq] at hs
          simp [hs.1, hs.2]; omega)]
      exact h.apexNS
  | some t =>
    simp only [applyDeleteRRset]
    split
    · exact h
    · rename_i hskip
      refine wf_sublist h (List.filter_sublist) ?_ ?_
      · rw [countP_filter_keep (fun r hr hs => by
            have hty : r.ty = .soa := by simpa [isSOA] using hs
            have hn := h.soaAtApex r hr hty
            have : ¬(apex = n ∧ Ty.soa = t) := fun ⟨e1, e2⟩ => hskip ⟨e1.symm, Or.inl e2.symm⟩
            simp only [hn, hty]; simp only [not_and] at this; simpa [Decidable.imp_iff_not_or] using this)]
        exact h.oneSOA
      · rw [countP_filter_keep (fun r _ hs => by
            simp only [isApexNS, Bool.and_eq_true, beq_iff_eq] at hs
            obtain ⟨hn, hty⟩ := hs
            have : ¬(apex = n ∧ Ty.ns = t) := fun ⟨e1, e2⟩ => hskip ⟨e1.symm, Or.inr e2.symm⟩
            simp only [hn, hty]; simp only [not_and] at this; simpa [Decidable.imp_iff_not_or] using this)]
        exact h.apexNS

theorem wf_deleteRecord {apex : Nat} {z : List RR} (rr : RR) (h : WF apex z) :
    WF apex (applyDeleteRecord apex z rr) := by
  unfold applyDeleteRecord
  split
  · exact h
  · rename_i hsoa
    split
    · exact h
    · rename_i hns
      refine wf_sublist h (List.eraseP_sublist) ?_ ?_
      · rw [countP_eraseP_keep (fun r hr hk => by
            simp only [key, beq_iff_eq, Prod.mk.injEq] at hk
            cases hs : isSOA r
            · rfl
            · have hty : r.ty = .soa := by simpa [isSOA] using hs
              exact absurd ⟨hk.1 ▸ h.soaAtApex r hr hty, hk.2.1 ▸ hty⟩ hsoa)]
        exact h.oneSOA
      · by_cases hk : rr.name = apex ∧ rr.ty = .ns
        · have hc : z.countP (isApexNS apex) ≥ 2 := by
            have := h.apexNS; simp only [hk, true_and, Nat.not_le] at hns; omega
          have := countP_eraseP_ge (p := fun x => key x == key rr) (q := isApexNS apex) z
          omega
        · rw [countP_eraseP_keep (fun r _ hkr => by
              simp only [key, beq_iff_eq, Prod.mk.injEq] at hkr
              simp only [isApexNS, Bool.and_eq_false_iff, beq_eq_false_iff_ne]
              by_cases e : r.name = apex
              · right; intro ht; exact hk ⟨hkr.1 ▸ e, hkr.2.1 ▸ ht⟩
              · left; exact e)]
          exact h.apexNS

/-- Appending a record that is not an SOA, not an apex-relevant NS loss, and
that respects CNAME exclusivity. -/
theorem wf_append {apex : Nat} {z : List RR} {rr : RR} (h : WF apex z)
    (hsoa : rr.ty ≠ .soa)
    (hexcl : ∀ n, ¬ (hasCNAME (z ++ [rr]) n = true ∧ hasNonCNAME (z ++ [rr]) n = true))
    (hone : ∀ n, (z ++ [rr]).countP (isCNAMEAt n) ≤ 1) : WF apex (z ++ [rr]) where
  oneSOA := by simp [List.countP_append, isSOA, hsoa, h.oneSOA]
  soaAtApex := by
    intro r hr hs
    rcases List.mem_append.1 hr with hr | hr
    · exact h.soaAtApex r hr hs
    · simp at hr; subst hr; exact absurd hs hsoa
  apexNS := by
    have := h.apexNS; simp only [List.countP_append]; omega
  cnameExcl := hexcl
  oneCNAME := hone

theorem has_append (p : RR → Bool) (z : List RR) (rr : RR) :
    (z ++ [rr]).any p = (z.any p || p rr) := by simp [List.any_append]

theorem wf_addOrRefresh_nonCNAME {apex : Nat} {z : List RR} {rr : RR} (h : WF apex z)
    (hsoa : rr.ty ≠ .soa) (hc : rr.ty ≠ .cname) (hno : hasCNAME z rr.name = false) :
    WF apex (addOrRefresh z rr) := by
  unfold addOrRefresh
  split
  · exact wf_refresh rr h
  · apply wf_append h hsoa
    · intro n ⟨h1, h2⟩
      unfold hasCNAME at h1; unfold hasNonCNAME at h2
      rw [has_append] at h1 h2
      have hrc : isCNAMEAt n rr = false := by simp [isCNAMEAt, hc]
      rw [hrc, Bool.or_false] at h1
      by_cases e : rr.name = n
      · subst e; unfold hasCNAME at hno; rw [hno] at h1; exact absurd h1 (by decide)
      · have : isNonCNAMEAt n rr = false := by simp [isNonCNAMEAt, e]
        rw [this, Bool.or_false] at h2
        exact h.cnameExcl n ⟨h1, h2⟩
    · intro n
      simp only [List.countP_append, List.countP_singleton]
      have : isCNAMEAt n rr = false := by simp [isCNAMEAt, hc]
      simp only [this]; have := h.oneCNAME n; simp; omega

theorem wf_addRFC {apex : Nat} {z : List RR} (rr : RR) (h : WF apex z) :
    WF apex (applyAddRFC apex z rr) := by
  unfold applyAddRFC
  split
  · -- SOA
    rename_i hsoa
    split
    · exact h
    · rename_i hapex
      simp only [ne_eq, Decidable.not_not] at hapex
      split
      · exact h
      · split
        · -- replace the SOA
          have hsub : (z.filter (fun x => !isSOA x)).Sublist z := List.filter_sublist
          have hnc := soa_has_apex_nonCNAME h
          have hnoC : hasCNAME z apex = false := by
            cases e : hasCNAME z apex
            · rfl
            · exact absurd ⟨e, hnc⟩ (h.cnameExcl apex)
          constructor
          · simp [List.countP_append, isSOA, hsoa]
          · intro r hr hs
            rcases List.mem_append.1 hr with hr | hr
            · simp only [List.mem_filter] at hr
              simp [isSOA, hs] at hr
            · simp at hr; subst hr; exact hapex
          · simp only [List.countP_append]
            rw [countP_filter_keep (fun r _ hns => by
              simp only [isApexNS, Bool.and_eq_true, beq_iff_eq] at hns
              simp [isSOA, hns.2])]
            have := h.apexNS; omega
          · intro n ⟨h1, h2⟩
            unfold hasCNAME at h1; unfold hasNonCNAME at h2
            rw [has_append] at h1 h2
            have hrc : isCNAMEAt n rr = false := by simp [isCNAMEAt, hsoa]
            rw [hrc, Bool.or_false] at h1
            have h1' := any_of_sublist hsub h1
            by_cases e : rr.name = n
            · subst e; rw [hapex] at h1'; unfold hasCNAME at hnoC; rw [hnoC] at h1'
              exact absurd h1' (by decide)
            · have : isNonCNAMEAt n rr = false := by simp [isNonCNAMEAt, e]
              rw [this, Bool.or_false] at h2
              exact h.cnameExcl n ⟨h1', any_of_sublist hsub h2⟩
          · intro n
            simp only [List.countP_append, List.countP_singleton]
            have : isCNAMEAt n rr = false := by simp [isCNAMEAt, hsoa]
            simp only [this]
            have := Nat.le_trans hsub.countP_le (h.oneCNAME n)
            simp; omega
        · exact h
  · split
    · -- CNAME
      rename_i hsoa hc
      split
      · exact h
      · rename_i hnon
        simp only [Bool.not_eq_true] at hnon
        split
        · unfold addOrRefresh; rw [if_pos (by assumption)]; exact wf_refresh rr h
        · have hsub : (z.filter (fun x => !isCNAMEAt rr.name x)).Sublist z := List.filter_sublist
          constructor
          · simp only [List.countP_append, List.countP_singleton]
            rw [countP_filter_keep (fun r _ hs => by
              have hty : r.ty = .soa := by simpa [isSOA] using hs
              simp [isCNAMEAt, hty])]
            simp [isSOA, hc, h.oneSOA]
          · intro r hr hs
            rcases List.mem_append.1 hr with hr | hr
            · exact h.soaAtApex r (hsub.subset hr) hs
            · simp at hr; subst hr; exact absurd hs hsoa
          · simp only [List.countP_append]
            rw [countP_filter_keep (fun r _ hns => by
              simp only [isApexNS, Bool.and_eq_true, beq_iff_eq] at hns
              simp [isCNAMEAt, hns.2])]
            have := h.apexNS; omega
          · intro n ⟨h1, h2⟩
            unfold hasCNAME at h1; unfold hasNonCNAME at h2
            rw [has_append] at h1 h2
            have hrn : isNonCNAMEAt n rr = false := by simp [isNonCNAMEAt, hc, nonCNAMEType]
            rw [hrn, Bool.or_false] at h2
            have h2' := any_of_sublist hsub h2
            by_cases e : rr.name = n
            · subst e; unfold hasNonCNAME at hnon; rw [hnon] at h2'
              exact absurd h2' (by decide)
            · have : isCNAMEAt n rr = false := by simp [isCNAMEAt, e]
              rw [this, Bool.or_false] at h1
              exact h.cnameExcl n ⟨any_of_sublist hsub h1, h2'⟩
          · intro n
            simp only [List.countP_append, List.countP_singleton]
            by_cases e : rr.name = n
            · subst e
              have : (z.filter (fun x => !isCNAMEAt rr.name x)).countP (isCNAMEAt rr.name) = 0 :=
                countP_filter_drop z
              simp only [this]; split <;> omega
            · have : isCNAMEAt n rr = false := by simp [isCNAMEAt, e]
              simp only [this]
              have := Nat.le_trans hsub.countP_le (h.oneCNAME n)
              simp; omega
    · -- every other type
      rename_i hsoa hc
      split
      · exact h
      · rename_i hno
        simp only [Bool.not_eq_true] at hno
        exact wf_addOrRefresh_nonCNAME h hsoa hc hno

theorem wf_step {apex : Nat} {z : List RR} (u : Upd) (h : WF apex z) :
    WF apex (step applyAddRFC apex z u) := by
  cases u with
  | add rr => exact wf_addRFC rr h
  | delRRset n t => exact wf_deleteRRset n t h
  | delRR rr => exact wf_deleteRecord rr h

/-- **Every update section keeps a well-formed zone well-formed**, under the
RFC 2136 §3.4.2.2 add rules. -/
theorem apply_preserves_wf {apex : Nat} (z : List RR) (us : List Upd) (h : WF apex z) :
    WF apex (apply applyAddRFC apex z us) := by
  induction us generalizing z with
  | nil => exact h
  | cons u us ih => exact ih _ (wf_step u h)

end DynUpdate

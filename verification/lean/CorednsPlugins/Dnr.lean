/-!
# RFC 9463 Encrypted DNS option codec — `radnr/pkg/dnr/dnr.go`

A byte is a `Nat`; a byte slice a `List Nat`. Each Go function below has a
model that follows it statement by statement, error returns becoming `none`.

The headline result is `unmarshal_marshal`: whatever `Marshal` accepts,
`Unmarshal` decodes back to the same option, except that the ADN loses at
most one trailing dot, as `encodeADN`'s `strings.TrimSuffix` says it should.
`marshal_aligned` proves the RA length invariant (RFC 4861 §4.6: option
length in units of 8 octets, covering the whole option).

Abstracted: `netip.Addr` is its 16-byte `As16()` form, and `Marshal`'s
"is IPv6" check is replaced by the hypothesis that every address is 16
bytes.

What this does and does not say about RFC 9463. The layout `marshal`
produces is the §6.1 RA option with all its fields: Type 144, Length "in
units of 8 octets" counting Type and Length, Service Priority, Lifetime, ADN
Length, ADN, Addr Length, the addresses, SvcParams Length, SvcParams, and
padding ("The option MUST be padded with zeros so that the full enclosed
data is a multiple of 8 octets"). The round trip is proved for that layout,
which is the one radnr sends: its config always has at least one address.
§6.1's ADN-only form, where "the "Addr Length", "ipv6-address(es)", and
"Service Parameters (SvcParams)" fields are not present", is not modelled:
`Marshal` never produces it (given no addresses it still writes both length
fields, as zero), and `Unmarshal` does not accept it unless at least four
octets of padding happen to stand in for those fields.
-/

namespace Dnr

/-- `binary.BigEndian.AppendUint16`. -/
def be16 (n : Nat) : List Nat := [n / 256 % 256, n % 256]

/-- `binary.BigEndian.AppendUint32`. -/
def be32 (n : Nat) : List Nat :=
  [n / 16777216 % 256, n / 65536 % 256, n / 256 % 256, n % 256]

/-! ## Names -/

/-- `strings.Split(s, ".")`. Never empty: `Split("", ".")` is `[""]`. -/
def split : List Nat → List (List Nat)
  | [] => [[]]
  | c :: cs =>
    if c = 46 then [] :: split cs
    else match split cs with
      | l :: ls => (c :: l) :: ls
      | [] => [[c]]

/-- `strings.Join(labels, ".")`. -/
def join : List (List Nat) → List Nat
  | [] => []
  | [l] => l
  | l :: l' :: ls => l ++ 46 :: join (l' :: ls)

theorem split_ne_nil (s : List Nat) : split s ≠ [] := by
  cases s with
  | nil => simp [split]
  | cons c cs =>
    unfold split
    split
    · simp
    · split <;> simp

theorem join_cons_cons (l : List Nat) (ls : List (List Nat)) (h : ls ≠ []) :
    join (l :: ls) = l ++ 46 :: join ls := by
  cases ls with
  | nil => exact absurd rfl h
  | cons _ _ => rfl

/-- Splitting then joining gives the name back. -/
theorem join_split (s : List Nat) : join (split s) = s := by
  induction s with
  | nil => rfl
  | cons c cs ih =>
    unfold split
    by_cases hc : c = 46
    · simp only [hc, if_true]
      rw [join_cons_cons _ _ (split_ne_nil cs), ih]
      rfl
    · simp only [hc, if_false]
      cases hs : split cs with
      | nil => exact absurd hs (split_ne_nil cs)
      | cons l ls =>
        simp only
        rw [hs] at ih
        cases ls with
        | nil => simp [join] at ih ⊢; exact ih
        | cons l' ls' =>
          rw [join_cons_cons _ _ (by simp)]
          rw [join_cons_cons _ _ (by simp)] at ih
          simp [ih]

/-- `strings.TrimSuffix(name, ".")`: removes one trailing dot, if present. -/
def trimDot (s : List Nat) : List Nat :=
  if s.getLast? = some 46 then s.dropLast else s

/-- The label loop of `encodeADN`. -/
def encodeLabels : List (List Nat) → Option (List Nat)
  | [] => some []
  | l :: ls =>
    if l = [] then none                  -- "empty label in ADN"
    else if l.length > 63 then none      -- checkedByteMax(len(label), 63, ...)
    else (encodeLabels ls).map (fun r => l.length :: l ++ r)

/-- `encodeADN`. -/
def encodeADN (name : List Nat) : Option (List Nat) :=
  let n := trimDot name
  if n = [] then none                    -- "empty ADN"
  else match encodeLabels (split n) with
    | none => none
    | some body =>
      let out := body ++ [0]             -- rootLabel
      if out.length > 255 then none else some out

/-- The loop of `decodeADN`. Note it stops at the first zero octet.
`fuel` bounds the iterations; every iteration consumes at least one octet,
so `decodeADN` passes the input length and fuel never runs out first. -/
def decodeLabels : Nat → List Nat → Option (List (List Nat))
  | 0, _ => none
  | _ + 1, [] => none                    -- "ADN not root-terminated"
  | f + 1, n :: rest =>
    if n = 0 then some []
    else if n > rest.length then none    -- "label length exceeds remaining"
    else (decodeLabels f (rest.drop n)).map (rest.take n :: ·)

/-- `decodeADN`. -/
def decodeADN (b : List Nat) : Option (List Nat) := (decodeLabels b.length b).map join

theorem decode_encodeLabels (ls : List (List Nat)) (body r : List Nat) (f : Nat)
    (hf : f > body.length) (h : encodeLabels ls = some body) :
    decodeLabels f (body ++ 0 :: r) = some ls := by
  induction ls generalizing body f with
  | nil =>
    simp [encodeLabels] at h; subst h
    cases f with
    | zero => omega
    | succ f => simp [decodeLabels]
  | cons l ls ih =>
    unfold encodeLabels at h
    split at h
    · simp at h
    · split at h
      · simp at h
      · rename_i hne hlen
        cases he : encodeLabels ls with
        | none => simp [he] at h
        | some body' =>
          simp only [he, Option.map_some, Option.some.injEq] at h
          subst h
          have hl : l.length ≠ 0 := by simpa using hne
          cases f with
          | zero => omega
          | succ f =>
            simp only [List.length_cons, List.length_append] at hf
            simp only [List.cons_append, List.append_assoc, decodeLabels, hl, if_false,
              List.length_append, List.length_cons]
            rw [if_neg (by omega)]
            simp [ih body' f (by omega) he]

theorem encodeADN_length {name out : List Nat} (h : encodeADN name = some out) :
    out.length ≤ 255 := by
  unfold encodeADN at h
  simp only at h
  split at h
  · simp at h
  · split at h
    · simp at h
    · split at h
      · simp at h
      · simp at h; subst h; omega

/-- ADN round trip: `decodeADN(encodeADN(name)) = TrimSuffix(name, ".")`. -/
theorem decodeADN_encodeADN {name out : List Nat} (h : encodeADN name = some out) :
    decodeADN out = some (trimDot name) := by
  unfold encodeADN at h
  simp only at h
  split at h
  · simp at h
  · split at h
    · simp at h
    · rename_i body hb
      split at h
      · simp at h
      · simp only [Option.some.injEq] at h
        subst h
        unfold decodeADN
        rw [decode_encodeLabels _ body [] _ (by simp) hb]
        simp [join_split]

/-- `decodeADN` is not injective, and accepts names `encodeADN` would never
produce: a single 3-octet label containing a `.` octet decodes to the same
text as the two labels `a`, `b`. A peer sending `\003a.b\000` gets ADN
"a.b", which re-encodes differently. (radnr only emits this option, so
this matters only to anything reusing the decoder.) -/
theorem decodeADN_not_injective :
    decodeADN [3, 97, 46, 98, 0] = decodeADN [1, 97, 1, 98, 0] ∧
    ([3, 97, 46, 98, 0] : List Nat) ≠ [1, 97, 1, 98, 0] := by
  decide

/-- `decodeADN` also ignores anything after the root label inside the ADN
field (`Unmarshal` slices exactly ADNLength octets, then stops at the first
zero): two different ADN fields give the same name. -/
theorem decodeADN_ignores_trailing :
    decodeADN [1, 97, 0, 255] = decodeADN [1, 97, 0] := by
  decide

/-! ## The option -/

/-- `EncryptedDNS`. `addrs` holds each address's `As16()` bytes. -/
structure Option' where
  prio : Nat
  lifetime : Nat
  adn : List Nat
  addrs : List (List Nat)
  svc : List Nat
  deriving DecidableEq

/-- The option body `Marshal` builds after the (Type, Length) header. -/
def body (o : Option') (adn : List Nat) : List Nat :=
  be16 o.prio ++ be32 o.lifetime ++ be16 adn.length ++ adn ++
    be16 o.addrs.flatten.length ++ o.addrs.flatten ++ be16 o.svc.length ++ o.svc

/-- `(octetUnit - total%octetUnit) % octetUnit`. -/
def padLen (total : Nat) : Nat := (8 - total % 8) % 8

theorem body_length (o : Option') (adn : List Nat) :
    (body o adn).length = 12 + adn.length + o.addrs.flatten.length + o.svc.length := by
  simp only [body, be16, be32, List.length_append, List.length_cons, List.length_nil]
  omega

theorem padLen_aligned (T : Nat) : (T + padLen T) % 8 = 0 := by
  unfold padLen; omega

theorem padLen_lt (T : Nat) : padLen T < 8 := by
  unfold padLen; omega

/-- `Marshal`. -/
def marshal (o : Option') : Option (List Nat) :=
  match encodeADN o.adn with
  | none => none
  | some adn =>
    if adn.length > 65535 ∨ o.addrs.flatten.length > 65535 ∨ o.svc.length > 65535 then none
    else
      let total := 2 + (body o adn).length
      if (total + padLen total) / 8 > 255 then none
      else some (144 :: (total + padLen total) / 8 :: body o adn ++ List.replicate (padLen total) 0)

/-- `parseHeader`. -/
def parseHeader (b : List Nat) : Option (List Nat) :=
  if b.length < 8 then none
  else match b with
    | t :: len :: _ =>
      if t ≠ 144 then none
      else if len * 8 = 0 ∨ len * 8 > b.length then none
      else some ((b.take (len * 8)).drop 2)
    | _ => none

/-- `read16`. -/
def read16 : List Nat → Option (Nat × List Nat)
  | a :: b :: r => some (a * 256 + b, r)
  | _ => none

/-- The lifetime read. -/
def read32 : List Nat → Option (Nat × List Nat)
  | a :: b :: c :: d :: r => some (((a * 256 + b) * 256 + c) * 256 + d, r)
  | _ => none

/-- `parseADNField`. -/
def parseADNField (p : List Nat) (len : Nat) : Option (List Nat × List Nat) :=
  if len > p.length then none
  else (decodeADN (p.take len)).map (·, p.drop len)

/-- The 16-octet stride loop of `parseAddrs`, with fuel as in
`decodeLabels`. -/
def chunks16 : Nat → List Nat → List (List Nat)
  | 0, _ => []
  | _ + 1, [] => []
  | f + 1, l => l.take 16 :: chunks16 f (l.drop 16)

/-- `parseAddrs`. -/
def parseAddrs (p : List Nat) (len : Nat) : Option (List (List Nat) × List Nat) :=
  if len % 16 ≠ 0 then none
  else if len > p.length then none
  else some (chunks16 len (p.take len), p.drop len)

/-- `parseSvcParams`. -/
def parseSvcParams (p : List Nat) (len : Nat) : Option (List Nat) :=
  if len > p.length then none else some (p.take len)

/-- `Unmarshal`. -/
def unmarshal (b : List Nat) : Option Option' := do
  let p ← parseHeader b
  let (prio, p) ← read16 p
  let (lifetime, p) ← read32 p
  let (adnLen, p) ← read16 p
  let (adn, p) ← parseADNField p adnLen
  let (addrLen, p) ← read16 p
  let (addrs, p) ← parseAddrs p addrLen
  let (svcLen, p) ← read16 p
  let svc ← parseSvcParams p svcLen
  pure { prio, lifetime, adn, addrs, svc }

/-! ### Field lemmas -/

theorem read16_be16 {n : Nat} (h : n < 65536) (r : List Nat) :
    read16 (be16 n ++ r) = some (n, r) := by
  simp only [be16, read16, List.cons_append, List.nil_append, Option.some.injEq,
    Prod.mk.injEq, and_true]
  omega

theorem read32_be32 {n : Nat} (h : n < 4294967296) (r : List Nat) :
    read32 (be32 n ++ r) = some (n, r) := by
  simp only [be32, read32, List.cons_append, List.nil_append, Option.some.injEq,
    Prod.mk.injEq, and_true]
  omega

theorem chunks16_flatten (as : List (List Nat)) (h : ∀ a ∈ as, a.length = 16)
    (f : Nat) (hf : f ≥ as.length) : chunks16 f as.flatten = as := by
  induction as generalizing f with
  | nil => cases f <;> simp [chunks16]
  | cons a as ih =>
    have ha : a.length = 16 := h a (by simp)
    cases f with
    | zero => simp at hf
    | succ f =>
      cases a with
      | nil => simp at ha
      | cons x xs =>
        rw [List.flatten_cons, List.cons_append, chunks16, ← List.cons_append,
          List.take_left' ha, List.drop_left' ha,
          ih (fun y hy => h y (by simp [hy])) f (by simp at hf; omega)]
        simp

theorem flatten_length (as : List (List Nat)) (h : ∀ a ∈ as, a.length = 16) :
    as.flatten.length = 16 * as.length := by
  induction as with
  | nil => simp
  | cons a as ih =>
    simp only [List.flatten_cons, List.length_append, List.length_cons,
      h a (by simp), ih (fun x hx => h x (by simp [hx]))]
    omega

theorem parseHeader_ok (k : Nat) (X : List Nat) (hk : k * 8 = X.length + 2)
    (_hX : X.length ≥ 6) : parseHeader (144 :: k :: X) = some X := by
  unfold parseHeader
  simp only [List.length_cons]
  rw [if_neg (by omega)]
  simp only [ne_eq, not_true_eq_false, if_false]
  rw [if_neg (by omega), List.take_of_length_le (by simp; omega)]
  rfl

theorem parseADNField_app {A n rest : List Nat} (h : decodeADN A = some n) :
    parseADNField (A ++ rest) A.length = some (n, rest) := by
  unfold parseADNField
  rw [if_neg (by simp), List.take_left, List.drop_left, h]
  rfl

theorem parseAddrs_app {as : List (List Nat)} (has : ∀ a ∈ as, a.length = 16)
    (rest : List Nat) : parseAddrs (as.flatten ++ rest) as.flatten.length = some (as, rest) := by
  unfold parseAddrs
  rw [if_neg (by simp [flatten_length _ has]), if_neg (by simp),
    List.take_left, List.drop_left,
    chunks16_flatten _ has _ (by simp [flatten_length _ has]; omega)]

theorem parseSvcParams_app (S pad : List Nat) :
    parseSvcParams (S ++ pad) S.length = some S := by
  unfold parseSvcParams
  rw [if_neg (by simp), List.take_left]

/-- `Unmarshal` on anything laid out the way `Marshal` lays it out. -/
theorem unmarshal_layout (prio life : Nat) (A n : List Nat) (as : List (List Nat))
    (S pad : List Nat) (k : Nat)
    (hprio : prio < 65536) (hlife : life < 4294967296)
    (hA : A.length < 65536) (hB : as.flatten.length < 65536) (hS : S.length < 65536)
    (hdec : decodeADN A = some n) (has : ∀ a ∈ as, a.length = 16)
    (hk : k * 8 = 2 + 12 + A.length + as.flatten.length + S.length + pad.length) :
    unmarshal (144 :: k :: (be16 prio ++ be32 life ++ be16 A.length ++ A ++
        be16 as.flatten.length ++ as.flatten ++ be16 S.length ++ S ++ pad))
      = some { prio := prio, lifetime := life, adn := n, addrs := as, svc := S } := by
  have hlen : (be16 prio ++ be32 life ++ be16 A.length ++ A ++ be16 as.flatten.length ++
      as.flatten ++ be16 S.length ++ S ++ pad).length
      = 12 + A.length + as.flatten.length + S.length + pad.length := by
    simp only [be16, be32, List.length_append, List.length_cons, List.length_nil]; omega
  rw [unmarshal, parseHeader_ok k _ (by rw [hlen]; omega) (by rw [hlen]; omega)]
  simp only [List.append_assoc, Option.bind_eq_bind, Option.bind_some,
    read16_be16 hprio, read32_be32 hlife, read16_be16 hA, parseADNField_app hdec,
    read16_be16 hB, parseAddrs_app has, read16_be16 hS, parseSvcParams_app]
  rfl

/-! ### The theorems -/

/-- RFC 4861 §4.6 / RFC 9463 §6.1: the encoded option is a whole number of
8-octet units, its Length octet counts exactly those units, and it fits
the one-octet field. -/
theorem marshal_aligned {o : Option'} {w : List Nat} (h : marshal o = some w) :
    w.length % 8 = 0 ∧ w[1]? = some (w.length / 8) ∧ w.length ≤ 2040 := by
  unfold marshal at h
  split at h
  · simp at h
  · rename_i adn _
    simp only at h
    split at h
    · simp at h
    · split at h
      · simp at h
      · rename_i hbig
        simp only [Option.some.injEq] at h
        subst h
        have hl : (144 :: (2 + (body o adn).length + padLen (2 + (body o adn).length)) / 8 ::
            body o adn ++ List.replicate (padLen (2 + (body o adn).length)) 0).length
            = 2 + (body o adn).length + padLen (2 + (body o adn).length) := by
          simp only [List.length_cons, List.length_append, List.length_replicate]; omega
        rw [hl]
        have ha := padLen_aligned (2 + (body o adn).length)
        refine ⟨ha, rfl, ?_⟩
        omega

/-- **Round trip.** Anything `Marshal` accepts, `Unmarshal` decodes to the
same option, with the ADN's one optional trailing dot removed. -/
theorem unmarshal_marshal (o : Option') (w : List Nat)
    (hprio : o.prio < 65536) (hlife : o.lifetime < 4294967296)
    (haddrs : ∀ a ∈ o.addrs, a.length = 16)
    (h : marshal o = some w) :
    unmarshal w = some { o with adn := trimDot o.adn } := by
  unfold marshal at h
  split at h
  · simp at h
  · rename_i adn hadn
    simp only at h
    split at h
    · simp at h
    · rename_i hfit
      split at h
      · simp at h
      · simp only [Option.some.injEq] at h
        subst h
        simp only [not_or, Nat.not_lt] at hfit
        obtain ⟨h1, h2, h3⟩ := hfit
        have ha := padLen_aligned (2 + (body o adn).length)
        have hb := body_length o adn
        simp only [List.cons_append]
        exact unmarshal_layout o.prio o.lifetime adn (trimDot o.adn) o.addrs o.svc
          (List.replicate (padLen (2 + (body o adn).length)) 0)
          ((2 + (body o adn).length + padLen (2 + (body o adn).length)) / 8)
          hprio hlife (by omega) (by omega) (by omega) (decodeADN_encodeADN hadn) haddrs
          (by simp only [List.length_replicate]; omega)

end Dnr

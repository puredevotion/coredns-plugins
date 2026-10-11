import CorednsPlugins.Serial

/-!
# DNS Cookies — the future `cookie` plugin (RFC 7873, RFC 9018)

There is no Go code yet. This file is the model the Go will be reviewed
against, so it uses the names and shapes the design (`docs/cookie-plugin.md`)
fixes:

```go
func classify(optLen int) class                         // malformed | clientOnly | withServer
func hashInput(client [8]byte, version byte, reserved [3]byte,
               ts uint32, ip []byte) []byte             // client|version|reserved|ts(BE)|ip, 20 or 32 bytes
func serverCookie(secret [16]byte, client [8]byte, ts uint32, ip netip.Addr) [16]byte
                                                        // version 1, reserved zero, ts BE, 8-byte SipHash-2-4
func verify(secrets [][16]byte, client [8]byte, server [16]byte, ip netip.Addr, now uint32) bool
                                                        // version == 1; hash over the RECEIVED reserved bytes;
                                                        // window by RFC 1982: <= 3600 s old or <= 300 s ahead
func inWindow(now, ts uint32) bool {
	if ts == now { return true }
	if serialGreater(now, ts) { return now-ts <= 3600 }   // cookie is in the past
	if serialGreater(ts, now) { return ts-now <= 300 }    // cookie is in the future
	return false                                          // antipode: RFC 1982 leaves it undefined
}
```

## Model, and how exact it is

* A byte is a `Nat` (below 256 wherever it matters), a byte string a
  `List Nat`. A `uint32` is a `Nat` below `2^32`. `now - ts` in Go wraps;
  under the guard `serialGreater now ts` it equals `(now + 2^32 - ts) % 2^32`,
  which is what `inWindow` uses, so the model is exact there.
* `serialGreater` is `Serial.serialGreater`, the RFC 1982 §3.2 comparison
  proved in `Serial.lean`. Nothing about it is redone here.
* An address is its 4 (IPv4) or 16 (IPv6) bytes. IPv4-mapped IPv6 unmapping
  (design doc, "Wire format") happens before `hashInput` and is not modelled;
  the proofs take the 4-or-16 byte slice as given.
* The Go arrays `[8]byte`, `[16]byte` are lists whose length is a hypothesis
  of the theorem that needs it (or a pattern in `verify`, which matches
  exactly 16 bytes).
* **SipHash is a parameter** `H : Secret -> Bytes -> Nat` in the structural
  theorems (§§ 1-4): deterministic, and nothing more, except where a theorem
  states an explicit hypothesis (`HInj`, the collision-freeness a
  pseudorandom function is *assumed* to have). Those theorems are therefore
  **conditional** and say so. In § 5 SipHash-2-4 is implemented concretely
  and the abstract model is instantiated with it.
* Hash byte order: SipHash returns a 64-bit **value**. RFC 9018 §4.4 puts it
  in the 8-byte Hash Sub-Field, and the test vectors (Appendix A) show it is
  serialised **little-endian**, least significant byte first. `le64` below is
  that serialisation; the vectors in § 5 fail if it is big-endian. (SipHash's
  own message and key words are also little-endian.)

## What is not claimed

Nothing here says SipHash is a PRF, or that a 64-bit tag is enough. It says
that *given* a collision-free hash the plugin's accept/reject logic is the
logic the RFCs prescribe, and that the concrete SipHash-2-4 here reproduces
the published vectors.
-/

namespace Cookie

/-- `2^32`, the timestamp space. -/
local notation "M" => 4294967296
/-- `2^64`, the SipHash output space. -/
local notation "M64" => 18446744073709551616

/-! ## 1. Option length classes — `classify` (RFC 7873 §4, §5.2.2) -/

/-- RFC 7873 §5.2.2 case (2), (3), and (4)/(5) of the five server cases. -/
inductive Class where
  | malformed
  | clientOnly
  | withServer
  deriving DecidableEq, Repr

/-- ```go
func classify(n int) class {
	switch {
	case n == 8:           return clientOnly
	case n >= 16 && n <= 40: return withServer
	}
	return malformed
}
``` -/
def classify (n : Nat) : Class :=
  if n = 8 then .clientOnly else if 16 ≤ n ∧ n ≤ 40 then .withServer else .malformed

/-- RFC 7873 §5.2.2: "If the COOKIE option is too short to contain a Client
Cookie, then FORMERR is generated. If the COOKIE option is longer than that
required to hold a COOKIE option with just a Client Cookie (8 bytes) but is
shorter than the minimum COOKIE option with both a Client Cookie and a Server
Cookie (16 bytes), then FORMERR is generated. If the COOKIE option is longer
than the maximum valid COOKIE option (40 bytes), then FORMERR is generated.
In summary, valid cookie lengths are 8 and 16 to 40 inclusive."

An option length is non-malformed exactly when it is 8 or in `16..40`. -/
theorem classify_valid_iff (n : Nat) :
    classify n ≠ .malformed ↔ (n = 8 ∨ (16 ≤ n ∧ n ≤ 40)) := by
  unfold classify
  split <;> try split
  all_goals simp_all <;> omega

/-- The three classes partition the lengths: each length has exactly the one
class, and each class is exactly its length set. -/
theorem classify_partition (n : Nat) :
    (classify n = .clientOnly ↔ n = 8) ∧
    (classify n = .withServer ↔ (16 ≤ n ∧ n ≤ 40)) ∧
    (classify n = .malformed ↔ (n ≠ 8 ∧ ¬ (16 ≤ n ∧ n ≤ 40))) := by
  unfold classify
  split <;> try split
  all_goals simp_all <;> omega

/-- RFC 7873 §4: a `withServer` option is an 8-byte client cookie followed by
"the variable-length (8 bytes to 32 bytes) Server Cookie". -/
theorem classify_server_len (n : Nat) (h : classify n = .withServer) :
    8 ≤ n - 8 ∧ n - 8 ≤ 32 := by
  have := (classify_partition n).2.1.mp h
  omega

/-! ## 2. The SipHash input — `hashInput` (RFC 9018 §4.4) -/

/-- A 32-bit big-endian serialisation, Go's `binary.BigEndian.PutUint32`. -/
def be32 (t : Nat) : List Nat := [t / 16777216 % 256, t / 65536 % 256, t / 256 % 256, t % 256]

/-- The 8-byte Hash Sub-Field: the 64-bit SipHash value, little-endian. -/
def le64 (h : Nat) : List Nat :=
  [h % 256, h / 256 % 256, h / 65536 % 256, h / 16777216 % 256,
   h / 4294967296 % 256, h / 1099511627776 % 256,
   h / 281474976710656 % 256, h / 72057594037927936 % 256]

/-- `hashInput`: `Client Cookie | Version | Reserved | Timestamp | Client-IP`. -/
def hashInput (client : List Nat) (version : Nat) (reserved : List Nat) (ts : Nat)
    (ip : List Nat) : List Nat :=
  client ++ [version] ++ reserved ++ be32 ts ++ ip

theorem be32_length (t : Nat) : (be32 t).length = 4 := rfl

/-- The timestamp serialisation loses nothing below `2^32`. -/
theorem be32_injective {a b : Nat} (ha : a < M) (hb : b < M) (h : be32 a = be32 b) : a = b := by
  simp only [be32, List.cons.injEq, and_true] at h
  omega

/-- RFC 9018 §4.4: "The length of all the concatenated elements (the input
into [SipHash-2-4]) MUST be either precisely 20 bytes in case of an IPv4
Client-IP or precisely 32 bytes in case of an IPv6 Client-IP." -/
theorem hashInput_length {client reserved ip : List Nat} {v ts : Nat}
    (hc : client.length = 8) (hr : reserved.length = 3)
    (hip : ip.length = 4 ∨ ip.length = 16) :
    (hashInput client v reserved ts ip).length = 20 ∧ ip.length = 4 ∨
    (hashInput client v reserved ts ip).length = 32 ∧ ip.length = 16 := by
  simp only [hashInput, List.length_append, List.length_cons, List.length_nil, hc, hr, be32_length]
  omega

/-- RFC 9018 §4.4: the length check on the option "ensures that the input
into [SipHash-2-4] is an injective function of the elements making up the
input, and thereby prevents data substitution attacks."

For an 8-byte client cookie, a 3-byte reserved field and a 4- or 16-byte IP,
`hashInput` is injective in `(client, version, reserved, ts, ip)`, **including
across the IPv4/IPv6 split**: two equal inputs have equal parts, in
particular the same IP length, and (by `hashInput_length`) a 20-byte input is
never equal to a 32-byte one. Timestamps are `uint32`, hence `< 2^32`.

The 4-or-16 hypotheses on the IPs are not used by the proof (hence the
underscores): injectivity holds because everything before the IP has a fixed
width and the IP comes last, so the IP is whatever remains. That is exactly
why the length gate matters: the confusion in `lenient_collision` arises when
a *variable-width* field (the server cookie) sits before the IP. -/
theorem hashInput_injective
    {c₁ c₂ r₁ r₂ ip₁ ip₂ : List Nat} {v₁ v₂ t₁ t₂ : Nat}
    (hc₁ : c₁.length = 8) (hc₂ : c₂.length = 8)
    (hr₁ : r₁.length = 3) (hr₂ : r₂.length = 3)
    (_hip₁ : ip₁.length = 4 ∨ ip₁.length = 16) (_hip₂ : ip₂.length = 4 ∨ ip₂.length = 16)
    (ht₁ : t₁ < M) (ht₂ : t₂ < M)
    (h : hashInput c₁ v₁ r₁ t₁ ip₁ = hashInput c₂ v₂ r₂ t₂ ip₂) :
    c₁ = c₂ ∧ v₁ = v₂ ∧ r₁ = r₂ ∧ t₁ = t₂ ∧ ip₁ = ip₂ := by
  have hlen := congrArg List.length h
  simp only [hashInput, List.length_append, List.length_cons, List.length_nil, hc₁, hc₂,
    hr₁, hr₂, be32_length] at hlen
  have hipl : ip₁.length = ip₂.length := by omega
  simp only [hashInput, List.append_assoc] at h
  obtain ⟨e1, h⟩ := List.append_inj h (by omega)
  obtain ⟨e2, h⟩ := List.append_inj h (by simp)
  obtain ⟨e3, h⟩ := List.append_inj h (by omega)
  obtain ⟨e4, e5⟩ := List.append_inj h (by simp [be32_length])
  simp only [List.cons.injEq, and_true] at e2
  exact ⟨e1, e2, e3, be32_injective ht₁ ht₂ e4, e5⟩

/-- The option the server sees is `client ++ server`; verification requires its
length to be exactly 24 (RFC 9018 §4.4: "the length of the received COOKIE
option MUST be precisely 24 bytes"). -/
def lengthGate (optLen : Nat) : Bool := optLen == 24

/-- What a *lenient* verifier would hash if it did not check the option
length: the received client cookie, then every received server-cookie byte
except the trailing 8-byte hash (`body`, which would be version, reserved and
timestamp for a 16-byte cookie), then the client IP. -/
def lenientInput (client body ip : List Nat) : List Nat := client ++ body ++ ip

/-- RFC 9018 §4.4: "this prevents a 36-byte COOKIE option coming from an
IPv4 Client-IP to be validated as if it were coming from an IPv6 Client-IP."

What this shows: WITHOUT the length check, the SipHash input is not injective
in the bytes the plugin controls. Here a 36-byte option from an IPv4 client
(`body` is 20 bytes) and a 24-byte option from an IPv6 client (`body` is 8
bytes) produce the very same 32-byte hash input, so one hash would validate
both. (The 12 padding bytes and the IPv4 address are chosen to spell out the
IPv6 address; the 8 bytes `0..7` stand for version, reserved and timestamp.) -/
theorem lenient_collision :
    ∃ (client body4 ip4 body6 ip6 : List Nat),
      ip4.length = 4 ∧ ip6.length = 16 ∧
      (client ++ body4).length + 8 = 36 ∧ (client ++ body6).length + 8 = 24 ∧
      lenientInput client body4 ip4 = lenientInput client body6 ip6 ∧ ip4 ≠ ip6 :=
  ⟨List.replicate 8 9, [1,0,0,0,0,0,0,1] ++ List.replicate 12 7, List.replicate 4 7,
   [1,0,0,0,0,0,0,1], List.replicate 16 7, by decide⟩

/-- What the length gate does show: if the whole option is 24 bytes, i.e. the
server cookie has 16 bytes, then `body` has exactly 8 bytes and the lenient
input *is* `hashInput`'s shape, so § 2's injectivity applies and the
collision above cannot happen. The 36-byte option is rejected by the gate
itself (`lengthGate 36 = false`).

What it does NOT show: that the Go slices the option at the right offsets,
or that no other length confusion exists in code that does not go through
`hashInput`. `verify` below matches exactly 16 server bytes, which is how the
gate is enforced in the model. -/
theorem gate_excludes_36 : lengthGate 36 = false ∧ lengthGate 24 = true := by decide

/-- Under the gate the body is 8 bytes: version, 3 reserved, 4 timestamp. -/
theorem gate_body_len {server : List Nat} (hs : server.length = 16) :
    (server.take (server.length - 8)).length = 8 := by
  simp [hs]

/-! ## 3. The timestamp window under serial arithmetic (RFC 9018 §4.3) -/

/-- `inWindow now ts`, exactly the Go above. -/
def inWindow (now ts : Nat) : Bool :=
  ts == now ||
  (Serial.serialGreater now ts && decide ((now + 4294967296 - ts) % 4294967296 ≤ 3600)) ||
  (Serial.serialGreater ts now && decide ((ts + 4294967296 - now) % 4294967296 ≤ 300))

/-- RFC 9018 §4.3: "The Timestamp value prevents Replay Attacks and MUST be
checked by the server to be within a defined period of time. The DNS server
SHOULD allow cookies within a 1-hour period in the past and a 5-minute period
into the future to allow operation of low-volume clients and some limited
time skew between the DNS servers in the anycast set."

"All comparisons involving these fields MUST use 'Serial number arithmetic',
as defined in [RFC1982]. [RFC1982] specifies how the differences should be
handled. This handles any relative time window less than 68 years, at any
time in the future (2038, 2106, 2256, 22209, or later.)" (RFC 1982 §3.2: `i1`
is less than `i2` iff "(i1 < i2 and i2 - i1 < 2^(SERIAL_BITS - 1)) or (i1 >
i2 and i1 - i2 > 2^(SERIAL_BITS - 1))".)

Let `t` be real, unbounded time and `d` an offset with `|d| < 2^31` (RFC 1982
leaves exactly `2^31` apart undefined). If now is `t mod 2^32` and the
cookie's stamp is `(t + d) mod 2^32`, the decision is the same as on unbounded
integers: accepted iff `-3600 ≤ d ≤ 300` (stamp up to 3600 s before now, or up
to 300 s after). This includes `t` and `t + d` on either side of a wrap of
the 32-bit counter. -/
theorem window_wrap (t : Nat) (d : Int) (hd1 : -2147483648 < d) (hd2 : d < 2147483648)
    (_ht : 0 ≤ (t : Int) + d) :
    inWindow (t % 4294967296) (((t : Int) + d) % 4294967296).toNat = true ↔
      (-3600 ≤ d ∧ d ≤ 300) := by
  unfold inWindow Serial.serialGreater
  simp only [Bool.or_eq_true, Bool.and_eq_true, beq_iff_eq, bne_iff_ne, ne_eq,
    decide_eq_true_eq, Bool.or_eq_true]
  omega

/-- The exact boundary seconds, for any `now` (`ts` is `now + d` taken mod
`2^32`): 3600 s old is in, 3601 s old is out; 300 s ahead is in, 301 s ahead is
out. -/
theorem window_edges (now : Nat) (hn : now < M) :
    inWindow now ((now + M - 3600) % M) = true ∧
    inWindow now ((now + M - 3601) % M) = false ∧
    inWindow now ((now + 300) % M) = true ∧
    inWindow now ((now + 301) % M) = false := by
  unfold inWindow Serial.serialGreater
  refine ⟨?_, ?_, ?_, ?_⟩ <;>
  · simp only [Bool.or_eq_true, Bool.and_eq_true, beq_iff_eq, bne_iff_ne, ne_eq,
      decide_eq_true_eq, Bool.or_eq_false_iff, Bool.and_eq_false_iff,
      decide_eq_false_iff_not, beq_eq_false_iff_ne]
    omega

/-- The antipodal stamp (exactly `2^31` away) is rejected, not guessed at:
RFC 1982 leaves it undefined, and 2^31 s is far outside both limits anyway. -/
theorem window_antipode (now : Nat) (hn : now < M) :
    inWindow now ((now + 2147483648) % M) = false := by
  unfold inWindow Serial.serialGreater
  simp only [Bool.or_eq_false_iff, Bool.and_eq_false_iff, decide_eq_false_iff_not,
      beq_eq_false_iff_ne]
  omega

/-- The wrap itself, concretely: now = 100 s after the counter wrapped, the
cookie was minted 100 s before the wrap. Plain integer comparison would call
it 4294967196 s in the future. -/
example : inWindow 100 4294967196 = true := by decide
/-- And from the other side: now 100 s before the wrap, a cookie stamped 100 s
after it is 200 s in the future, inside the 300 s allowance. -/
example : inWindow 4294967196 100 = true := by decide

/-! ## 4. Construction and verification -/

section Model

-- SipHash-2-4, abstractly: key bytes and message bytes to a 64-bit value.
-- No property is assumed except where a theorem takes `HInj`.
variable (H : List Nat → List Nat → Nat)

/-- `serverCookie`: version 1, reserved zero, timestamp BE, then the 8-byte
hash (SipHash value, little-endian) over `hashInput client 1 000 ts ip`. -/
def serverCookie (k client : List Nat) (ts : Nat) (ip : List Nat) : List Nat :=
  [1, 0, 0, 0] ++ be32 ts ++ le64 (H k (hashInput client 1 [0, 0, 0] ts ip))

/-- A version-1 cookie with arbitrary reserved bytes whose hash is taken over
those same bytes: what an RFC 9018 server other than this one may legally have
minted in the future (A.3). -/
def mkCookie (k client : List Nat) (r₁ r₂ r₃ ts : Nat) (ip : List Nat) : List Nat :=
  [1, r₁, r₂, r₃] ++ be32 ts ++ le64 (H k (hashInput client 1 [r₁, r₂, r₃] ts ip))

theorem serverCookie_eq_mkCookie (k client ts ip) :
    serverCookie H k client ts ip = mkCookie H k client 0 0 0 ts ip := rfl

/-- ```go
func verify(secrets [][16]byte, client [8]byte, server [16]byte, ip netip.Addr, now uint32) bool {
	if server[0] != 1 { return false }
	reserved := server[1:4]  // NOT required to be zero
	ts := binary.BigEndian.Uint32(server[4:8])
	if !inWindow(now, ts) { return false }
	for _, k := range secrets {
		if hash(k, hashInput(client, 1, reserved, ts, ip)) == server[8:16] { return true }
	}
	return false
}
```
The Go signature takes `server [16]byte`, so "not exactly 16 bytes" is checked
by the caller (the length gate); the model takes a byte list and matches
exactly 16 elements, anything else is `false`. -/
def verify (secrets : List (List Nat)) (client server : List Nat) (ip : List Nat)
    (now : Nat) : Bool :=
  match server with
  | [v, r₁, r₂, r₃, t₁, t₂, t₃, t₄, h₁, h₂, h₃, h₄, h₅, h₆, h₇, h₈] =>
    let ts := ((t₁ * 256 + t₂) * 256 + t₃) * 256 + t₄
    v == 1 && inWindow now ts &&
    secrets.any fun k =>
      le64 (H k (hashInput client 1 [r₁, r₂, r₃] ts ip)) == [h₁, h₂, h₃, h₄, h₅, h₆, h₇, h₈]
  | _ => false

theorem be32_decode {ts : Nat} (h : ts < M) :
    ((ts / 16777216 % 256 * 256 + ts / 65536 % 256) * 256 + ts / 256 % 256) * 256 + ts % 256
      = ts := by
  omega

/-- A cookie `serverCookie` built under secret `k` at time `ts` is accepted by
`verify` whenever `k` is among the secrets and `now` is inside the window of
`ts`, for any client cookie and IP. (`ts` is a `uint32`.) No property of `H`
is needed: verification recomputes exactly what construction computed. -/
theorem verify_generate (secrets : List (List Nat)) (k client ip : List Nat) (ts now : Nat)
    (hk : k ∈ secrets) (hts : ts < M) (hw : inWindow now ts = true) :
    verify H secrets client (serverCookie H k client ts ip) ip now = true := by
  simp only [serverCookie, verify, be32, le64, List.cons_append, List.nil_append, be32_decode hts,
    hw, Bool.and_true, beq_self_eq_true, Bool.true_and, List.any_eq_true]
  exact ⟨k, hk, by simp [hashInput, be32]⟩

/-- RFC 9018 §4.2: "On construction, it MUST be set to zero octets. On Server
Cookie verification, the server MUST NOT enforce those fields to be zero, and
the Hash should be computed with the received value as described in Section
4.4." (Appendix A.3: "the Server Cookie has Reserved bytes set but is still
valid with the configured secret; the Hash part is calculated taking along the
Reserved bytes.")

A cookie with arbitrary reserved bytes, hashed over those bytes, verifies. So
verification neither enforces zero nor ignores the field: § 5 checks the
concrete A.3 cookie (`abcdef`) end to end, and `verify_reserved_hashed` below
shows the hash does depend on the received bytes. -/
theorem verify_reserved (secrets : List (List Nat)) (k client ip : List Nat)
    (r₁ r₂ r₃ ts now : Nat)
    (hk : k ∈ secrets) (hts : ts < M) (hw : inWindow now ts = true) :
    verify H secrets client (mkCookie H k client r₁ r₂ r₃ ts ip) ip now = true := by
  simp only [mkCookie, verify, be32, le64, List.cons_append, List.nil_append, be32_decode hts,
    hw, Bool.and_true, beq_self_eq_true, Bool.true_and, List.any_eq_true]
  exact ⟨k, hk, by simp [hashInput, be32]⟩

/-- Collision-freeness of the hash, *as a hypothesis*: equal 64-bit outputs
come from equal keys and equal inputs. This is the (idealised) PRF assumption
and is the only thing the three theorems below use about `H`. A real 64-bit
function cannot satisfy it on an infinite domain; it is true of a PRF only up
to a negligible probability on the finitely many inputs an adversary can try.
Those theorems are conditional on it, and say nothing about SipHash's real
collision probability. -/
def HInj : Prop :=
  ∀ k m k' m', H k m % M64 = H k' m' % M64 → k = k' ∧ m = m'

theorem le64_injective {a b : Nat} (h : le64 a = le64 b) : a % M64 = b % M64 := by
  simp only [le64, List.cons.injEq, and_true] at h
  omega

/-- A cookie minted for `ip₁` does not verify for any other IP `ip₂` (both 4 or
16 bytes), and one minted under `k₁` verifies only if `k₁` is among the
secrets — in particular not under a single different secret `k₂ ≠ k₁`
(`verify_wrong_secret`). Conditional on `HInj`. -/
theorem verify_wrong_ip (hinj : HInj H) (secrets : List (List Nat))
    (k client ip₁ ip₂ : List Nat) (ts now : Nat)
    (hc : client.length = 8) (hts : ts < M)
    (h₁ : ip₁.length = 4 ∨ ip₁.length = 16) (h₂ : ip₂.length = 4 ∨ ip₂.length = 16)
    (hne : ip₁ ≠ ip₂) :
    verify H secrets client (serverCookie H k client ts ip₁) ip₂ now = false := by
  cases hv : verify H secrets client (serverCookie H k client ts ip₁) ip₂ now
  · rfl
  · exfalso
    simp only [serverCookie, verify, be32, le64, List.cons_append, List.nil_append,
      be32_decode hts, Bool.and_eq_true, beq_iff_eq, List.any_eq_true, List.cons.injEq,
      and_true] at hv
    obtain ⟨⟨_, _⟩, k', _, hk'⟩ := hv
    have hm := hinj _ _ _ _ (le64_injective (by simpa [le64] using hk'))
    have := hashInput_injective hc hc (by rfl) (by rfl) h₂ h₁ hts hts hm.2
    exact hne this.2.2.2.2.symm

theorem verify_wrong_secret (hinj : HInj H) (secrets : List (List Nat))
    (k₁ client ip : List Nat) (ts now : Nat) (hts : ts < M)
    (h : verify H secrets client (serverCookie H k₁ client ts ip) ip now = true) :
    k₁ ∈ secrets := by
  simp only [serverCookie, verify, be32, le64, List.cons_append, List.nil_append,
    be32_decode hts, Bool.and_eq_true, beq_iff_eq, List.any_eq_true, List.cons.injEq,
    and_true] at h
  obtain ⟨⟨_, _⟩, k', hk', hk''⟩ := h
  have hm := hinj _ _ _ _ (le64_injective (by simpa [le64] using hk''))
  rw [← hm.1]; exact hk'

/-- The same, in the shape the task states it: one secret, `k₂ ≠ k₁`. -/
theorem verify_wrong_secret_or_ip (hinj : HInj H) (k₁ k₂ client ip₁ ip₂ : List Nat)
    (ts now : Nat) (hc : client.length = 8) (hts : ts < M)
    (h₁ : ip₁.length = 4 ∨ ip₁.length = 16) (h₂ : ip₂.length = 4 ∨ ip₂.length = 16)
    (hk : k₁ ≠ k₂) (hip : ip₁ ≠ ip₂) :
    verify H [k₂] client (serverCookie H k₁ client ts ip₁) ip₁ now = false ∧
    verify H [k₁] client (serverCookie H k₁ client ts ip₁) ip₂ now = false := by
  refine ⟨?_, verify_wrong_ip H hinj [k₁] k₁ client ip₁ ip₂ ts now hc hts h₁ h₂ hip⟩
  cases hv : verify H [k₂] client (serverCookie H k₁ client ts ip₁) ip₁ now
  · rfl
  · exact absurd (by simpa using verify_wrong_secret H hinj [k₂] k₁ client ip₁ ts now hts hv)
      hk

/-- The hash really covers the *received* reserved bytes: a cookie whose
reserved bytes were set to something nonzero after the hash was computed over
zeros is rejected. (Conditional on `HInj`; `ip` is 4 or 16 bytes.) -/
theorem verify_reserved_hashed (hinj : HInj H) (secrets : List (List Nat))
    (k client ip : List Nat) (r₁ r₂ r₃ ts now : Nat)
    (hc : client.length = 8) (hts : ts < M) (hip : ip.length = 4 ∨ ip.length = 16)
    (hr : ¬ (r₁ = 0 ∧ r₂ = 0 ∧ r₃ = 0)) :
    verify H secrets client
      ([1, r₁, r₂, r₃] ++ be32 ts ++ le64 (H k (hashInput client 1 [0, 0, 0] ts ip))) ip now
      = false := by
  cases hv : verify H secrets client
      ([1, r₁, r₂, r₃] ++ be32 ts ++ le64 (H k (hashInput client 1 [0, 0, 0] ts ip))) ip now
  · rfl
  · exfalso
    simp only [verify, be32, le64, List.cons_append, List.nil_append, be32_decode hts,
      Bool.and_eq_true, beq_iff_eq, List.any_eq_true, List.cons.injEq, and_true] at hv
    obtain ⟨⟨_, _⟩, k', _, hk'⟩ := hv
    have hm := hinj _ _ _ _ (le64_injective (by simpa [le64] using hk'))
    have := hashInput_injective hc hc (by rfl) (by rfl) hip hip hts hts hm.2
    simp only [List.cons.injEq, and_true] at this
    exact hr (by simp_all)

/-- A server cookie whose length is not exactly 16 never verifies (RFC 9018
§4.4, the length check; §7: version 1 is defined for size 16 only), and
neither does a 16-byte one whose version byte is not 1 (§4.1, §6: "determined
by the initial version byte and by the length"). -/
theorem verify_rejects_bad_length_or_version (secrets : List (List Nat))
    (client server ip : List Nat) (now : Nat) :
    (server.length ≠ 16 → verify H secrets client server ip now = false) ∧
    (∀ v rest, server = v :: rest → v ≠ 1 → verify H secrets client server ip now = false) := by
  constructor
  · intro hl
    unfold verify
    split
    · simp_all
    · rfl
  · intro v rest hs hv
    subst hs
    unfold verify
    split
    · simp_all
    · rfl

end Model

/-! ## 5. SipHash-2-4, concretely, against RFC 9018 Appendix A -/

namespace Sip

/-- `rotl`, on 64 bits. -/
def rotl (x : UInt64) (b : UInt64) : UInt64 := (x <<< b) ||| (x >>> (64 - b))

/-- The SipRound of the SipHash paper (§2.2), on `(v0, v1, v2, v3)`. -/
def round (v : UInt64 × UInt64 × UInt64 × UInt64) : UInt64 × UInt64 × UInt64 × UInt64 :=
  let (v0, v1, v2, v3) := v
  let v0 := v0 + v1
  let v1 := rotl v1 13
  let v1 := v1 ^^^ v0
  let v0 := rotl v0 32
  let v2 := v2 + v3
  let v3 := rotl v3 16
  let v3 := v3 ^^^ v2
  let v0 := v0 + v3
  let v3 := rotl v3 21
  let v3 := v3 ^^^ v0
  let v2 := v2 + v1
  let v1 := rotl v1 17
  let v1 := v1 ^^^ v2
  let v2 := rotl v2 32
  (v0, v1, v2, v3)

/-- A little-endian 64-bit word from at most 8 bytes (missing high bytes are
zero). `foldr` makes the first byte the least significant. -/
def word (bs : List UInt8) : UInt64 :=
  bs.foldr (fun b acc => (acc <<< 8) ||| b.toUInt64) 0

/-- Process the `n` full 8-byte blocks of `m` (c = 2 rounds per block). -/
def blocks : Nat → List UInt8 → (UInt64 × UInt64 × UInt64 × UInt64) →
    (UInt64 × UInt64 × UInt64 × UInt64)
  | 0, _, s => s
  | n + 1, m, (v0, v1, v2, v3) =>
    let w := word (m.take 8)
    let s := round (round (v0, v1 , v2, v3 ^^^ w))
    blocks n (m.drop 8) (s.1 ^^^ w, s.2.1, s.2.2.1, s.2.2.2)

/-- SipHash-2-4, 64-bit output, 16-byte key (`k`) — the SipHash paper, §2. -/
def siphash24 (k m : List UInt8) : UInt64 :=
  let k0 := word (k.take 8)
  let k1 := word ((k.drop 8).take 8)
  let s := blocks (m.length / 8) m
    (k0 ^^^ 0x736f6d6570736575, k1 ^^^ 0x646f72616e646f6d,
     k0 ^^^ 0x6c7967656e657261, k1 ^^^ 0x7465646279746573)
  let b := (m.length.toUInt64 <<< 56) ||| word (m.drop (8 * (m.length / 8)))
  let s := round (round (s.1, s.2.1, s.2.2.1, s.2.2.2 ^^^ b))
  let s := round (round (round (round (s.1 ^^^ b, s.2.1, s.2.2.1 ^^^ 0xff, s.2.2.2))))
  s.1 ^^^ s.2.1 ^^^ s.2.2.1 ^^^ s.2.2.2

/-- Hex digit to value. -/
def nib (c : Char) : Nat :=
  if c.toNat ≤ 57 then c.toNat - 48 else c.toNat - 87

/-- `"0a1b"` to `[0x0a, 0x1b]`. -/
def hex (s : String) : List Nat :=
  let rec go : List Char → List Nat
    | a :: b :: r => (nib a * 16 + nib b) :: go r
    | _ => []
  go s.toList

/-- The abstract model's `H`, instantiated: SipHash-2-4 on byte lists. -/
def H (k m : List Nat) : Nat :=
  (siphash24 (k.map Nat.toUInt8) (m.map Nat.toUInt8)).toNat

end Sip

open Sip in
/-- Reference vectors from the SipHash paper (Appendix A and the reference
`vectors.h`), key `00 01 .. 0f`: the paper's 15-byte message `00 .. 0e` gives
`a129ca6149be45e5`, and the empty message gives `726fdb47dd0e0e31`. -/
theorem siphash_paper_vectors :
    siphash24 ((List.range 16).map Nat.toUInt8) ((List.range 15).map Nat.toUInt8)
      = 0xa129ca6149be45e5 ∧
    siphash24 ((List.range 16).map Nat.toUInt8) [] = 0x726fdb47dd0e0e31 := by
  decide +kernel

open Sip

/-! ### RFC 9018 Appendix A

Common to every vector: the Hash Sub-Field is the SipHash value
**little-endian**, so e.g. A.1's `1f8130c3eee29480` is the value
`0x8094e2eec330811f`. Kernel-checked (`decide +kernel`: the kernel evaluates
the definitions above; no compiler and no `native_decide`). -/

/-- A.1: client 198.51.100.100, client cookie `2464c4abcf10c957`, secret
`e5e973e5a6b2a43f48e7dc849e37bfcf`, timestamp 1559731985 (2019-06-05
10:53:05 UTC): "COOKIE: 2464c4abcf10c957010000005cf79f111f8130c3eee29480
(good)". -/
theorem vector_A1 :
    serverCookie H (hex "e5e973e5a6b2a43f48e7dc849e37bfcf") (hex "2464c4abcf10c957")
      1559731985 [198, 51, 100, 100] = hex "010000005cf79f111f8130c3eee29480" := by
  decide +kernel

/-- A.2: the same client and secret 40 minutes later, timestamp 1559734385:
`2464c4abcf10c957010000005cf7a871d4a564a1442aca77`. And the A.1 cookie the
client sends back, now 2400 s old, verifies. -/
theorem vector_A2 :
    serverCookie H (hex "e5e973e5a6b2a43f48e7dc849e37bfcf") (hex "2464c4abcf10c957")
      1559734385 [198, 51, 100, 100] = hex "010000005cf7a871d4a564a1442aca77" ∧
    verify H [hex "e5e973e5a6b2a43f48e7dc849e37bfcf"] (hex "2464c4abcf10c957")
      (hex "010000005cf79f111f8130c3eee29480") [198, 51, 100, 100] 1559734385 = true := by
  decide +kernel

/-- A.3: client 203.0.113.203, client cookie `fc93fc62807ddb86`. The request's
server cookie `01abcdef5cf78f71a314227b6679ebf5` (timestamp 1559727985, Reserved
`abcdef`) is valid with the configured secret, the hash taken over the
Reserved bytes: it verifies at its own timestamp and at any time up to an hour
later; the reply, a freshly generated cookie with Reserved zero and timestamp
1559734700, is `010000005cf7a9acf73a7810aca2381e`.

FINDING. The RFC's reply is sent at 1559734700, which is **6715 s** after the
request cookie's timestamp, more than the 3600 s that RFC 9018 §4.3 says a
server SHOULD allow. So with the fixed one-hour window of the design,
`verify` at the reply's time returns **false** (`A3_stale`), although the hash
is right and the RFC calls the cookie "valid". Both are conforming (§4.3 is a
SHOULD); a Go test of this vector must pick `now` inside the window (or test
the hash separately), or it will fail for the wrong reason. -/
theorem vector_A3 :
    verify H [hex "e5e973e5a6b2a43f48e7dc849e37bfcf"] (hex "fc93fc62807ddb86")
      (hex "01abcdef5cf78f71a314227b6679ebf5") [203, 0, 113, 203] 1559727985 = true ∧
    verify H [hex "e5e973e5a6b2a43f48e7dc849e37bfcf"] (hex "fc93fc62807ddb86")
      (hex "01abcdef5cf78f71a314227b6679ebf5") [203, 0, 113, 203] (1559727985 + 3600) = true ∧
    mkCookie H (hex "e5e973e5a6b2a43f48e7dc849e37bfcf") (hex "fc93fc62807ddb86")
      0xab 0xcd 0xef 1559727985 [203, 0, 113, 203]
      = hex "01abcdef5cf78f71a314227b6679ebf5" ∧
    serverCookie H (hex "e5e973e5a6b2a43f48e7dc849e37bfcf") (hex "fc93fc62807ddb86")
      1559734700 [203, 0, 113, 203] = hex "010000005cf7a9acf73a7810aca2381e" := by
  decide +kernel

/-- The finding above, stated: at the reply's time the request cookie is
outside the window, and the zeroed-Reserved variant of the same cookie would
not have verified either (the hash covers the bytes). -/
theorem A3_stale :
    inWindow 1559734700 1559727985 = false ∧
    verify H [hex "e5e973e5a6b2a43f48e7dc849e37bfcf"] (hex "fc93fc62807ddb86")
      (hex "01abcdef5cf78f71a314227b6679ebf5") [203, 0, 113, 203] 1559734700 = false ∧
    verify H [hex "e5e973e5a6b2a43f48e7dc849e37bfcf"] (hex "fc93fc62807ddb86")
      (hex "01000000" ++ hex "5cf78f71a314227b6679ebf5") [203, 0, 113, 203] 1559727985 = false := by
  decide +kernel

/-- A.4: IPv6 client `2001:db8:220:1:59de:d0f4:8769:82b8`, client cookie
`22681ab97d52c298`. The request cookie `010000005cf7c57926556bd0934c72f8`
(timestamp 1559741817, 13:36:57) was minted under the old secret
`dd3bdf9344b678b185a6f5cb60fca715`; the server now generates with
`445536bcd2513298075a5d379663c962` but still verifies the old one, so with
`[new, old]` it verifies at the reply's time (1559741961, 144 s later) and
with the new secret alone it does not. The reply is
`010000005cf7c609a6bb79d16625507a`. -/
theorem vector_A4 :
    verify H [hex "445536bcd2513298075a5d379663c962", hex "dd3bdf9344b678b185a6f5cb60fca715"]
      (hex "22681ab97d52c298") (hex "010000005cf7c57926556bd0934c72f8")
      (hex "20010db80220000159ded0f4876982b8") 1559741961 = true ∧
    verify H [hex "445536bcd2513298075a5d379663c962"]
      (hex "22681ab97d52c298") (hex "010000005cf7c57926556bd0934c72f8")
      (hex "20010db80220000159ded0f4876982b8") 1559741961 = false ∧
    serverCookie H (hex "dd3bdf9344b678b185a6f5cb60fca715") (hex "22681ab97d52c298")
      1559741817 (hex "20010db80220000159ded0f4876982b8")
      = hex "010000005cf7c57926556bd0934c72f8" ∧
    serverCookie H (hex "445536bcd2513298075a5d379663c962") (hex "22681ab97d52c298")
      1559741961 (hex "20010db80220000159ded0f4876982b8")
      = hex "010000005cf7c609a6bb79d16625507a" := by
  decide +kernel

/-- The hash length is exactly what the Go's `[16]byte` holds: for the
concrete SipHash too (`le64` always yields 8 bytes), so `serverCookie` is 16
bytes. -/
theorem serverCookie_length (k client ip : List Nat) (ts : Nat) :
    (serverCookie H k client ts ip).length = 16 := rfl

end Cookie

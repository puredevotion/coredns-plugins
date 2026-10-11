package cookie

import (
	"encoding/binary"
	"math/bits"
)

// SipHash initialisation constants: the ASCII of "somepseudorandomlygeneratedbytes".
const (
	sipInit0 = 0x736f6d6570736575
	sipInit1 = 0x646f72616e646f6d
	sipInit2 = 0x6c7967656e657261
	sipInit3 = 0x7465646279746573
)

// Finalisation and message-length constants.
const (
	lengthShift = 56   // The message length mod 256 goes in the top byte of the last block.
	sipFinal    = 0xff // Xored into v2 before the finalisation rounds.
	byteMask    = 0xff
	bitsPerByte = 8
)

// SipRound rotation distances.
const (
	rotA = 13
	rotB = 32
	rotC = 16
	rotD = 21
	rotE = 17
)

// sipState is SipHash's four-word internal state.
type sipState struct{ v0, v1, v2, v3 uint64 }

// round is one SipRound.
func (s *sipState) round() {
	s.v0 += s.v1
	s.v1 = bits.RotateLeft64(s.v1, rotA)
	s.v1 ^= s.v0
	s.v0 = bits.RotateLeft64(s.v0, rotB)
	s.v2 += s.v3
	s.v3 = bits.RotateLeft64(s.v3, rotC)
	s.v3 ^= s.v2
	s.v0 += s.v3
	s.v3 = bits.RotateLeft64(s.v3, rotD)
	s.v3 ^= s.v0
	s.v2 += s.v1
	s.v1 = bits.RotateLeft64(s.v1, rotE)
	s.v1 ^= s.v2
	s.v2 = bits.RotateLeft64(s.v2, rotB)
}

// absorb mixes one 64-bit message word in: the "2" of SipHash-2-4.
func (s *sipState) absorb(m uint64) {
	s.v3 ^= m
	s.round()
	s.round()
	s.v0 ^= m
}

// siphash24 is SipHash-2-4 with a 128-bit key and a 64-bit output (Aumasson
// and Bernstein, "SipHash: a fast short-input PRF", INDOCRYPT 2012). RFC 9018
// §6 makes it the REQUIRED algorithm for interoperable server cookies.
//
// Written out here rather than imported: it is a page of code with no
// dependency, and it is checked against both the paper's vectors and the RFC
// 9018 Appendix A cookies (cookie_test.go).
func siphash24(key [16]byte, msg []byte) uint64 {
	k0 := binary.LittleEndian.Uint64(key[0:8])
	k1 := binary.LittleEndian.Uint64(key[8:16])
	s := sipState{k0 ^ sipInit0, k1 ^ sipInit1, k0 ^ sipInit2, k1 ^ sipInit3}

	n := len(msg)
	for len(msg) >= 8 {
		s.absorb(binary.LittleEndian.Uint64(msg))
		msg = msg[8:]
	}

	// The last block: the remaining 0..7 bytes, little endian, with the
	// message length mod 256 in the top byte.
	last := uint64(n&byteMask) << lengthShift
	for i, b := range msg {
		last |= uint64(b) << (bitsPerByte * uint(i))
	}
	s.absorb(last)

	// Finalisation: the "4".
	s.v2 ^= sipFinal
	s.round()
	s.round()
	s.round()
	s.round()
	return s.v0 ^ s.v1 ^ s.v2 ^ s.v3
}

package swu

import (
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"math/bits"
	"testing"
)

const (
	rfc4186MK   = "e576d5ca332e9930018bf1baee2763c795b3c712"
	rfc4186Keys = "536e5ebc4465582aa6a8ec9986ebb62025af1942efcbf4bc72b3943421f2a974" +
		"39d45aeaf4e30601983e972b6cfd46d1c363773365690d09cd44976b525f47d3" +
		"a60a985e955c53b090b2e4b73719196a402542968fd14a888f46b9a7886e4488" +
		"5949eab0fff69d52315c6c634fd14a7f0d52023d56f79698fa6596abeed4f93f" +
		"bb48eb534d985414ceed0d9a8ed33c387c9dfdab92ffbdf240fcecf65a2c93b9"
)

func referenceHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func referenceCompression(input []byte) []byte {
	initial := [5]uint32{0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0}
	state := initial
	var block [64]byte
	copy(block[:], input)
	var schedule [80]uint32
	for index := range 16 {
		schedule[index] = binary.BigEndian.Uint32(block[index*4:])
	}
	for index := 16; index < 80; index++ {
		schedule[index] = bits.RotateLeft32(schedule[index-16]^schedule[index-14]^schedule[index-8]^schedule[index-3], 1)
	}
	constants := [4]uint32{0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6}
	for index, word := range schedule {
		var nonlinear uint32
		switch index / 20 {
		case 0:
			nonlinear = state[3] ^ (state[1] & (state[2] ^ state[3]))
		case 1, 3:
			nonlinear = state[1] ^ state[2] ^ state[3]
		case 2:
			nonlinear = (state[1] & state[2]) | (state[3] & (state[1] | state[2]))
		}
		next := bits.RotateLeft32(state[0], 5) + nonlinear + state[4] + constants[index/20] + word
		state = [5]uint32{next, state[0], bits.RotateLeft32(state[1], 30), state[2], state[3]}
	}
	var output []byte
	for index, word := range state {
		output = binary.BigEndian.AppendUint32(output, word+initial[index])
	}
	return output
}

func referenceExpansion(master []byte) []byte {
	state := new(big.Int).SetBytes(master)
	modulus := new(big.Int).Lsh(big.NewInt(1), 160)
	var output []byte
	for range 8 {
		block := referenceCompression(state.FillBytes(make([]byte, 20)))
		output = append(output, block...)
		state.Add(state, new(big.Int).SetBytes(block))
		state.Add(state, big.NewInt(1))
		state.Mod(state, modulus)
	}
	return output
}

func Test_AKAReference_matchesPublishedVector_whenRFC4186A5MK(t *testing.T) {
	master := referenceHex(t, rfc4186MK)
	got := referenceExpansion(master)
	if hex.EncodeToString(got) != rfc4186Keys {
		t.Fatal("independent reference differs from RFC 4186 Appendix A.5")
	}
}

func Test_AKAReference_matchesSHA1_whenOnePaddedBlock(t *testing.T) {
	block := make([]byte, 64)
	copy(block, "abc")
	block[3] = 0x80
	block[63] = 24
	got := referenceCompression(block)
	want := sha1.Sum([]byte("abc"))
	if hex.EncodeToString(got) != hex.EncodeToString(want[:]) {
		t.Fatal("independent compression differs from standard SHA-1")
	}
}

package crypto

import (
	"encoding/hex"
	"testing"
)

type xcbcVector struct {
	name    string
	key     string
	message string
	want    string
}

func Test_AES128XCBCPRF_matchesRFC3566Vectors(t *testing.T) {
	const key = "000102030405060708090a0b0c0d0e0f"
	runAES128XCBCVectors(t, []xcbcVector{
		{name: "empty message", key: key, message: "", want: "75f0251d528ac01c4573dfd584d79f29"},
		{name: "partial block", key: key, message: "000102", want: "5b376580ae2f19afe7219ceef172756f"},
		{name: "one complete block", key: key, message: "000102030405060708090a0b0c0d0e0f", want: "d2a246fa349b68a79998a4394ff7a263"},
		{name: "complete and partial blocks", key: key, message: "000102030405060708090a0b0c0d0e0f10111213", want: "47f51b4564966215b8985c63055ed308"},
		{name: "two complete blocks", key: key, message: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", want: "f54f0ec8d2b9f3d36807734bd5283fd4"},
		{name: "two complete and one partial blocks", key: key, message: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021", want: "becbb3bccdb518a30677d5481fb6b4d8"},
	})
}

func Test_AES128XCBCPRF_normalizesKeys_perRFC4434(t *testing.T) {
	const message = "000102030405060708090a0b0c0d0e0f10111213"
	runAES128XCBCVectors(t, []xcbcVector{
		{name: "exact key", key: "000102030405060708090a0b0c0d0e0f", message: message, want: "47f51b4564966215b8985c63055ed308"},
		{name: "short key", key: "00010203040506070809", message: message, want: "0fa087af7d866e7653434e602fdde835"},
		{name: "long key", key: "000102030405060708090a0b0c0d0e0fedcb", message: message, want: "8cd3c93ae598a9803006ffb67c40e9e4"},
	})
}

func runAES128XCBCVectors(t *testing.T, vectors []xcbcVector) {
	t.Helper()
	for _, vector := range vectors {
		t.Run(vector.name, func(t *testing.T) {
			// Given
			key := decodeTestHex(t, vector.key)
			message := decodeTestHex(t, vector.message)

			// When
			prf, err := GetPRF(4)
			if err != nil {
				t.Fatalf("GetPRF(4): %v", err)
			}
			got, err := prf.Compute(key, message)
			// Then
			if err != nil {
				t.Fatalf("Compute: %v", err)
			}
			if gotHex := hex.EncodeToString(got); gotHex != vector.want {
				t.Fatalf("Compute() = %s, want %s", gotHex, vector.want)
			}
		})
	}
}

func decodeTestHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("decode %q: %v", value, err)
	}
	return decoded
}

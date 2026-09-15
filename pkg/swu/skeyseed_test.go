package swu

import (
	"encoding/hex"
	"testing"

	"github.com/1239t/swu-go/pkg/crypto"
)

func Test_deriveInitialSKEYSEED_usesCompleteNonces_forVariableLengthPRF(t *testing.T) {
	// Given
	input := initialSKEYSEEDInput{
		PRF:            crypto.PRF_HMAC_SHA2_256,
		InitiatorNonce: decodeSKEYSEEDHex(t, "0001020304050607a0a1a2a3a4a5a6a7"),
		ResponderNonce: decodeSKEYSEEDHex(t, "08090a0b0c0d0e0fb0b1b2b3b4b5b6b7"),
		SharedSecret:   decodeSKEYSEEDHex(t, "000102030405060708090a0b0c0d0e0f10111213"),
	}

	// When
	got, err := deriveInitialSKEYSEED(input)
	// Then
	if err != nil {
		t.Fatalf("deriveInitialSKEYSEED: %v", err)
	}
	const want = "b434d32cf48a7e3a989d6698892e745cda5f2409901e6229fd0d3fbf8d85b68c"
	if gotHex := hex.EncodeToString(got); gotHex != want {
		t.Fatalf("SKEYSEED = %s, want %s", gotHex, want)
	}
}

func Test_deriveInitialSKEYSEED_usesNoncePrefixes_forFixedLengthPRF(t *testing.T) {
	// Given: the first eight bytes of each nonce form the RFC 4434 16-byte test key.
	input := initialSKEYSEEDInput{
		PRF:            crypto.PRF_AES128_XCBC,
		InitiatorNonce: decodeSKEYSEEDHex(t, "0001020304050607a0a1a2a3a4a5a6a7"),
		ResponderNonce: decodeSKEYSEEDHex(t, "08090a0b0c0d0e0fb0b1b2b3b4b5b6b7"),
		SharedSecret:   decodeSKEYSEEDHex(t, "000102030405060708090a0b0c0d0e0f10111213"),
	}

	// When
	got, err := deriveInitialSKEYSEED(input)
	// Then
	if err != nil {
		t.Fatalf("deriveInitialSKEYSEED: %v", err)
	}
	const want = "47f51b4564966215b8985c63055ed308"
	if gotHex := hex.EncodeToString(got); gotHex != want {
		t.Fatalf("SKEYSEED = %s, want %s", gotHex, want)
	}
}

func Test_deriveInitialSKEYSEED_rejectsShortNonce_forFixedLengthPRF(t *testing.T) {
	// Given
	input := initialSKEYSEEDInput{
		PRF:            crypto.PRF_AES128_XCBC,
		InitiatorNonce: make([]byte, 7),
		ResponderNonce: make([]byte, 8),
		SharedSecret:   []byte("shared secret"),
	}

	// When
	_, err := deriveInitialSKEYSEED(input)

	// Then
	if err == nil {
		t.Fatal("deriveInitialSKEYSEED succeeded with a short initiator nonce")
	}
}

func decodeSKEYSEEDHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("decode %q: %v", value, err)
	}
	return decoded
}

package swu

import (
	"encoding/hex"
	"testing"

	"github.com/1239t/swu-go/pkg/crypto"
)

func Test_computeIKEAuthData_preservesHMACSHA256Flow(t *testing.T) {
	// Given
	input := ikeAuthPRFInput{
		PRF:             crypto.PRF_HMAC_SHA2_256,
		MSK:             []byte("0123456789abcdef0123456789abcdef"),
		InitiatorPRFKey: []byte("abcdef0123456789abcdef0123456789"),
		InitiatorIDBody: append([]byte{0x03, 0x00, 0x00, 0x00}, []byte("user@example.com")...),
		SAInitRequest:   []byte("ike-sa-init-request"),
		ResponderNonce:  []byte("responder-nonce"),
	}

	// When
	got, err := computeIKEAuthData(input)
	// Then
	if err != nil {
		t.Fatalf("computeIKEAuthData: %v", err)
	}
	const want = "bbce937fb6b2a3b256eb3c283f6f4728c34503c3cd867612d0ff5632b6eabd25"
	if gotHex := hex.EncodeToString(got); gotHex != want {
		t.Fatalf("AUTH data = %s, want %s", gotHex, want)
	}
}

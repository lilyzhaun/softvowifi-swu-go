package swu

import (
	"fmt"

	"github.com/1239t/swu-go/pkg/crypto"
)

type initialSKEYSEEDInput struct {
	PRF            crypto.PRF
	InitiatorNonce []byte
	ResponderNonce []byte
	SharedSecret   []byte
}

func deriveInitialSKEYSEED(input initialSKEYSEEDInput) ([]byte, error) {
	keyCapacity := len(input.InitiatorNonce) + len(input.ResponderNonce)
	if input.PRF.FixedKeySize() {
		keyCapacity = input.PRF.KeyLen()
	}
	key := make([]byte, 0, keyCapacity)

	if input.PRF.FixedKeySize() {
		noncePrefixLen := input.PRF.KeyLen() / 2
		if len(input.InitiatorNonce) < noncePrefixLen || len(input.ResponderNonce) < noncePrefixLen {
			return nil, fmt.Errorf(
				"fixed-size PRF requires %d bytes from each nonce: initiator=%d responder=%d",
				noncePrefixLen,
				len(input.InitiatorNonce),
				len(input.ResponderNonce),
			)
		}
		key = append(key, input.InitiatorNonce[:noncePrefixLen]...)
		key = append(key, input.ResponderNonce[:noncePrefixLen]...)
	} else {
		key = append(key, input.InitiatorNonce...)
		key = append(key, input.ResponderNonce...)
	}

	skeyseed, err := input.PRF.Compute(key, input.SharedSecret)
	if err != nil {
		return nil, fmt.Errorf("compute initial SKEYSEED: %w", err)
	}
	return skeyseed, nil
}

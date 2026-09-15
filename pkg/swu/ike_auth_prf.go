package swu

import (
	"fmt"

	"github.com/1239t/swu-go/pkg/crypto"
)

type ikeAuthPRFInput struct {
	PRF             crypto.PRF
	MSK             []byte
	InitiatorPRFKey []byte
	InitiatorIDBody []byte
	SAInitRequest   []byte
	ResponderNonce  []byte
}

func computeIKEAuthData(input ikeAuthPRFInput) ([]byte, error) {
	authKey, err := input.PRF.Compute(input.MSK, []byte("Key Pad for IKEv2"))
	if err != nil {
		return nil, fmt.Errorf("derive IKE_AUTH key: %w", err)
	}

	idHash, err := input.PRF.Compute(input.InitiatorPRFKey, input.InitiatorIDBody)
	if err != nil {
		return nil, fmt.Errorf("compute IKE_AUTH identity hash: %w", err)
	}

	signedOctets := make([]byte, 0, len(input.SAInitRequest)+len(input.ResponderNonce)+len(idHash))
	signedOctets = append(signedOctets, input.SAInitRequest...)
	signedOctets = append(signedOctets, input.ResponderNonce...)
	signedOctets = append(signedOctets, idHash...)

	authData, err := input.PRF.Compute(authKey, signedOctets)
	if err != nil {
		return nil, fmt.Errorf("compute IKE_AUTH data: %w", err)
	}
	return authData, nil
}

// computeResponderIKEAuthData is RFC 7296 §2.15/§2.16 responder AUTH after EAP:
// prf(prf(MSK, "Key Pad for IKEv2"), RealMessage2 | Ni | prf(SK_pr, IDr')).
func computeResponderIKEAuthData(prf crypto.PRF, msk, skPr, idrBody, realMessage2, ni []byte) ([]byte, error) {
	return computeIKEAuthData(ikeAuthPRFInput{
		PRF:             prf,
		MSK:             msk,
		InitiatorPRFKey: skPr,
		InitiatorIDBody: idrBody,
		SAInitRequest:   realMessage2,
		ResponderNonce:  ni,
	})
}

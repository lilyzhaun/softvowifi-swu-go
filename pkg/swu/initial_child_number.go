package swu

import "github.com/1239t/swu-go/pkg/ikev2"

// InitialChildProposalNumberError still rejects the entire authenticated
// transaction. It only permits a caller to make a fresh, single-offer request.
type InitialChildProposalNumberError struct {
	OfferedNumber uint8
}

func (*InitialChildProposalNumberError) Error() string {
	return "initial Child proposal numbering mismatch: invalid initial Child SA transaction"
}

func (*InitialChildProposalNumberError) Unwrap() error { return errInitialChild }

// The caller has verified responder AUTH and all final notifications. A hint
// additionally requires every original SA/CP/TS check with only the number
// corrected, and must identify exactly one complete, original offer.
func (s *Session) initialChildProposalNumberHint(payloads []ikev2.Payload) error {
	if s.cfg.InitialChildProposalNumber != 0 {
		return nil
	}
	request, err := ikev2.DecodePacket(s.initialChildRequest)
	if err != nil {
		return nil
	}
	var offers []*ikev2.Proposal
	for _, payload := range request.Payloads {
		if sa, ok := payload.(*ikev2.EncryptedPayloadSA); ok {
			offers = sa.Proposals
		}
	}
	var hint *InitialChildProposalNumberError
	for index, payload := range payloads {
		sa, ok := payload.(*ikev2.EncryptedPayloadSA)
		if !ok || len(sa.Proposals) != 1 || sa.Proposals[0].ProposalNum != 1 {
			continue
		}
		for _, offer := range offers {
			if offer.ProposalNum == 1 {
				continue
			}
			selected := *sa.Proposals[0]
			selected.ProposalNum = offer.ProposalNum
			corrected := append([]ikev2.Payload(nil), payloads...)
			corrected[index] = &ikev2.EncryptedPayloadSA{Proposals: []*ikev2.Proposal{&selected}}
			if _, err := s.selectInitialChild(corrected); err == nil {
				if hint != nil {
					return nil
				}
				hint = &InitialChildProposalNumberError{OfferedNumber: offer.ProposalNum}
			}
		}
	}
	if hint != nil {
		return hint
	}
	return nil
}

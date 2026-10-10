package ikev2

import "fmt"

// InitProposalNumberError is still an invalid response, never an accepted SA.
// It identifies one complete original offer for a caller's fresh-session retry.
type InitProposalNumberError struct {
	OfferedNumber uint8
}

func (e *InitProposalNumberError) Error() string {
	return fmt.Sprintf("IKE_SA_INIT proposal number mismatch (offered %d)", e.OfferedNumber)
}

func (e *InitProposalNumberError) Unwrap() error { return ErrInitResponse }

func initProposalNumberHint(payloads, offered []Payload) error {
	for index, payload := range payloads {
		sa, ok := payload.(*EncryptedPayloadSA)
		if !ok || len(sa.Proposals) != 1 || sa.Proposals[0].ProposalNum != 1 {
			continue
		}
		for _, original := range offered {
			offer, ok := original.(*EncryptedPayloadSA)
			if !ok {
				continue
			}
			for _, proposal := range offer.Proposals {
				if proposal.ProposalNum <= 1 || len(proposal.Transforms) != 4 {
					continue
				}
				chosen := *sa.Proposals[0]
				chosen.ProposalNum = proposal.ProposalNum
				trial := append([]Payload(nil), payloads...)
				trial[index] = &EncryptedPayloadSA{Proposals: []*Proposal{&chosen}}
				// Reuse every strict structural, DH, nonce and whole-offer check.
				// Only diagnose renumbering; never replace the response transcript.
				if ValidateInitSelection(trial, offered) == nil {
					return &InitProposalNumberError{OfferedNumber: proposal.ProposalNum}
				}
			}
		}
	}
	return nil
}

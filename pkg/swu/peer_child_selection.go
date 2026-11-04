package swu

import (
	"encoding/binary"

	"github.com/1239t/swu-go/pkg/ikev2"
)

type peerChildSelection struct {
	proposal *ikev2.Proposal
	nonce    []byte
	tsi, tsr []*ikev2.TrafficSelector
	ke       []byte
}

func (s *Session) currentChildProposal(spi []byte) *ikev2.Proposal {
	p := ikev2.NewProposal(1, ikev2.ProtoESP, spi)
	p.AddTransformWithKeyLen(ikev2.TransformTypeEncr, ikev2.AlgorithmType(s.childEncrID), s.childEncrKeyLenBits)
	if s.childIntegID != 0 {
		p.AddTransform(ikev2.TransformTypeInteg, ikev2.AlgorithmType(s.childIntegID), 0)
	}
	esn := ikev2.AlgorithmType(0)
	if s.childESN {
		esn = 1
	}
	p.AddTransform(ikev2.TransformTypeESN, esn, 0)
	return p
}

func (s *Session) selectPeerChild(payloads []ikev2.Payload) (peerChildSelection, uint16) {
	var empty peerChildSelection
	var sa *ikev2.EncryptedPayloadSA
	var nonce *ikev2.EncryptedPayloadNonce
	var tsi, tsr *ikev2.EncryptedPayloadTS
	var predecessor *ikev2.EncryptedPayloadNotify
	var ke *ikev2.EncryptedPayloadKE
	for _, pl := range payloads {
		switch p := pl.(type) {
		case *ikev2.EncryptedPayloadSA:
			if sa != nil {
				return empty, ikev2.INVALID_SYNTAX
			}
			sa = p
		case *ikev2.EncryptedPayloadNonce:
			if nonce != nil {
				return empty, ikev2.INVALID_SYNTAX
			}
			nonce = p
		case *ikev2.EncryptedPayloadTS:
			if p.IsInitiator {
				if tsi != nil {
					return empty, ikev2.INVALID_SYNTAX
				}
				tsi = p
			} else {
				if tsr != nil {
					return empty, ikev2.INVALID_SYNTAX
				}
				tsr = p
			}
		case *ikev2.EncryptedPayloadKE:
			if ke != nil {
				return empty, ikev2.INVALID_SYNTAX
			}
			ke = p
		case *ikev2.EncryptedPayloadNotify:
			if p.NotifyType < 16384 {
				return empty, ikev2.INVALID_SYNTAX
			}
			if p.NotifyType == ikev2.REKEY_SA {
				if predecessor != nil {
					return empty, ikev2.INVALID_SYNTAX
				}
				predecessor = p
			}
		}
	}
	if predecessor == nil {
		return empty, ikev2.NO_ADDITIONAL_SAS
	}
	if predecessor.ProtocolID != ikev2.ProtoESP || len(predecessor.SPI) != 4 || len(predecessor.NotifyData) != 0 {
		return empty, ikev2.INVALID_SYNTAX
	}
	if s.ChildSAIn == nil || s.ChildSAOut == nil || binary.BigEndian.Uint32(predecessor.SPI) != s.ChildSAOut.SPI {
		return empty, ikev2.CHILD_SA_NOT_FOUND
	}
	if sa == nil || nonce == nil || len(nonce.NonceData) < max(16, s.PRFAlg.KeyLen()/2) || len(nonce.NonceData) > 256 {
		return empty, ikev2.INVALID_SYNTAX
	}
	group := s.proposalPolicy.childPFS
	if group == 0 && ke != nil {
		return empty, ikev2.NO_PROPOSAL_CHOSEN
	}
	if group != 0 {
		if ke == nil {
			return empty, ikev2.INVALID_SYNTAX
		}
		if uint16(ke.DHGroup) != group {
			return empty, ikev2.INVALID_KE_PAYLOAD
		}
	}
	// Exchange initiator is the peer, so its TSi is our stored TSr.
	if tsi == nil || tsr == nil || validateInitialTS(tsi, &ikev2.EncryptedPayloadTS{IsInitiator: true, TrafficSelectors: s.tsr}) != nil || validateInitialTS(tsr, &ikev2.EncryptedPayloadTS{TrafficSelectors: s.tsi}) != nil {
		return empty, ikev2.TS_UNACCEPTABLE
	}
	// This rekey preserves the existing policy selectors; it does not claim
	// support for changing/narrowing the original kernel policy during rekey.
	if validateInitialTS(&ikev2.EncryptedPayloadTS{IsInitiator: true, TrafficSelectors: s.tsr}, tsi) != nil || validateInitialTS(&ikev2.EncryptedPayloadTS{TrafficSelectors: s.tsi}, tsr) != nil {
		return empty, ikev2.TS_UNACCEPTABLE
	}
	want := s.currentChildProposal(nil)
	if group != 0 {
		want.AddTransform(ikev2.TransformTypeDH, ikev2.AlgorithmType(group), 0)
	}
	for _, p := range sa.Proposals {
		if p.ProtocolID != ikev2.ProtoESP || len(p.SPI) != 4 || p.ProposalNum == 0 || binary.BigEndian.Uint32(p.SPI) == 0 || binary.BigEndian.Uint32(p.SPI) == s.ChildSAOut.SPI {
			continue
		}
		selected := ikev2.NewProposal(p.ProposalNum, ikev2.ProtoESP, append([]byte(nil), p.SPI...))
		for _, expected := range want.Transforms {
			for _, got := range p.Transforms {
				if sameRekeyTransform(got, expected) {
					selected.Transforms = append(selected.Transforms, got)
					break
				}
			}
		}
		known := true
		dhCount := 0
		for _, got := range p.Transforms {
			if got.Type == ikev2.TransformTypeDH {
				dhCount++
				if dhCount > 1 || uint16(got.ID) != group || len(got.Attributes) != 0 {
					known = false
				}
			}
			found := false
			for _, expected := range want.Transforms {
				found = found || got.Type == expected.Type
			}
			known = known && found
		}
		if known && len(selected.Transforms) == len(want.Transforms) {
			result := peerChildSelection{proposal: selected, nonce: nonce.NonceData, tsi: tsi.TrafficSelectors, tsr: tsr.TrafficSelectors}
			if ke != nil {
				result.ke = ke.KEData
			}
			return result, 0
		}
	}
	return empty, ikev2.NO_PROPOSAL_CHOSEN
}

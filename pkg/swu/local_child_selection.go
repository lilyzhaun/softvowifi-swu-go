package swu

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/1239t/swu-go/pkg/ikev2"
)

func (s *Session) localChildProposals(spi []byte) ([]*ikev2.Proposal, error) {
	all := ikev2.CreateMultiProposalESP(spi)
	current := s.currentChildProposal(spi)
	found := -1
	for i, p := range all {
		if sameCompleteChildProposal(p, current) {
			found = i
			break
		}
	}
	if found < 0 {
		return nil, errors.New("negotiated Child suite is not a supported complete offer")
	}
	preferred := all[found]
	copy(all[1:found+1], all[:found])
	all[0] = preferred
	for i, p := range all {
		p.ProposalNum = uint8(i + 1)
	}
	return all, nil
}

func sameCompleteChildProposal(selected, offered *ikev2.Proposal) bool {
	if len(selected.Transforms) != len(offered.Transforms) {
		return false
	}
	seen := map[ikev2.TransformType]bool{}
	for _, t := range selected.Transforms {
		if seen[t.Type] {
			return false
		}
		seen[t.Type] = true
		found := false
		for _, candidate := range offered.Transforms {
			found = found || sameRekeyTransform(t, candidate)
		}
		if !found {
			return false
		}
	}
	return true
}

type localChildSelection struct {
	encr, integ uint16
	bits        int
	esn         bool
	spi         uint32
	nonce       []byte
}

func (s *Session) selectLocalChildRekey(payloads []ikev2.Payload, request []byte) (localChildSelection, error) {
	var result localChildSelection
	invalid := errors.New("invalid local Child rekey selection")
	offer, err := ikev2.DecodePacket(request)
	if err != nil {
		return result, err
	}
	var offered *ikev2.EncryptedPayloadSA
	var offeredI, offeredR *ikev2.EncryptedPayloadTS
	for _, pl := range offer.Payloads {
		switch p := pl.(type) {
		case *ikev2.EncryptedPayloadSA:
			offered = p
		case *ikev2.EncryptedPayloadTS:
			if p.IsInitiator {
				offeredI = p
			} else {
				offeredR = p
			}
		}
	}
	var selected *ikev2.EncryptedPayloadSA
	var nonce *ikev2.EncryptedPayloadNonce
	var tsi, tsr *ikev2.EncryptedPayloadTS
	for _, pl := range payloads {
		switch p := pl.(type) {
		case *ikev2.EncryptedPayloadSA:
			if selected != nil {
				return result, invalid
			}
			selected = p
		case *ikev2.EncryptedPayloadNonce:
			if nonce != nil {
				return result, invalid
			}
			nonce = p
		case *ikev2.EncryptedPayloadTS:
			if p.IsInitiator {
				if tsi != nil {
					return result, invalid
				}
				tsi = p
			} else {
				if tsr != nil {
					return result, invalid
				}
				tsr = p
			}
		case *ikev2.EncryptedPayloadKE:
			return result, invalid
		case *ikev2.EncryptedPayloadNotify:
			if p.NotifyType < 16384 {
				return result, fmt.Errorf("CREATE_CHILD_SA 被拒绝，通知类型: %d", p.NotifyType)
			}
		}
	}
	if selected == nil || len(selected.Proposals) != 1 || offered == nil || nonce == nil || len(nonce.NonceData) < max(16, s.PRFAlg.KeyLen()/2) || len(nonce.NonceData) > 256 {
		return result, invalid
	}
	if tsi == nil || tsr == nil || offeredI == nil || offeredR == nil || validateInitialTS(tsi, offeredI) != nil || validateInitialTS(tsr, offeredR) != nil || validateInitialTS(offeredI, tsi) != nil || validateInitialTS(offeredR, tsr) != nil {
		return result, invalid
	}
	p := selected.Proposals[0]
	if p.ProtocolID != ikev2.ProtoESP || len(p.SPI) != 4 || binary.BigEndian.Uint32(p.SPI) == 0 || binary.BigEndian.Uint32(p.SPI) == s.ChildSAOut.SPI {
		return result, invalid
	}
	matched := false
	for _, original := range offered.Proposals {
		if original.ProposalNum == p.ProposalNum && sameCompleteChildProposal(p, original) {
			matched = true
			break
		}
	}
	if !matched {
		return result, invalid
	}
	for _, t := range p.Transforms {
		switch t.Type {
		case ikev2.TransformTypeEncr:
			result.encr = uint16(t.ID)
			result.bits = int(t.Attributes[0].Val)
		case ikev2.TransformTypeInteg:
			result.integ = uint16(t.ID)
		case ikev2.TransformTypeESN:
			result.esn = t.ID == 1
		}
	}
	result.spi, result.nonce = binary.BigEndian.Uint32(p.SPI), nonce.NonceData
	return result, nil
}

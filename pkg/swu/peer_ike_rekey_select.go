package swu

import (
	"bytes"
	"encoding/binary"

	"github.com/1239t/swu-go/pkg/ikev2"
)

type peerIKERekeyRejection struct{ notify uint16 }

func (e *peerIKERekeyRejection) Error() string { return "peer IKE rekey request rejected" }

func (s *Session) selectPeerIKERekey(payloads []ikev2.Payload) (*ikev2.Proposal, []byte, []byte, error) {
	invalid := &peerIKERekeyRejection{notify: ikev2.INVALID_SYNTAX}
	var sa *ikev2.EncryptedPayloadSA
	var nonce *ikev2.EncryptedPayloadNonce
	var ke *ikev2.EncryptedPayloadKE
	for _, pl := range payloads {
		switch p := pl.(type) {
		case *ikev2.EncryptedPayloadSA:
			if sa != nil {
				return nil, nil, nil, invalid
			}
			sa = p
		case *ikev2.EncryptedPayloadNonce:
			if nonce != nil {
				return nil, nil, nil, invalid
			}
			nonce = p
		case *ikev2.EncryptedPayloadKE:
			if ke != nil {
				return nil, nil, nil, invalid
			}
			ke = p
		case *ikev2.EncryptedPayloadTS:
			return nil, nil, nil, invalid
		case *ikev2.EncryptedPayloadNotify:
			if p.NotifyType < 16384 {
				return nil, nil, nil, invalid
			}
		}
	}
	if sa == nil || nonce == nil || len(nonce.NonceData) < 16 || len(nonce.NonceData) > 256 || ke == nil || len(ke.KEData) == 0 || s.Keys == nil {
		return nil, nil, nil, invalid
	}
	if uint16(ke.DHGroup) != s.ikeDHID {
		return nil, nil, nil, &peerIKERekeyRejection{notify: ikev2.INVALID_KE_PAYLOAD}
	}
	if len(nonce.NonceData) < max(16, s.PRFAlg.KeyLen()/2) {
		return nil, nil, nil, invalid
	}
	want := s.ikeRekeyProposal(nil)
	for _, offered := range sa.Proposals {
		if offered.ProtocolID != ikev2.ProtoIKE || offered.ProposalNum == 0 || len(offered.SPI) != 8 || binary.BigEndian.Uint64(offered.SPI) == 0 {
			continue
		}
		selected := ikev2.NewProposal(offered.ProposalNum, ikev2.ProtoIKE, append([]byte(nil), offered.SPI...))
		for _, required := range want.Transforms {
			for _, got := range offered.Transforms {
				if sameRekeyTransform(got, required) {
					selected.Transforms = append(selected.Transforms, got)
					break
				}
			}
		}
		known := true
		for _, got := range offered.Transforms {
			supportedType := false
			for _, required := range want.Transforms {
				supportedType = supportedType || got.Type == required.Type
			}
			known = known && supportedType
		}
		if known && len(selected.Transforms) == len(want.Transforms) {
			return selected, nonce.NonceData, ke.KEData, nil
		}
	}
	return nil, nil, nil, &peerIKERekeyRejection{notify: ikev2.NO_PROPOSAL_CHOSEN}
}

func sameRekeyTransform(a, b *ikev2.Transform) bool {
	if a.Type != b.Type || a.ID != b.ID || len(a.Attributes) != len(b.Attributes) {
		return false
	}
	for i, attr := range a.Attributes {
		other := b.Attributes[i]
		if attr.Type != other.Type || attr.Val != other.Val || !bytes.Equal(attr.Value, other.Value) {
			return false
		}
	}
	return true
}

package ikev2

import (
	"bytes"
	"errors"
	"math/big"

	"github.com/1239t/swu-go/pkg/crypto"
)

var ErrInitResponse = errors.New("invalid IKE_SA_INIT response")

func DecodeInitResponse(data, offered []byte) (*IKEPacket, error) {
	request, err := DecodePacket(offered)
	if err != nil {
		return nil, err
	}
	header, err := DecodeHeader(data)
	if err != nil {
		return nil, err
	}
	if header.SPIi != request.Header.SPIi || header.Version>>4 != 2 ||
		header.Flags&(FlagResponse|FlagInitiator) != FlagResponse || header.ExchangeType != IKE_SA_INIT ||
		header.MessageID != 0 || int(header.Length) != len(data) {
		return nil, ErrInitResponse
	}
	payloads, err := decodeInitPayloads(data)
	if err != nil {
		return nil, err
	}
	packet := &IKEPacket{Header: header, Payloads: payloads}
	if len(packet.Payloads) == 1 {
		if notify, ok := packet.Payloads[0].(*EncryptedPayloadNotify); ok {
			if notify.ProtocolID != 0 || len(notify.SPI) != 0 {
				return nil, ErrInitResponse
			}
			switch notify.NotifyType {
			case COOKIE:
				if len(notify.NotifyData) < 1 || len(notify.NotifyData) > 64 {
					return nil, ErrInitResponse
				}
				return packet, nil
			case NO_PROPOSAL_CHOSEN, REDIRECT:
				return packet, nil
			}
		}
	}
	if header.SPIr == 0 {
		return nil, ErrInitResponse
	}
	if err := ValidateInitSelection(packet.Payloads, request.Payloads); err != nil {
		return nil, err
	}
	return packet, nil
}

func ValidateInitSelection(payloads, offered []Payload) error {
	var selected *Proposal
	var ke *EncryptedPayloadKE
	var nonce *EncryptedPayloadNonce
	for _, payload := range payloads {
		switch value := payload.(type) {
		case *EncryptedPayloadSA:
			if selected != nil || len(value.Proposals) != 1 {
				return ErrInitResponse
			}
			selected = value.Proposals[0]
		case *EncryptedPayloadKE:
			if ke != nil {
				return ErrInitResponse
			}
			ke = value
		case *EncryptedPayloadNonce:
			if nonce != nil {
				return ErrInitResponse
			}
			nonce = value
		case *EncryptedPayloadNotify:
			if value.NotifyType == COOKIE || value.NotifyType == REDIRECT || value.NotifyType < 16384 {
				return ErrInitResponse
			}
		}
	}
	if selected == nil || ke == nil || nonce == nil || len(nonce.NonceData) < 16 ||
		len(nonce.NonceData) > 256 || ke.DHGroup != MODP_2048_bit || len(ke.KEData) != 256 ||
		selected.ProtocolID != ProtoIKE || len(selected.SPI) != 0 || len(selected.Transforms) != 4 {
		return ErrInitResponse
	}
	dh, err := crypto.NewDiffieHellman(uint16(ke.DHGroup))
	if err != nil {
		return err
	}
	public := new(big.Int).SetBytes(ke.KEData)
	if public.Cmp(big.NewInt(1)) <= 0 || public.Cmp(new(big.Int).Sub(dh.P, big.NewInt(1))) >= 0 {
		return ErrInitResponse
	}
	var proposal *Proposal
	for _, payload := range offered {
		if sa, ok := payload.(*EncryptedPayloadSA); ok {
			for _, candidate := range sa.Proposals {
				if candidate.ProposalNum == selected.ProposalNum {
					proposal = candidate
				}
			}
		}
	}
	if proposal == nil {
		return ErrInitResponse
	}
	seen := make(map[TransformType]bool, 4)
	for _, transform := range selected.Transforms {
		if seen[transform.Type] {
			return ErrInitResponse
		}
		seen[transform.Type] = true
		switch transform.Type {
		case TransformTypeEncr:
			if transform.ID != ENCR_AES_CBC || len(transform.Attributes) != 1 {
				return ErrInitResponse
			}
			attr := transform.Attributes[0]
			if attr.Type != AttributeKeyLength || len(attr.Value) != 0 || (attr.Val != 128 && attr.Val != 256) {
				return ErrInitResponse
			}
		case TransformTypeInteg, TransformTypePRF:
			if len(transform.Attributes) != 0 {
				return ErrInitResponse
			}
		case TransformTypeDH:
			if transform.ID != AlgorithmType(ke.DHGroup) || len(transform.Attributes) != 0 {
				return ErrInitResponse
			}
		default:
			return ErrInitResponse
		}
		matched := false
		for _, candidate := range proposal.Transforms {
			if candidate.Type != transform.Type || candidate.ID != transform.ID || len(candidate.Attributes) != len(transform.Attributes) {
				continue
			}
			if len(transform.Attributes) == 0 || (candidate.Attributes[0].Type == transform.Attributes[0].Type && candidate.Attributes[0].Val == transform.Attributes[0].Val && bytes.Equal(candidate.Attributes[0].Value, transform.Attributes[0].Value)) {
				matched = true
			}
		}
		if !matched {
			return ErrInitResponse
		}
	}
	return nil
}

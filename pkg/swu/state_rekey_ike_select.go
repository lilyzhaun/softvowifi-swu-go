package swu

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/1239t/swu-go/pkg/ikev2"
)

var errIKERekeyResponse = errors.New("IKE SA Rekey 响应无效")

type ikeRekeySelected struct {
	newSPIr uint64
	nonce   []byte
	ke      []byte
}

func (s *Session) selectIKERekeyResponse(payloads []ikev2.Payload) (ikeRekeySelected, error) {
	var sa *ikev2.EncryptedPayloadSA
	var nonce *ikev2.EncryptedPayloadNonce
	var ke *ikev2.EncryptedPayloadKE
	for _, p := range payloads {
		switch pl := p.(type) {
		case *ikev2.EncryptedPayloadSA:
			if sa != nil {
				return ikeRekeySelected{}, fmt.Errorf("IKE SA Rekey 响应 SA 重复: %w", errIKERekeyResponse)
			}
			sa = pl
		case *ikev2.EncryptedPayloadNonce:
			if nonce != nil {
				return ikeRekeySelected{}, fmt.Errorf("IKE SA Rekey 响应 Nonce 重复: %w", errIKERekeyResponse)
			}
			nonce = pl
		case *ikev2.EncryptedPayloadKE:
			if ke != nil {
				return ikeRekeySelected{}, fmt.Errorf("IKE SA Rekey 响应 KE 重复: %w", errIKERekeyResponse)
			}
			ke = pl
		}
	}
	if sa == nil || nonce == nil || ke == nil {
		return ikeRekeySelected{}, fmt.Errorf("IKE SA Rekey 响应缺少 SA/KE/Nonce: %w", errIKERekeyResponse)
	}
	if len(sa.Proposals) != 1 {
		return ikeRekeySelected{}, fmt.Errorf("IKE SA Rekey 响应提案数 %d: %w", len(sa.Proposals), errIKERekeyResponse)
	}
	prop := sa.Proposals[0]
	if prop.ProtocolID != ikev2.ProtoIKE || len(prop.SPI) != 8 {
		return ikeRekeySelected{}, fmt.Errorf("IKE SA Rekey 响应 SPI 无效: %w", errIKERekeyResponse)
	}
	newSPIr := binary.BigEndian.Uint64(prop.SPI)
	if newSPIr == 0 {
		return ikeRekeySelected{}, fmt.Errorf("IKE SA Rekey 响应 SPI 无效: %w", errIKERekeyResponse)
	}
	if err := s.matchIKERekeyTransforms(prop); err != nil {
		return ikeRekeySelected{}, err
	}
	if ke.DHGroup != ikev2.AlgorithmType(s.ikeDHID) || len(ke.KEData) == 0 {
		return ikeRekeySelected{}, fmt.Errorf("IKE SA Rekey 响应 KE 组不一致: %w", errIKERekeyResponse)
	}
	if len(nonce.NonceData) < 16 {
		return ikeRekeySelected{}, fmt.Errorf("IKE SA Rekey 响应 Nonce 过短: %w", errIKERekeyResponse)
	}
	return ikeRekeySelected{newSPIr: newSPIr, nonce: nonce.NonceData, ke: ke.KEData}, nil
}

func (s *Session) matchIKERekeyTransforms(prop *ikev2.Proposal) error {
	seen := make(map[ikev2.TransformType]struct{})
	var encr, integ, prf, dh ikev2.AlgorithmType
	var keyLen int
	var hasEncr, hasInteg, hasPRF, hasDH bool
	for _, xf := range prop.Transforms {
		if _, ok := seen[xf.Type]; ok {
			return fmt.Errorf("IKE SA Rekey 响应变换重复: %w", errIKERekeyResponse)
		}
		seen[xf.Type] = struct{}{}
		switch xf.Type {
		case ikev2.TransformTypeEncr:
			encr = xf.ID
			hasEncr = true
			keyAttrs := 0
			for _, attr := range xf.Attributes {
				if attr.Type == ikev2.AttributeKeyLength {
					keyAttrs++
					keyLen = int(attr.Val)
				}
			}
			if keyAttrs > 1 {
				return fmt.Errorf("IKE SA Rekey 响应密钥长度重复: %w", errIKERekeyResponse)
			}
		case ikev2.TransformTypeInteg:
			integ = xf.ID
			hasInteg = true
		case ikev2.TransformTypePRF:
			prf = xf.ID
			hasPRF = true
		case ikev2.TransformTypeDH:
			dh = xf.ID
			hasDH = true
		default:
			return fmt.Errorf("IKE SA Rekey 响应含未知变换: %w", errIKERekeyResponse)
		}
	}
	if !hasEncr || !hasPRF || !hasDH {
		return fmt.Errorf("IKE SA Rekey 响应缺少必要变换: %w", errIKERekeyResponse)
	}
	if uint16(encr) != s.ikeEncrID || keyLen != s.ikeEncrKeyLenBits || uint16(prf) != s.ikePRFID || uint16(dh) != s.ikeDHID {
		return fmt.Errorf("IKE SA Rekey 响应与当前提案不一致: %w", errIKERekeyResponse)
	}
	if s.ikeIsAEAD {
		if hasInteg {
			return fmt.Errorf("IKE SA Rekey 响应 AEAD 含完整性变换: %w", errIKERekeyResponse)
		}
		return nil
	}
	if !hasInteg || uint16(integ) != s.ikeIntegID {
		return fmt.Errorf("IKE SA Rekey 响应与当前提案不一致: %w", errIKERekeyResponse)
	}
	return nil
}

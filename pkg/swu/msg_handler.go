package swu

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/1239t/swu-go/pkg/crypto"
	"github.com/1239t/swu-go/pkg/ikev2"
	"github.com/1239t/swu-go/pkg/logger"
)

// The dispatcher hands this owned, fully authenticated message to consumers.
// A nil message means that a valid fragment is still awaiting its siblings.
type protectedIKEMessage struct {
	msgID    uint32
	payloads []ikev2.Payload
	fragment *fragmentKey
}

var errFragmentIncomplete = errors.New("incomplete protected IKE message")

func (s *Session) decryptAndParse(data []byte) (uint32, []ikev2.Payload, error) {
	message, err := s.decodeProtectedIKE(data)
	if err != nil {
		return 0, nil, err
	}
	if message == nil {
		return binary.BigEndian.Uint32(data[20:24]), nil, nil
	}
	return message.msgID, message.payloads, nil
}

func (s *Session) decodeProtectedIKE(data []byte) (*protectedIKEMessage, error) {
	header, err := s.protectedHeader(data)
	if err != nil {
		return nil, err
	}

	// RFC 7383: 处理 Encrypted Fragment (SKF) 载荷
	if header.NextPayload == ikev2.EncryptedFragment {
		plaintext, fragNum, totalFrags, msgID, err := s.decryptSKF(data)
		if err != nil {
			return nil, fmt.Errorf("SKF 解密失败: %w", err)
		}
		s.Logger.Debug("收到 IKE 分片",
			logger.Int("frag", int(fragNum)),
			logger.Int("total", int(totalFrags)),
			logger.Uint32("msgID", msgID))

		first := ikev2.PayloadType(data[ikev2.IKE_HEADER_LEN])
		if (fragNum > 1 && first != 0) || (fragNum == 1 && first == 0 && (totalFrags != 1 || len(plaintext) != 0)) {
			return nil, ErrInvalidProtectedIKE
		}
		key := s.fragmentKey(header)
		if err := s.fragmentBuf.replay(key, fragNum, time.Now()); err != nil {
			return nil, err
		}
		reassembled, first, err := s.fragmentBuf.addFragment(key, first, fragNum, totalFrags, plaintext, time.Now())
		if err != nil {
			return nil, err
		}
		if reassembled == nil {
			return nil, nil
		}
		payloads, err := s.parsePayloads(reassembled, first)
		if err != nil {
			return nil, err
		}
		return &protectedIKEMessage{msgID: msgID, payloads: payloads, fragment: &key}, nil
	}

	// 处理 SK 载荷
	offset := ikev2.IKE_HEADER_LEN
	genHeader, err := ikev2.DecodePayloadHeader(data[offset : offset+4])
	if err != nil {
		return nil, err
	}

	skBodyLen := int(genHeader.PayloadLength) - 4
	if skBodyLen < 0 || offset+4+skBodyLen != len(data) {
		return nil, errors.New("SK 载荷太短")
	}

	skContent := data[offset+4 : offset+4+skBodyLen]
	ivSize := s.EncAlg.IVSize()

	if len(skContent) < ivSize {
		return nil, errors.New("SK 内容对于 IV 来说太短")
	}
	iv := skContent[:ivSize]
	// RFC5282: AEAD authenticates the generic SK header as well as IKE.
	aad := data[:ikev2.IKE_HEADER_LEN+4]
	key := s.Keys.SK_er
	integrityKey := s.Keys.SK_ar
	if s.localResponder {
		key, integrityKey = s.Keys.SK_ei, s.Keys.SK_ai
	}

	ciphertext := skContent[ivSize:]
	if !s.ikeIsAEAD && s.IntegAlg != nil {
		icvSize := s.IntegAlg.OutputSize()
		if len(ciphertext) < icvSize {
			return nil, errors.New("SK 内容对于 ICV 来说太短")
		}
		receivedICV := ciphertext[len(ciphertext)-icvSize:]
		ciphertext = ciphertext[:len(ciphertext)-icvSize]

		dataToVerify := data[:ikev2.IKE_HEADER_LEN+4+ivSize+len(ciphertext)]
		if !s.IntegAlg.Verify(integrityKey, dataToVerify, receivedICV) {
			return nil, errors.New("IKE 完整性校验失败")
		}
	}

	plaintext, err := s.EncAlg.Decrypt(ciphertext, key, iv, aad)
	if err != nil {
		return nil, fmt.Errorf("解密失败(encr=%s aead=%v iv=%d ct=%d): %v",
			ikev2.EncrToString(s.ikeEncrID), s.ikeIsAEAD, ivSize, len(ciphertext), err)
	}

	if len(plaintext) < 1 {
		return nil, errors.New("SK 明文太短")
	}
	padLen := int(plaintext[len(plaintext)-1])
	if len(plaintext) < 1+padLen {
		return nil, errors.New("SK 填充长度无效")
	}
	plaintext = plaintext[:len(plaintext)-1-padLen]

	payloads, err := s.parsePayloads(plaintext, genHeader.NextPayload)
	if err != nil {
		return nil, err
	}
	return &protectedIKEMessage{msgID: header.MessageID, payloads: payloads}, nil
}

func (s *Session) parsePayloads(data []byte, firstType ikev2.PayloadType) ([]ikev2.Payload, error) {
	var payloads []ikev2.Payload
	offset := 0
	nextType := firstType

	for nextType != ikev2.NoNextPayload {
		if offset+4 > len(data) {
			return nil, errors.New("incomplete IKE payload chain")
		}
		genHeader, err := ikev2.DecodePayloadHeader(data[offset : offset+4])
		if err != nil {
			return nil, err
		}

		length := int(genHeader.PayloadLength)
		if length < 4 || offset+length > len(data) {
			return nil, errors.New("载荷太短")
		}

		body := data[offset+4 : offset+length]
		var p ikev2.Payload

		switch nextType {
		case ikev2.SA:
			p, err = ikev2.DecodePayloadSA(body)
		case ikev2.KE:
			p, err = ikev2.DecodePayloadKE(body)
		case ikev2.IDi, ikev2.IDr:
			p, err = ikev2.DecodePayloadID(body, nextType == ikev2.IDi)
		case ikev2.AUTH:
			p, err = ikev2.DecodePayloadAuth(body)
		case ikev2.EAP:
			p, err = ikev2.DecodePayloadEAP(body)
		case ikev2.CP:
			p, err = ikev2.DecodePayloadCP(body)
		case ikev2.D:
			p, err = ikev2.DecodePayloadDelete(body)
		case ikev2.TSI:
			p, err = ikev2.DecodePayloadTS(body, true)
		case ikev2.TSR:
			p, err = ikev2.DecodePayloadTS(body, false)
		case ikev2.N:
			p, err = ikev2.DecodePayloadNotify(body)
		case ikev2.NiNr:
			p, err = ikev2.DecodePayloadNonce(body)
		default:
			if genHeader.Critical {
				return nil, errors.New("unsupported critical IKE payload")
			}
			p = &ikev2.RawPayload{PType: nextType, Data: body}
		}

		if err != nil {
			return nil, err
		}
		if p != nil {
			payloads = append(payloads, p)
		}

		nextType = genHeader.NextPayload
		offset += length
	}
	if offset != len(data) {
		return nil, errors.New("trailing IKE payload bytes")
	}
	return payloads, nil
}

func (s *Session) encryptAndWrap(payloads []ikev2.Payload, exchangeType ikev2.ExchangeType, isResponse bool) ([]byte, error) {
	msgID := uint32(s.NextSequenceNumber())
	return s.encryptAndWrapWithMsgID(payloads, exchangeType, msgID, isResponse)
}

func (s *Session) encryptAndWrapWithMsgID(payloads []ikev2.Payload, exchangeType ikev2.ExchangeType, msgID uint32, isResponse bool) ([]byte, error) {
	innerData := []byte{}

	for i, pl := range payloads {
		nextType := ikev2.NoNextPayload
		if i < len(payloads)-1 {
			nextType = payloads[i+1].Type()
		}

		body, err := pl.Encode()
		if err != nil {
			return nil, err
		}

		header := &ikev2.PayloadHeader{
			NextPayload:   nextType,
			PayloadLength: uint16(4 + len(body)),
		}
		innerData = append(innerData, header.Encode()...)
		innerData = append(innerData, body...)
	}

	key := s.Keys.SK_ei
	integrityKey := s.Keys.SK_ai
	if s.localResponder {
		key, integrityKey = s.Keys.SK_er, s.Keys.SK_ar
	}
	iv, err := crypto.RandomBytes(s.EncAlg.IVSize())
	if err != nil {
		return nil, err
	}

	icvSize := 0
	if !s.ikeIsAEAD && s.IntegAlg != nil {
		icvSize = s.IntegAlg.OutputSize()
	}

	plainToEncrypt := innerData
	padLen := 0
	if !s.ikeIsAEAD {
		blockSize := s.EncAlg.BlockSize()
		if blockSize <= 0 {
			return nil, errors.New("无效的块大小")
		}
		if rem := (len(plainToEncrypt) + 1) % blockSize; rem != 0 {
			padLen = blockSize - rem
		}
	}
	// Pad Length is mandatory even when AEAD requires no block padding.
	plainToEncrypt = append(plainToEncrypt, make([]byte, padLen)...)
	plainToEncrypt = append(plainToEncrypt, byte(padLen))
	expectedCipherLen := len(plainToEncrypt)
	if s.ikeIsAEAD {
		expectedCipherLen += 16
	}

	nextPayload := ikev2.NoNextPayload
	if len(payloads) > 0 {
		nextPayload = payloads[0].Type()
	}

	hdr := &ikev2.IKEHeader{
		SPIi:         s.SPIi,
		SPIr:         s.SPIr,
		NextPayload:  ikev2.SK,
		Version:      0x20,
		ExchangeType: exchangeType,
		Flags:        ikev2.FlagInitiator,
		MessageID:    msgID,
		Length:       uint32(ikev2.IKE_HEADER_LEN + 4 + len(iv) + expectedCipherLen + icvSize),
	}
	if isResponse {
		hdr.Flags |= ikev2.FlagResponse
	}
	if s.localResponder {
		hdr.Flags &^= ikev2.FlagInitiator
	}

	skHeader := &ikev2.PayloadHeader{
		NextPayload:   nextPayload,
		PayloadLength: uint16(4 + len(iv) + expectedCipherLen + icvSize),
	}
	aad := append(hdr.Encode(), skHeader.Encode()...)
	ciphertext, err := s.EncAlg.Encrypt(plainToEncrypt, key, iv, aad)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) != expectedCipherLen {
		return nil, errors.New("加密输出长度不匹配")
	}

	packet := append(aad, iv...)
	packet = append(packet, ciphertext...)
	if !s.ikeIsAEAD && s.IntegAlg != nil {
		icv := s.IntegAlg.Compute(integrityKey, packet)
		packet = append(packet, icv...)
	}
	if uint32(len(packet)) != hdr.Length {
		return nil, errors.New("IKE 长度字段不匹配")
	}
	return packet, nil
}

func (s *Session) NextSequenceNumber() uint32 {
	return s.SequenceNumber.Add(1) - 1
}

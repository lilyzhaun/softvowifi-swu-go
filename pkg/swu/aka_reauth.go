package swu

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/1239t/swu-go/pkg/crypto"
	"github.com/1239t/swu-go/pkg/eap"
	"github.com/1239t/swu-go/pkg/ikev2"
)

var errAKAReauthentication = errors.New("invalid EAP-AKA reauthentication")

type akaReauthExchange struct {
	request, response []byte
	fallback          bool
}

// The MAC must be verified before decrypting. Reserved fields are ignored on
// receipt; AT_PADDING, unlike a reserved field, must be all zero and last.
func decryptAKAAttributes(attrs map[byte][]byte, key []byte) (map[byte][]byte, error) {
	iv, data := attrs[eap.AT_IV], attrs[eap.AT_ENCR_DATA]
	if len(key) != 16 || len(iv) != 18 || len(data) < 18 || (len(data)-2)%16 != 0 {
		return nil, errAKAReauthentication
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errAKAReauthentication
	}
	plain := make([]byte, len(data)-2)
	cipher.NewCBCDecrypter(block, iv[2:]).CryptBlocks(plain, data[2:])
	inner, offsets, err := notificationAttributes(plain)
	if err != nil {
		return nil, errAKAReauthentication
	}
	if padding, ok := inner[eap.AT_PADDING]; ok {
		if len(padding) > 10 || !eapReauthAllZero(padding) || offsets[eap.AT_PADDING]+2+len(padding) != len(plain) {
			return nil, errAKAReauthentication
		}
	}
	return inner, nil
}

func encryptAKAAttributes(plain, key []byte) ([]byte, error) {
	if len(key) != 16 || len(plain) == 0 || len(plain)%4 != 0 || len(plain) > 1008 {
		return nil, errAKAReauthentication
	}
	plain = bytes.Clone(plain)
	if padding := (16 - len(plain)%16) % 16; padding != 0 {
		plain = append(plain, eap.AT_PADDING, byte(padding/4))
		plain = append(plain, make([]byte, padding-2)...)
	}
	iv, err := crypto.RandomBytes(16)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errAKAReauthentication
	}
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(plain, plain)
	result := append([]byte{eap.AT_IV, 5, 0, 0}, iv...)
	result = append(result, eap.AT_ENCR_DATA, byte((len(plain)+4)/4), 0, 0)
	return append(result, plain...), nil
}

func akaNextIdentity(attrs map[byte][]byte, kind byte) (string, error) {
	value, present := attrs[kind]
	if !present {
		return "", nil
	}
	if len(value) < 2 {
		return "", errAKAReauthentication
	}
	n := int(binary.BigEndian.Uint16(value))
	// Identity padding is not part of the opaque identity and is ignored.
	if n == 0 || n > len(value)-2 || len(value)-2-n > 3 {
		return "", errAKAReauthentication
	}
	identity := string(value[2 : 2+n])
	if !utf8.ValidString(identity) || strings.ContainsRune(identity, 0) || (kind == eap.AT_NEXT_PSEUDONYM && strings.ContainsRune(identity, '@')) {
		return "", errAKAReauthentication
	}
	return identity, nil
}

func (s *Session) fullAuthTemporaryIdentity(attrs map[byte][]byte, mk, kAut, kEncr []byte) (*AKATemporaryIdentity, error) {
	pending := &AKATemporaryIdentity{Pseudonym: s.akaPseudonym}
	_, hasIV := attrs[eap.AT_IV]
	_, hasData := attrs[eap.AT_ENCR_DATA]
	if !hasIV && !hasData {
		return pending, nil
	}
	inner, err := decryptAKAAttributes(attrs, kEncr)
	if err != nil {
		return nil, err
	}
	for kind := range inner {
		switch kind {
		case eap.AT_NEXT_REAUTH_ID, eap.AT_NEXT_PSEUDONYM, eap.AT_PADDING:
		case eap.AT_IV, eap.AT_ENCR_DATA, eap.AT_RESULT_IND, eap.AT_CHECKCODE:
			return nil, errAKAReauthentication
		default:
			if kind < 128 {
				return nil, errAKAReauthentication
			}
		}
	}
	identity, err := akaNextIdentity(inner, eap.AT_NEXT_REAUTH_ID)
	if err != nil {
		return nil, err
	}
	if identity != "" && s.akaUsedFastID != "" && sameAKAUsername(identity, s.akaUsedFastID) {
		return nil, errAKAReauthentication
	}
	pseudonym, err := akaNextIdentity(inner, eap.AT_NEXT_PSEUDONYM)
	if err != nil {
		return nil, err
	}
	if pseudonym != "" {
		pending.Pseudonym = pseudonym
	}
	if identity != "" {
		pending.ReauthID, pending.MK = identity, bytes.Clone(mk)
		pending.KAut, pending.KEncr = bytes.Clone(kAut), bytes.Clone(kEncr)
	}
	return pending, nil
}

func (s *Session) handleAKAReauthentication(pkt *eap.EAPPacket, raw []byte) ([]ikev2.Payload, error) {
	if len(raw) < 8 || int(binary.BigEndian.Uint16(raw[2:4])) != len(raw) {
		return nil, errAKAReauthentication
	}
	if old := &s.akaReauth; old.request != nil {
		if !bytes.Equal(old.request, raw) {
			return nil, errAKAReauthentication
		}
		return notificationPayload(old.response), nil
	}
	ctx := s.fastReauthCtx
	if s.eapNotification.authenticated || ctx == nil || !ctx.CanUseReauth() ||
		len(ctx.MK) != 20 || len(ctx.KEncr) != 16 || len(ctx.KAut) != 16 {
		return nil, errAKAReauthentication
	}
	identity := s.akaIdentity.selected
	if len(identity) == 0 {
		identity = s.akaIdentity.outer
	}
	if len(identity) == 0 || !bytes.Equal(identity, []byte(ctx.ReauthID)) {
		return nil, errAKAReauthentication
	}
	attrs, _, err := notificationAttributes(pkt.Data)
	if err != nil {
		return nil, errAKAReauthentication
	}
	for kind, value := range attrs {
		switch kind {
		case eap.AT_MAC, eap.AT_IV:
			if len(value) != 18 {
				return nil, errAKAReauthentication
			}
		case eap.AT_ENCR_DATA, eap.AT_CHECKCODE:
		case eap.AT_RESULT_IND:
			if len(value) != 2 {
				return nil, errAKAReauthentication
			}
		case eap.AT_NEXT_REAUTH_ID, eap.AT_NEXT_PSEUDONYM:
			return nil, errAKAReauthentication
		default:
			if kind < 128 {
				return nil, errAKAReauthentication
			}
		}
	}
	mac := attrs[eap.AT_MAC]
	if len(mac) != 18 || eapReauthAllZero(mac[2:]) || verifyEAPAKAMAC(raw, pkt.Data, ctx.KAut, mac[2:]) != nil {
		return nil, errAKAReauthentication
	}
	inner, err := decryptAKAAttributes(attrs, ctx.KEncr)
	if err != nil {
		return nil, err
	}
	for kind := range inner {
		switch kind {
		case eap.AT_COUNTER, eap.AT_NONCE_S, eap.AT_NEXT_REAUTH_ID, eap.AT_PADDING:
		case eap.AT_IV, eap.AT_ENCR_DATA, eap.AT_NEXT_PSEUDONYM, eap.AT_RESULT_IND, eap.AT_CHECKCODE:
			return nil, errAKAReauthentication
		default:
			if kind < 128 {
				return nil, errAKAReauthentication
			}
		}
	}
	if len(inner[eap.AT_COUNTER]) != 2 || len(inner[eap.AT_NONCE_S]) != 18 {
		return nil, errAKAReauthentication
	}
	counter := binary.BigEndian.Uint16(inner[eap.AT_COUNTER])
	nonce := inner[eap.AT_NONCE_S][2:]
	// Counter is the last accepted value, not the next expected value.
	small := counter <= ctx.Counter
	var next string
	if !small {
		// RFC 4187 §5.5 requires ignoring the contents of the next identity
		// when the counter is too small. Container/TLV checks still apply.
		next, err = akaNextIdentity(inner, eap.AT_NEXT_REAUTH_ID)
		if err != nil || (next != "" && sameAKAUsername(next, ctx.ReauthID)) {
			return nil, errAKAReauthentication
		}
	}
	plain := []byte{eap.AT_COUNTER, 1, byte(counter >> 8), byte(counter)}
	if small {
		plain = append(plain, eap.AT_COUNTER_TOO_SMALL, 1, 0, 0)
	}
	response, err := encryptAKAAttributes(plain, ctx.KEncr)
	if err != nil {
		return nil, err
	}
	_, resultInd := attrs[eap.AT_RESULT_IND]
	if resultInd && !small {
		response = append(response, eap.AT_RESULT_IND, 1, 0, 0)
	}
	response = append(response, eap.AT_MAC, 5, 0, 0)
	response = append(response, make([]byte, 16)...)
	response = (&eap.EAPPacket{Code: eap.CodeResponse, Identifier: pkt.Identifier,
		Type: eap.TypeAKA, Subtype: eap.SubtypeReauthentication, Data: response}).Encode()
	if err := fillEAPAKAReauthResponseMAC(response, ctx.KAut, nonce); err != nil {
		return nil, err
	}
	if small {
		// Keep the current exchange and identity for the server's full Challenge.
		// Do not derive a fast MSK or accept Success for a rejected counter.
		s.fastReauthCtx = eap.NewFastReauthContext()
		s.akaPending = nil
	} else {
		h := sha1.New()
		h.Write(identity)
		h.Write(inner[eap.AT_COUNTER])
		h.Write(nonce)
		h.Write(ctx.MK)
		material := crypto.NewFIPS1862PRFSHA1(h.Sum(nil)).Bytes(nil, 128)
		s.MSK = bytes.Clone(material[:64])
		s.completedEAPMethod(eap.TypeAKA, ctx.KAut, resultInd, true, counter, ctx.KEncr)
		// MAC verification is unconditional for reauthentication, including when
		// full-Challenge diagnostic validation has been disabled by the caller.
		s.eapNotification.authenticated = true
		s.akaPending = &AKATemporaryIdentity{Pseudonym: s.akaPseudonym}
		if next != "" && counter != 65535 {
			s.akaPending.ReauthID, s.akaPending.Counter = next, counter
			s.akaPending.MK, s.akaPending.KAut, s.akaPending.KEncr = bytes.Clone(ctx.MK), bytes.Clone(ctx.KAut), bytes.Clone(ctx.KEncr)
		}
		// The old identity is unusable for another authentication. The pending
		// replacement is published only after the final IKE authentication.
		s.fastReauthCtx = eap.NewFastReauthContext()
	}
	s.akaReauth = akaReauthExchange{bytes.Clone(raw), bytes.Clone(response), small}
	return notificationPayload(response), nil
}

func sameAKAUsername(first, second string) bool {
	a, _, _ := strings.Cut(first, "@")
	b, _, _ := strings.Cut(second, "@")
	return a == b
}

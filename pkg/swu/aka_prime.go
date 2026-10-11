package swu

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"slices"
	"unicode/utf8"

	"github.com/1239t/swu-go/pkg/crypto"
	"github.com/1239t/swu-go/pkg/eap"
	"github.com/1239t/swu-go/pkg/ikev2"
	"github.com/1239t/swu-go/pkg/sim"
)

type akaPrimeState struct {
	kdfs              []uint16
	negotiating       bool
	started           bool
	request, response []byte
}

var errAKAPrimeChallenge = errors.New("invalid EAP-AKA' Challenge")

func parsePrimeChallenge(raw []byte) (map[byte][]byte, []uint16, int, string, error) {
	if len(raw) < 8 || int(binary.BigEndian.Uint16(raw[2:4])) != len(raw) {
		return nil, nil, 0, "", errAKAPrimeChallenge
	}
	attrs := make(map[byte][]byte)
	var kdfs []uint16
	macPosition := 0
	for offset := 8; offset < len(raw); {
		if len(raw)-offset < 4 {
			return nil, nil, 0, "", errAKAPrimeChallenge
		}
		kind, length := raw[offset], int(raw[offset+1])*4
		if length < 4 || length > len(raw)-offset {
			return nil, nil, 0, "", errAKAPrimeChallenge
		}
		value := raw[offset+2 : offset+length]
		if kind == eap.AT_KDF {
			if length != 4 {
				return nil, nil, 0, "", errAKAPrimeChallenge
			}
			kdfs = append(kdfs, binary.BigEndian.Uint16(value))
		} else {
			if _, exists := attrs[kind]; exists {
				return nil, nil, 0, "", errAKAPrimeChallenge
			}
			if kind < 128 && kind != eap.AT_RAND && kind != eap.AT_AUTN && kind != eap.AT_MAC && kind != eap.AT_KDF_INPUT {
				return nil, nil, 0, "", errAKAPrimeChallenge
			}
			attrs[kind] = value
			if kind == eap.AT_MAC {
				macPosition = offset + 4
			}
		}
		offset += length
	}
	if len(kdfs) == 0 || len(attrs[eap.AT_RAND]) != 18 || len(attrs[eap.AT_AUTN]) != 18 || len(attrs[eap.AT_MAC]) != 18 || attrs[eap.AT_AUTN][8]&0x80 == 0 {
		return nil, nil, 0, "", errAKAPrimeChallenge
	}
	if value, ok := attrs[eap.AT_RESULT_IND]; ok && len(value) != 2 {
		return nil, nil, 0, "", errAKAPrimeChallenge
	}
	if value, ok := attrs[eap.AT_CHECKCODE]; ok && len(value) != 2 {
		return nil, nil, 0, "", errAKAPrimeChallenge
	}
	name := attrs[eap.AT_KDF_INPUT]
	if len(name) < 3 {
		return nil, nil, 0, "", errAKAPrimeChallenge
	}
	n := int(binary.BigEndian.Uint16(name))
	if n == 0 || n > len(name)-2 || len(name)-2-n > 3 || !utf8.Valid(name[2:2+n]) {
		return nil, nil, 0, "", errAKAPrimeChallenge
	}
	return attrs, kdfs, macPosition, string(name[2 : 2+n]), nil
}

func deriveAKAPrime(ck, ik, autn, identity []byte, network string) ([]byte, error) {
	input := append([]byte{0x20}, []byte(network)...)
	input = binary.BigEndian.AppendUint16(input, uint16(len(network)))
	input = append(input, autn[:6]...)
	input = append(input, 0, 6)
	m := hmac.New(sha256.New, append(bytes.Clone(ck), ik...))
	m.Write(input)
	prime := m.Sum(nil)
	key := append(bytes.Clone(prime[16:]), prime[:16]...)
	seed := append([]byte("EAP-AKA'"), identity...)
	return crypto.PrfPlus(crypto.PRF_HMAC_SHA2_256, key, seed, 208)
}

func primeEAPPayload(id, subtype byte, attrs []byte) []ikev2.Payload {
	return []ikev2.Payload{&ikev2.EncryptedPayloadEAP{EAPMessage: (&eap.EAPPacket{Code: eap.CodeResponse, Identifier: id, Type: eap.TypeAKAPrime, Subtype: subtype, Data: attrs}).Encode()}}
}

func (s *Session) handleAKAPrimeChallenge(pkt *eap.EAPPacket, raw []byte) ([]ikev2.Payload, error) {
	attrs, kdfs, macPos, network, err := parsePrimeChallenge(raw)
	if err != nil {
		return nil, err
	}
	state := &s.akaPrime
	state.started = true
	if bytes.Equal(raw, state.request) {
		return notificationPayload(state.response), nil
	}
	if state.negotiating {
		if kdfs[0] != 1 || !slices.Equal(kdfs[1:], state.kdfs) {
			return nil, errAKAPrimeChallenge
		}
	} else {
		if state.kdfs != nil {
			if !slices.Equal(kdfs, state.kdfs) {
				return nil, errAKAPrimeChallenge
			}
		} else {
			seen := make(map[uint16]bool)
			for _, kdf := range kdfs {
				if seen[kdf] {
					return nil, errAKAPrimeChallenge
				}
				seen[kdf] = true
			}
		}
		if kdfs[0] != 1 {
			if !slices.Contains(kdfs, 1) {
				return nil, errAKAPrimeChallenge
			}
			state.kdfs, state.negotiating = slices.Clone(kdfs), true
			response := primeEAPPayload(pkt.Identifier, eap.SubtypeChallenge, []byte{eap.AT_KDF, 1, 0, 1})
			state.request, state.response = bytes.Clone(raw), bytes.Clone(response[0].(*ikev2.EncryptedPayloadEAP).EAPMessage)
			return response, nil
		}
	}
	// Use the actual identity previously sent, never reconstruct a different
	// permanent NAI or ignore a SIM identity-read error during key derivation.
	identity := s.akaIdentity.outer
	if len(identity) == 0 {
		return nil, errAKAPrimeChallenge
	}
	rand, autn := attrs[eap.AT_RAND][2:], attrs[eap.AT_AUTN][2:]
	res, ck, ik, auts, err := s.calculateAKAWithDiagnostics(rand, autn)
	if err != nil {
		if errors.Is(err, sim.ErrSyncFailure) {
			if len(auts) != 14 {
				return nil, errAKAPrimeChallenge
			}
			data := append([]byte{eap.AT_AUTS, 4}, auts...)
			for _, kdf := range kdfs {
				data = append(data, eap.AT_KDF, 1, byte(kdf>>8), byte(kdf))
			}
			state.kdfs, state.negotiating = slices.Clone(kdfs), false
			response := primeEAPPayload(pkt.Identifier, eap.SubtypeSyncFailure, data)
			state.request, state.response = bytes.Clone(raw), bytes.Clone(response[0].(*ikev2.EncryptedPayloadEAP).EAPMessage)
			return response, nil
		}
		return nil, errors.New("SIM AKA failed during EAP-AKA'")
	}
	if err := validateAKAResult(res, ck, ik); err != nil {
		return nil, err
	}
	material, err := deriveAKAPrime(ck, ik, autn, identity, network)
	if err != nil {
		return nil, err
	}
	kAut := material[16:48]
	copyRaw := bytes.Clone(raw)
	clear(copyRaw[macPos : macPos+16])
	m := hmac.New(sha256.New, kAut)
	m.Write(copyRaw)
	if !hmac.Equal(m.Sum(nil)[:16], raw[macPos:macPos+16]) {
		return nil, errors.New("EAP-AKA' MAC verification failed")
	}
	data := binary.BigEndian.AppendUint16(nil, uint16(len(res)*8))
	data = append(data, res...)
	data = (&eap.Attribute{Type: eap.AT_RES, Value: data}).Encode()
	_, resultInd := attrs[eap.AT_RESULT_IND]
	if resultInd {
		data = append(data, eap.AT_RESULT_IND, 1, 0, 0)
	}
	data = append(data, eap.AT_MAC, 5, 0, 0)
	data = append(data, make([]byte, 16)...)
	response := primeEAPPayload(pkt.Identifier, eap.SubtypeChallenge, data)
	encoded := response[0].(*ikev2.EncryptedPayloadEAP).EAPMessage
	m = hmac.New(sha256.New, kAut)
	m.Write(encoded)
	copy(encoded[len(encoded)-16:], m.Sum(nil)[:16])
	// Type50 has a distinct K_re/KDF. Do not cache it as a Type23 fast context.
	s.MSK = bytes.Clone(material[80:144])
	s.completedEAPMethod(eap.TypeAKAPrime, kAut, resultInd, false, 0, material[:16])
	state.kdfs, state.negotiating = slices.Clone(kdfs), false
	state.request, state.response = bytes.Clone(raw), bytes.Clone(encoded)
	return response, nil
}

package swu

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/1239t/swu-go/pkg/eap"
	"github.com/1239t/swu-go/pkg/ikev2"
)

type akaIdentityExchange struct {
	request, response []byte
}

type akaIdentityState struct {
	outer, selected []byte
	exchanges       []akaIdentityExchange
	lastRequest     uint8
	extended        bool
	closed, failed  bool
}

func (s *Session) resetAKAIdentity() {
	s.akaIdentity = akaIdentityState{}
	s.eapKAut = nil
	s.eapNotification = eapNotificationState{}
	s.akaPrime = akaPrimeState{}
}

func (s *Session) akaIdentityClientError(id uint8) ([]ikev2.Payload, error) {
	s.akaIdentity.failed = true
	packet := &eap.EAPPacket{Code: eap.CodeResponse, Identifier: id, Type: eap.TypeAKA, Subtype: 14,
		Data: []byte{eap.AT_CLIENT_ERROR_CODE, 1, 0, 0}}
	return []ikev2.Payload{&ikev2.EncryptedPayloadEAP{EAPMessage: packet.Encode()}}, nil
}

func parseAKAIdentityRequest(data []byte) (uint8, bool, error) {
	var request uint8
	extended := false
	seen := make(map[byte]bool)
	for offset := 0; offset < len(data); {
		if len(data)-offset < 4 {
			return 0, false, errors.New("truncated AKA identity attribute")
		}
		attrType, length := data[offset], int(data[offset+1])*4
		if length < 4 || length > len(data)-offset || seen[attrType] {
			return 0, false, errors.New("invalid or duplicate AKA identity attribute")
		}
		seen[attrType] = true
		switch attrType {
		case eap.AT_ANY_ID_REQ, eap.AT_FULLAUTH_ID_REQ, eap.AT_PERMANENT_ID_REQ:
			if request != 0 || length != 4 {
				return 0, false, errors.New("conflicting AKA identity requests")
			}
			request = attrType
		case eap.AT_IV, eap.AT_ENCR_DATA:
			return 0, false, errors.New("protected attributes in AKA identity request")
		default:
			if attrType < 128 {
				return 0, false, errors.New("unexpected AKA identity attribute")
			}
			extended = true
		}
		offset += length
	}
	if request == 0 {
		return 0, false, errors.New("missing AKA identity request")
	}
	return request, extended, nil
}

func (s *Session) handleAKAIdentity(pkt *eap.EAPPacket, raw []byte) ([]ikev2.Payload, error) {
	state := &s.akaIdentity
	if len(raw) < 8 || state.closed {
		return s.akaIdentityClientError(pkt.Identifier)
	}
	raw = raw[:binary.BigEndian.Uint16(raw[2:4])]
	for _, exchange := range state.exchanges {
		if exchange.request[1] == pkt.Identifier {
			if !bytes.Equal(raw, exchange.request) {
				return s.akaIdentityClientError(pkt.Identifier)
			}
			return []ikev2.Payload{&ikev2.EncryptedPayloadEAP{EAPMessage: bytes.Clone(exchange.response)}}, nil
		}
	}
	request, extended, err := parseAKAIdentityRequest(pkt.Data)
	if err != nil || len(state.exchanges) >= 3 || state.lastRequest == eap.AT_PERMANENT_ID_REQ ||
		(request == eap.AT_ANY_ID_REQ && len(state.exchanges) > 0) ||
		(request == eap.AT_FULLAUTH_ID_REQ && state.lastRequest == eap.AT_FULLAUTH_ID_REQ) {
		return s.akaIdentityClientError(pkt.Identifier)
	}
	imsi, err := s.cfg.SIM.GetIMSI()
	if err != nil {
		return nil, fmt.Errorf("AKA identity SIM identity: %w", err)
	}
	if imsi == "" {
		return nil, errors.New("AKA permanent identity unavailable")
	}
	identity := []byte(buildNAI(imsi, s.cfg))
	value := make([]byte, 2+len(identity))
	binary.BigEndian.PutUint16(value, uint16(len(identity)))
	copy(value[2:], identity)
	attr := &eap.Attribute{Type: eap.AT_IDENTITY, Value: value}
	response := (&eap.EAPPacket{Code: eap.CodeResponse, Identifier: pkt.Identifier,
		Type: eap.TypeAKA, Subtype: eap.SubtypeIdentity, Data: attr.Encode()}).Encode()
	state.selected = identity
	state.exchanges = append(state.exchanges, akaIdentityExchange{bytes.Clone(raw), bytes.Clone(response)})
	state.lastRequest = request
	state.extended = state.extended || extended
	s.akaPermanentIdentity = true
	s.fastReauthCtx = eap.NewFastReauthContext()
	return []ikev2.Payload{&ikev2.EncryptedPayloadEAP{EAPMessage: response}}, nil
}

func (s *Session) akaKeyIdentity() ([]byte, error) {
	if len(s.akaIdentity.selected) > 0 {
		return s.akaIdentity.selected, nil
	}
	if len(s.akaIdentity.outer) > 0 {
		return s.akaIdentity.outer, nil
	}
	imsi, err := s.cfg.SIM.GetIMSI()
	if err != nil {
		return nil, fmt.Errorf("AKA key identity: %w", err)
	}
	return []byte(buildNAI(imsi, s.cfg)), nil
}

func (s *Session) validateAKACheckcode(data []byte) error {
	var checkcode []byte
	for offset := 0; offset < len(data); {
		if len(data)-offset < 4 {
			return errors.New("truncated AKA attribute")
		}
		length := int(data[offset+1]) * 4
		if length < 4 || length > len(data)-offset {
			return errors.New("invalid AKA attribute length")
		}
		if data[offset] == eap.AT_CHECKCODE {
			if checkcode != nil || (length != 4 && length != 24) {
				return errors.New("invalid or duplicate AKA checkcode")
			}
			checkcode = data[offset+2 : offset+length]
		}
		offset += length
	}
	if checkcode == nil {
		if s.akaIdentity.extended {
			return errors.New("AKA identity extension requires checkcode")
		}
		return nil
	}
	var expected []byte
	if len(s.akaIdentity.exchanges) > 0 {
		digest := sha1.New()
		for _, exchange := range s.akaIdentity.exchanges {
			digest.Write(exchange.request)
			digest.Write(exchange.response)
		}
		expected = digest.Sum(nil)
	}
	if !hmac.Equal(expected, checkcode[2:]) {
		return errors.New("AKA checkcode mismatch")
	}
	return nil
}

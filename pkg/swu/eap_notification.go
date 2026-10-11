package swu

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"

	"github.com/1239t/swu-go/pkg/crypto"
	"github.com/1239t/swu-go/pkg/eap"
	"github.com/1239t/swu-go/pkg/ikev2"
)

type eapNotificationState struct {
	method                                    uint8
	authenticated, resultInd, reauth, success bool
	counter                                   uint16
	kEncr                                     []byte
	request, response                         []byte
	failure                                   *EAPNotificationFailure
}

// EAPNotificationFailure is a verified method outcome, not a guessed account,
// carrier, geographic or retry-timer classification.
type EAPNotificationFailure struct{ Code uint16 }

func (e *EAPNotificationFailure) Error() string {
	return fmt.Sprintf("EAP notification failure (code=%d)", e.Code)
}

var errEAPNotification = errors.New("invalid EAP notification")

func (s *Session) completedEAPMethod(method uint8, kAut []byte, resultInd, reauth bool, counter uint16, kEncr []byte) {
	s.eapKAut = bytes.Clone(kAut)
	s.eapNotification = eapNotificationState{method: method, authenticated: !s.cfg.DisableEAPMACValidation, resultInd: resultInd, reauth: reauth, counter: counter, kEncr: bytes.Clone(kEncr)}
}

func notificationAttributes(data []byte) (map[byte][]byte, map[byte]int, error) {
	attrs := make(map[byte][]byte)
	offsets := make(map[byte]int)
	for offset := 0; offset < len(data); {
		if len(data)-offset < 4 {
			return nil, nil, errEAPNotification
		}
		kind, length := data[offset], int(data[offset+1])*4
		if length < 4 || length > len(data)-offset {
			return nil, nil, errEAPNotification
		}
		if _, exists := attrs[kind]; exists {
			return nil, nil, errEAPNotification
		}
		attrs[kind], offsets[kind] = data[offset+2:offset+length], offset
		offset += length
	}
	return attrs, offsets, nil
}

func notificationMAC(method uint8, key, raw []byte) ([]byte, error) {
	var newHash func() hash.Hash
	switch method {
	case eap.TypeAKA:
		if len(key) != 16 {
			return nil, errEAPNotification
		}
		newHash = sha1.New
	case eap.TypeAKAPrime:
		if len(key) != 32 {
			return nil, errEAPNotification
		}
		newHash = sha256.New
	default:
		return nil, errEAPNotification
	}
	m := hmac.New(newHash, key)
	m.Write(raw)
	return m.Sum(nil)[:16], nil
}

func (s *Session) handleEAPNotification(pkt *eap.EAPPacket, raw []byte) ([]ikev2.Payload, error) {
	if len(raw) < 8 || int(binary.BigEndian.Uint16(raw[2:4])) != len(raw) || pkt.Code != eap.CodeRequest || pkt.Subtype != eap.SubtypeNotificationAlt {
		return nil, errEAPNotification
	}
	state := &s.eapNotification
	if state.request != nil {
		if !bytes.Equal(raw, state.request) {
			return nil, errEAPNotification
		}
		return notificationPayload(state.response), nil
	}
	attrs, offsets, err := notificationAttributes(pkt.Data)
	if err != nil {
		return nil, err
	}
	value, ok := attrs[eap.AT_NOTIFICATION]
	if !ok || len(value) != 2 {
		return nil, errEAPNotification
	}
	code := binary.BigEndian.Uint16(value)
	pre, success := code&0x4000 != 0, code&0x8000 != 0
	for kind := range attrs {
		if kind < 128 && kind != eap.AT_NOTIFICATION && kind != eap.AT_MAC {
			return nil, errEAPNotification
		}
	}
	mac, hasMAC := attrs[eap.AT_MAC]
	_, hasIV := attrs[eap.AT_IV]
	_, hasEncrypted := attrs[eap.AT_ENCR_DATA]
	if pre {
		if success || s.akaIdentity.closed || state.authenticated || hasMAC || hasIV || hasEncrypted {
			return nil, errEAPNotification
		}
	} else {
		if !state.authenticated || state.method != pkt.Type || !hasMAC || len(mac) != 18 || (code == 0x8000 && !state.resultInd) {
			return nil, errEAPNotification
		}
		toMAC := bytes.Clone(raw)
		pos := 8 + offsets[eap.AT_MAC] + 4
		clear(toMAC[pos : pos+16])
		want, err := notificationMAC(pkt.Type, s.eapKAut, toMAC)
		if err != nil || !hmac.Equal(want, mac[2:]) {
			return nil, errEAPNotification
		}
		if state.reauth {
			if err := verifyNotificationCounter(attrs, state.kEncr, state.counter); err != nil {
				return nil, err
			}
		} else if hasIV || hasEncrypted {
			return nil, errEAPNotification
		}
	}
	response := []byte{eap.CodeResponse, pkt.Identifier, 0, 8, pkt.Type, eap.SubtypeNotificationAlt, 0, 0}
	if !pre {
		if state.reauth {
			encrypted, err := notificationCounterResponse(state.kEncr, state.counter)
			if err != nil {
				return nil, err
			}
			response = append(response, encrypted...)
		}
		response = append(response, eap.AT_MAC, 5, 0, 0)
		response = append(response, make([]byte, 16)...)
		binary.BigEndian.PutUint16(response[2:4], uint16(len(response)))
		mac, err := notificationMAC(pkt.Type, s.eapKAut, response)
		if err != nil {
			return nil, err
		}
		copy(response[len(response)-16:], mac)
	}
	// Commit only after phase, structure, MAC and counter validation and a
	// complete response. Retransmissions own neither the input nor cached reply.
	state.request, state.response = bytes.Clone(raw), bytes.Clone(response)
	state.success = code == 0x8000
	if !success {
		state.failure = &EAPNotificationFailure{Code: code}
	}
	return notificationPayload(response), nil
}

func notificationPayload(raw []byte) []ikev2.Payload {
	return []ikev2.Payload{&ikev2.EncryptedPayloadEAP{EAPMessage: bytes.Clone(raw)}}
}

func verifyNotificationCounter(attrs map[byte][]byte, key []byte, want uint16) error {
	iv, data := attrs[eap.AT_IV], attrs[eap.AT_ENCR_DATA]
	if len(key) != 16 || len(iv) != 18 || len(data) < 18 || (len(data)-2)%16 != 0 {
		return errEAPNotification
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return errEAPNotification
	}
	plain := make([]byte, len(data)-2)
	cipher.NewCBCDecrypter(block, iv[2:]).CryptBlocks(plain, data[2:])
	inner, offsets, err := notificationAttributes(plain)
	if err != nil {
		return err
	}
	counter, ok := inner[eap.AT_COUNTER]
	if !ok || len(counter) != 2 || binary.BigEndian.Uint16(counter) != want {
		return errEAPNotification
	}
	for kind, value := range inner {
		if kind == eap.AT_COUNTER {
			continue
		}
		if kind != eap.AT_PADDING || !eapReauthAllZero(value) || offsets[kind]+2+len(value) != len(plain) {
			return errEAPNotification
		}
	}
	return nil
}

func notificationCounterResponse(key []byte, counter uint16) ([]byte, error) {
	if len(key) != 16 {
		return nil, errEAPNotification
	}
	iv, err := crypto.RandomBytes(16)
	if err != nil {
		return nil, err
	}
	plain := []byte{eap.AT_COUNTER, 1, byte(counter >> 8), byte(counter), eap.AT_PADDING, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errEAPNotification
	}
	ciphertext := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, plain)
	result := append([]byte{eap.AT_IV, 5, 0, 0}, iv...)
	return append(append(result, eap.AT_ENCR_DATA, 5, 0, 0), ciphertext...), nil
}

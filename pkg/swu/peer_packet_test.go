package swu

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"github.com/1239t/swu-go/pkg/ikev2"
)

// encodePeerPacket builds the CBC/SHA256 test peer using the standard library,
// never the Session's outgoing wrapper. Receive and send keys may differ.
func encodePeerPacket(t *testing.T, s *Session, payloads []ikev2.Payload, exchange ikev2.ExchangeType, mid uint32, response bool) []byte {
	t.Helper()
	var inner []byte
	for i, payload := range payloads {
		body, err := payload.Encode()
		if err != nil {
			t.Fatal(err)
		}
		next := ikev2.NoNextPayload
		if i+1 < len(payloads) {
			next = payloads[i+1].Type()
		}
		inner = append(inner, byte(next), 0)
		inner = binary.BigEndian.AppendUint16(inner, uint16(4+len(body)))
		inner = append(inner, body...)
	}
	first := ikev2.NoNextPayload
	if len(payloads) != 0 {
		first = payloads[0].Type()
	}
	return encodePeerCBCPlaintext(t, s, inner, first, exchange, mid, response)
}

func encodePeerCBCPlaintext(t *testing.T, s *Session, inner []byte, first ikev2.PayloadType, exchange ikev2.ExchangeType, mid uint32, response bool) []byte {
	t.Helper()
	key, macKey := s.Keys.SK_er, s.Keys.SK_ar
	flags := byte(0)
	if s.localResponder {
		key, macKey = s.Keys.SK_ei, s.Keys.SK_ai
		flags = byte(ikev2.FlagInitiator)
	}
	if response {
		flags |= byte(ikev2.FlagResponse)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	padding := (aes.BlockSize - (len(inner)+1)%aes.BlockSize) % aes.BlockSize
	plain := append(bytes.Clone(inner), make([]byte, padding)...)
	plain = append(plain, byte(padding))
	iv := bytes.Repeat([]byte{0x63}, aes.BlockSize)
	ciphertext := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, plain)
	size := 4 + len(iv) + len(ciphertext) + 16
	raw := binary.BigEndian.AppendUint64(nil, s.SPIi)
	raw = binary.BigEndian.AppendUint64(raw, s.SPIr)
	raw = append(raw, byte(ikev2.SK), 0x20, byte(exchange), flags)
	raw = binary.BigEndian.AppendUint32(raw, mid)
	raw = binary.BigEndian.AppendUint32(raw, uint32(28+size))
	raw = append(raw, byte(first), 0)
	raw = binary.BigEndian.AppendUint16(raw, uint16(size))
	raw = append(raw, iv...)
	raw = append(raw, ciphertext...)
	mac := hmac.New(sha256.New, macKey)
	mac.Write(raw)
	return append(raw, mac.Sum(nil)[:16]...)
}

func testPeerReceiver(s *Session) *Session {
	return &Session{
		SPIi: s.SPIi, SPIr: s.SPIr, localResponder: !s.localResponder,
		Keys: s.Keys, EncAlg: s.EncAlg, IntegAlg: s.IntegAlg,
		ikeIsAEAD: s.ikeIsAEAD, Logger: s.Logger, fragmentBuf: newFragmentBuffer(),
	}
}

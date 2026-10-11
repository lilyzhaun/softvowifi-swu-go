package swu

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"github.com/1239t/swu-go/pkg/eap"
	"github.com/1239t/swu-go/pkg/ikev2"
)

func counterNotification(t *testing.T, key, enc []byte, counter uint16) []byte {
	t.Helper()
	raw := notificationWire(0x8000, nil)
	iv := bytes.Repeat([]byte{7}, 16)
	plain := []byte{19, 1, byte(counter >> 8), byte(counter), 6, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	block, err := aes.NewCipher(enc)
	if err != nil {
		t.Fatal(err)
	}
	sealed := make([]byte, 16)
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(sealed, plain)
	raw = append(raw, 129, 5, 0, 0)
	raw = append(raw, iv...)
	raw = append(raw, 130, 5, 0, 0)
	raw = append(raw, sealed...)
	raw = append(raw, 11, 5, 0, 0)
	raw = append(raw, make([]byte, 16)...)
	binary.BigEndian.PutUint16(raw[2:4], uint16(len(raw)))
	m := hmac.New(sha1.New, key)
	m.Write(raw)
	copy(raw[len(raw)-16:], m.Sum(nil)[:16])
	return raw
}

// This fixture represents an already completed method round; it tests only
// Notification, not the existing fast-authentication KDF/wire implementation.
func TestNotificationFastCounterBindingAndEncryptedACK(t *testing.T) {
	key, enc := bytes.Repeat([]byte{3}, 16), bytes.Repeat([]byte{5}, 16)
	for _, variant := range []string{"valid", "wrong counter", "missing encrypted counter", "bad ciphertext", "bad key"} {
		t.Run(variant, func(t *testing.T) {
			s := NewSession(&Config{}, nil)
			s.completedEAPMethod(eap.TypeAKA, key, true, true, 9, enc)
			raw := counterNotification(t, key, enc, 9)
			switch variant {
			case "wrong counter":
				raw = counterNotification(t, key, enc, 8)
			case "missing encrypted counter":
				raw = notificationWire(0x8000, key)
			case "bad ciphertext":
				raw[36] ^= 1
				clear(raw[len(raw)-16:])
				m := hmac.New(sha1.New, key)
				m.Write(raw)
				copy(raw[len(raw)-16:], m.Sum(nil)[:16])
			case "bad key":
				s.eapNotification.kEncr = []byte{1}
			}
			pls, err := s.handleEAP(raw)
			if variant != "valid" {
				if err == nil {
					t.Fatal("unbound fast Notification accepted")
				}
				if s.eapNotification.request != nil {
					t.Fatal("bad counter committed notification state")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			response := pls[0].(*ikev2.EncryptedPayloadEAP).EAPMessage
			if len(response) != 68 || !bytes.Equal(response[:8], []byte{2, 0x87, 0, 68, 23, 12, 0, 0}) {
				t.Fatal("fast Notification ACK has wrong layout")
			}
			toMAC := bytes.Clone(response)
			clear(toMAC[52:68])
			m := hmac.New(sha1.New, key)
			m.Write(toMAC)
			if !hmac.Equal(m.Sum(nil)[:16], response[52:68]) {
				t.Fatal("fast ACK MAC differs from independent peer")
			}
			block, err := aes.NewCipher(enc)
			if err != nil {
				t.Fatal(err)
			}
			plain := make([]byte, 16)
			cipher.NewCBCDecrypter(block, response[12:28]).CryptBlocks(plain, response[32:48])
			if !bytes.Equal(plain, []byte{19, 1, 0, 9, 6, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}) {
				t.Fatal("ACK did not encrypt the original round counter")
			}
		})
	}
}

func TestNotificationPrimeUsesSHA256AndMethodBinding(t *testing.T) {
	key := bytes.Repeat([]byte{0x39}, 32)
	s := NewSession(&Config{}, nil)
	s.completedEAPMethod(eap.TypeAKAPrime, key, true, false, 0, nil)
	raw := notificationWire(0x8000, nil)
	raw[4] = 50
	raw = append(raw, 11, 5, 0, 0)
	raw = append(raw, make([]byte, 16)...)
	binary.BigEndian.PutUint16(raw[2:4], uint16(len(raw)))
	m := hmac.New(sha256.New, key)
	m.Write(raw)
	copy(raw[len(raw)-16:], m.Sum(nil)[:16])
	pls, err := s.handleEAP(raw)
	if err != nil {
		t.Fatal(err)
	}
	response := pls[0].(*ikev2.EncryptedPayloadEAP).EAPMessage
	want := []byte{2, 0x87, 0, 28, 50, 12, 0, 0, 11, 5, 0, 0}
	want = append(want, make([]byte, 16)...)
	m = hmac.New(sha256.New, key)
	m.Write(want)
	copy(want[12:], m.Sum(nil)[:16])
	if !bytes.Equal(response, want) {
		t.Fatal("Type50 Notification ACK used AKA/SHA1 semantics")
	}
}

package swu

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/1239t/swu-go/pkg/eap"
	"github.com/1239t/swu-go/pkg/ikev2"
)

// Independent RFC4187 wire encoding; all values are synthetic. The MSK vectors
// use a separate SHA1-compression/FIPS186-2 implementation checked against every
// published byte of RFC4186 Appendix A.5, not the production PRF under test.
func encryptedReauthRequest(t *testing.T, counter uint16, nonce, key, integrity []byte) []byte {
	t.Helper()
	inner := []byte{eap.AT_COUNTER, 1, byte(counter >> 8), byte(counter)}
	inner = append(inner, eap.AT_NONCE_S, 5, 0, 0)
	inner = append(inner, nonce...)
	inner = append(inner, independentIdentityAttribute(eap.AT_NEXT_REAUTH_ID, "next-synthetic@public.invalid")...)
	return independentProtectedAKARequest(t, eap.SubtypeReauthentication, inner, key, integrity, nil)
}

func independentIdentityAttribute(kind byte, value string) []byte {
	next := []byte(value)
	attributeSize := (4 + len(next) + 3) / 4 * 4
	identity := make([]byte, attributeSize)
	identity[0], identity[1] = kind, byte(attributeSize/4)
	binary.BigEndian.PutUint16(identity[2:4], uint16(len(next)))
	copy(identity[4:], next)
	return identity
}

func independentProtectedAKARequest(t *testing.T, subtype byte, inner, key, integrity, outer []byte) []byte {
	t.Helper()
	inner = bytes.Clone(inner)
	if padding := (16 - len(inner)%16) % 16; padding != 0 {
		inner = append(inner, eap.AT_PADDING, byte(padding/4))
		inner = append(inner, make([]byte, padding-2)...)
	}
	iv := bytes.Repeat([]byte{0x55}, 16)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := make([]byte, len(inner))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, inner)
	raw := []byte{1, 7, 0, 0, eap.TypeAKA, subtype, 0, 0}
	raw = append(raw, outer...)
	raw = append(raw, eap.AT_IV, 5, 0, 0)
	raw = append(raw, iv...)
	raw = append(raw, eap.AT_ENCR_DATA, byte((4+len(ciphertext))/4), 0, 0)
	raw = append(raw, ciphertext...)
	raw = append(raw, eap.AT_MAC, 5, 0, 0)
	raw = append(raw, make([]byte, 16)...)
	binary.BigEndian.PutUint16(raw[2:4], uint16(len(raw)))
	mac := hmac.New(sha1.New, integrity)
	mac.Write(raw)
	copy(raw[len(raw)-16:], mac.Sum(nil)[:16])
	return raw
}

func independentReauthAttributes(t *testing.T, data []byte) map[byte][]byte {
	t.Helper()
	result := map[byte][]byte{}
	for offset := 0; offset < len(data); {
		if len(data)-offset < 4 {
			t.Fatal("truncated reauth attribute")
		}
		kind, size := data[offset], int(data[offset+1])*4
		if size < 4 || size > len(data)-offset || result[kind] != nil {
			t.Fatal("invalid or duplicate reauth attribute")
		}
		result[kind] = bytes.Clone(data[offset+2 : offset+size])
		offset += size
	}
	return result
}

func assertEncryptedReauthResponse(t *testing.T, payloads []ikev2.Payload, counter uint16, nonce, key, integrity []byte, small bool) {
	t.Helper()
	if len(payloads) != 1 {
		t.Fatal("missing one protected reauth response")
	}
	payload, ok := payloads[0].(*ikev2.EncryptedPayloadEAP)
	if !ok {
		t.Fatal("missing EAP payload")
	}
	raw := payload.EAPMessage
	if len(raw) < 8 || raw[0] != 2 || raw[1] != 7 || raw[4] != eap.TypeAKA || raw[5] != eap.SubtypeReauthentication || int(binary.BigEndian.Uint16(raw[2:4])) != len(raw) {
		t.Fatal("invalid reauth response header")
	}
	attrs := independentReauthAttributes(t, raw[8:])
	if len(attrs) != 3 || len(attrs[eap.AT_MAC]) != 18 || len(attrs[eap.AT_IV]) != 18 || len(attrs[eap.AT_ENCR_DATA]) < 18 {
		t.Fatal("counter or counter-too-small escaped the encrypted response")
	}
	if !hmac.Equal(attrs[eap.AT_MAC][2:], independentType23ReauthResponseMAC(integrity, raw, nonce)) {
		t.Fatal("reauth response MAC omitted the full packet or NONCE_S")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := attrs[eap.AT_ENCR_DATA][2:]
	if len(ciphertext)%16 != 0 {
		t.Fatal("encrypted attributes are not complete CBC blocks")
	}
	plain := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, attrs[eap.AT_IV][2:]).CryptBlocks(plain, ciphertext)
	inner := independentReauthAttributes(t, plain)
	if len(inner[eap.AT_COUNTER]) != 2 || binary.BigEndian.Uint16(inner[eap.AT_COUNTER]) != counter || (inner[eap.AT_COUNTER_TOO_SMALL] != nil) != small {
		t.Fatal("protected response counter or fallback marker differs")
	}
	for kind, value := range inner {
		switch kind {
		case eap.AT_COUNTER:
		case eap.AT_COUNTER_TOO_SMALL, eap.AT_PADDING:
			if !bytes.Equal(value, make([]byte, len(value))) {
				t.Fatal("nonzero reserved or padding bytes")
			}
		default:
			t.Fatal("unexpected protected response attribute")
		}
	}
}

func TestAKAReauthRFC4187EncryptedRequestUsesFreshMSKSeed(t *testing.T) {
	cases := []struct {
		identity string
		counter  uint16
		nonce    byte
		msk      string
	}{
		{"reauth-synthetic@public.invalid", 30, 0x33, "254d4718022b990ada6d1946e87cd66440232cb6a5d5e1d723bbf50e3a3e59d20b5f353ea1d73281715354115767d405fb2e5c11c60bd5bf6d45f6edc45c201c"},
		{"reauth-synthetic@public.invalid", 31, 0x33, "ab0090262969241ea61a7373cc39c22e2c9d1c36f9c730facd8a6ffdbcb1eb0eeeed629c9396713d00a8a37549787762b16955f6fae9d3e40d1f8f8b5b1045ca"},
		{"reauth-synthetic@public.invalid", 30, 0x34, "8b58c2f52b7b6e526e5efb7fd9082b2f0ab8d99b0892849a4ad157f1df8a126d662268e433fa8985c5cf63a19c6e8a1c3dcc923dcf69b8ee90531a14cfe40e16"},
		{"other-synthetic@public.invalid", 30, 0x33, "b334f6c19b886d8ccacf9e787217401c22358a7fc55ddc1237ee80a0932f6b0334f113f02ab6964c3244b6092d32e05b59c36322428824bfcf59a5202a3caf5e"},
	}
	for _, test := range cases {
		mk, integrity, key := bytes.Repeat([]byte{0x11}, 20), bytes.Repeat([]byte{0x22}, 16), bytes.Repeat([]byte{0x44}, 16)
		session := type23ReauthSession(t, 20, mk, integrity)
		session.akaIdentity.outer = []byte(test.identity)
		session.fastReauthCtx.ReauthID = test.identity
		nonce := bytes.Repeat([]byte{test.nonce}, 16)
		payloads, err := session.handleEAP(encryptedReauthRequest(t, test.counter, nonce, key, integrity))
		if err != nil {
			t.Fatal("valid independently protected RFC4187 reauth request was rejected")
		}
		expected, err := hex.DecodeString(test.msk)
		if err != nil || !bytes.Equal(session.MSK, expected) {
			t.Fatal("fast MSK did not bind Identity, network-order counter, NONCE_S and MK")
		}
		assertEncryptedReauthResponse(t, payloads, test.counter, nonce, key, integrity, false)
	}
}

func TestAKAReauthRFC4187RejectsCleartextCounterAndNonce(t *testing.T) {
	mk, integrity := bytes.Repeat([]byte{0x11}, 20), bytes.Repeat([]byte{0x22}, 16)
	session := type23ReauthSession(t, 20, mk, integrity)
	session.akaIdentity.outer = []byte("reauth-synthetic@public.invalid")
	before := snapReauth(session)
	data := []byte{eap.AT_COUNTER, 1, 0, 30, eap.AT_NONCE_S, 5, 0, 0}
	data = append(data, bytes.Repeat([]byte{0x33}, 16)...)
	data = append(data, eap.AT_MAC, 5, 0, 0)
	data = append(data, make([]byte, 16)...)
	raw := (&eap.EAPPacket{Code: 1, Identifier: 7, Type: eap.TypeAKA, Subtype: eap.SubtypeReauthentication, Data: data}).Encode()
	copy(raw[len(raw)-16:], independentType23ReauthRequestMAC(integrity, raw))
	if payloads, err := session.handleEAP(raw); err == nil || len(payloads) != 0 || len(session.MSK) != 0 || !before.equalCache(snapReauth(session)) {
		t.Fatal("cleartext counter/nonce were accepted or mutated authenticated cache")
	}
}

func TestAKAReauthRFC4187CounterTooSmallHasProtectedResponse(t *testing.T) {
	mk, integrity, key := bytes.Repeat([]byte{0x11}, 20), bytes.Repeat([]byte{0x22}, 16), bytes.Repeat([]byte{0x44}, 16)
	session := type23ReauthSession(t, 20, mk, integrity)
	session.akaIdentity.outer = []byte("reauth-synthetic@public.invalid")
	session.fastReauthCtx.ReauthID = "reauth-synthetic@public.invalid"
	nonce := bytes.Repeat([]byte{0x33}, 16)
	payloads, err := session.handleEAP(encryptedReauthRequest(t, 19, nonce, key, integrity))
	if err != nil || len(session.MSK) != 0 {
		t.Fatal("counter-too-small must answer within this exchange without publishing a fast MSK")
	}
	assertEncryptedReauthResponse(t, payloads, 19, nonce, key, integrity, true)
}

func TestAKAReauthRFC4187RejectsMalformedProtectedAttributesWithoutPublishing(t *testing.T) {
	key, integrity := bytes.Repeat([]byte{0x44}, 16), bytes.Repeat([]byte{0x22}, 16)
	valid := append([]byte{eap.AT_COUNTER, 1, 0, 30, eap.AT_NONCE_S, 5, 0, 0}, bytes.Repeat([]byte{0x33}, 16)...)
	badID := independentIdentityAttribute(eap.AT_NEXT_REAUTH_ID, "next@public.invalid")
	badID[2], badID[3] = 0xff, 0xff
	for name, inner := range map[string][]byte{
		"duplicate-counter":   append(bytes.Clone(valid), eap.AT_COUNTER, 1, 0, 31),
		"bad-counter-length":  append([]byte{eap.AT_COUNTER, 2, 0, 30, 0, 0, 0, 0}, valid[4:]...),
		"missing-nonce":       {eap.AT_COUNTER, 1, 0, 30},
		"bad-identity-length": append(bytes.Clone(valid), badID...),
		"padding-not-last":    append(append(bytes.Clone(valid), eap.AT_PADDING, 1, 0, 0), independentIdentityAttribute(eap.AT_NEXT_REAUTH_ID, "next@public.invalid")...),
		"padding-not-zero":    append(bytes.Clone(valid), eap.AT_PADDING, 2, 0, 0, 1, 0, 0, 0),
		"unexpected-required": append(bytes.Clone(valid), eap.AT_COUNTER_TOO_SMALL, 1, 0, 0),
	} {
		t.Run(name, func(t *testing.T) {
			s := type23ReauthSession(t, 20, bytes.Repeat([]byte{0x11}, 20), integrity)
			s.akaIdentity.outer = []byte("reauth-synthetic@public.invalid")
			s.fastReauthCtx.ReauthID = "reauth-synthetic@public.invalid"
			before := snapReauth(s)
			updates := 0
			s.cfg.OnFastReauthUpdate = func(string, []byte, []byte, []byte) { updates++ }
			raw := independentProtectedAKARequest(t, 13, inner, key, integrity, nil)
			payloads, err := s.handleEAP(raw)
			if err == nil || len(payloads) != 0 || len(s.MSK) != 0 || !before.equalCache(snapReauth(s)) || updates != 0 {
				t.Fatal("invalid encrypted request published keys, cache or response")
			}
		})
	}
}

func TestAKAReauthRFC4187EqualLastCounterFallsBackAndReplayIsStable(t *testing.T) {
	key, integrity, nonce := bytes.Repeat([]byte{0x44}, 16), bytes.Repeat([]byte{0x22}, 16), bytes.Repeat([]byte{0x33}, 16)
	for _, counter := range []uint16{20, 21, 65535} {
		s := type23ReauthSession(t, 20, bytes.Repeat([]byte{0x11}, 20), integrity)
		s.akaIdentity.outer = []byte("reauth-synthetic@public.invalid")
		s.fastReauthCtx.ReauthID = "reauth-synthetic@public.invalid"
		raw := encryptedReauthRequest(t, counter, nonce, key, integrity)
		first, err := s.handleEAP(raw)
		if err != nil {
			t.Fatal(err)
		}
		assertEncryptedReauthResponse(t, first, counter, nonce, key, integrity, counter == 20)
		second, err := s.handleEAP(bytes.Clone(raw))
		if err != nil || len(second) != 1 || !bytes.Equal(first[0].(*ikev2.EncryptedPayloadEAP).EAPMessage, second[0].(*ikev2.EncryptedPayloadEAP).EAPMessage) {
			t.Fatal("same EAP request did not replay the exact protected response")
		}
	}
}

func TestAKAReauthRequiresTheActuallySelectedFastIdentityAndFreshUsername(t *testing.T) {
	for _, scenario := range []string{"missing", "different", "reused-next-username"} {
		t.Run(scenario, func(t *testing.T) {
			v := syntheticTemporaryIdentity()
			s := NewSession(&Config{SIM: issue25ReauthSIM{}, TemporaryIdentity: v}, nil)
			s.akaIdentity.outer = []byte(v.ReauthID)
			switch scenario {
			case "missing":
				s.akaIdentity.outer = nil
			case "different":
				s.akaIdentity.outer = []byte("different@public.invalid")
			case "reused-next-username":
				s.fastReauthCtx.ReauthID = "next-synthetic@old.invalid"
				s.akaIdentity.outer = []byte(s.fastReauthCtx.ReauthID)
			}
			before := snapReauth(s)
			raw := encryptedReauthRequest(t, 21, bytes.Repeat([]byte{0x33}, 16), v.KEncr, v.KAut)
			if payloads, err := s.handleEAP(raw); err == nil || len(payloads) != 0 || len(s.MSK) != 0 || s.akaPending != nil || !before.equalCache(snapReauth(s)) {
				t.Fatal("unadvertised identity or recycled one-time username accepted")
			}
		})
	}
}

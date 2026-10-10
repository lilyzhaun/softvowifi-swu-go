package swu

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"testing"

	"github.com/1239t/swu-go/pkg/crypto"
	"github.com/1239t/swu-go/pkg/ikev2"
)

func receiveGCMFixture(t *testing.T, role bool) *Session {
	t.Helper()
	s, _ := newPostEAPSession(t)
	s.localResponder = role
	enc, err := crypto.GetEncrypterWithKeyLen(uint16(ikev2.ENCR_AES_GCM_16), 128)
	if err != nil {
		t.Fatal(err)
	}
	s.EncAlg, s.IntegAlg, s.ikeIsAEAD = enc, nil, true
	s.Keys.SK_ei = bytes.Repeat([]byte{0x11}, 20)
	s.Keys.SK_er = bytes.Repeat([]byte{0x22}, 20)
	return s
}

// RFC5282 sections 3/5 and RFC7383: the Pad Length is present for AEAD,
// and AAD includes the SK header (plus fragment numbers for SKF), not just IKE.
func independentGCMFrame(t *testing.T, s *Session, fragment bool, pad byte) []byte {
	t.Helper()
	key := s.Keys.SK_er
	flags := byte(ikev2.FlagResponse)
	if s.localResponder {
		key = s.Keys.SK_ei
		flags |= byte(ikev2.FlagInitiator)
	}
	block, err := aes.NewCipher(key[:len(key)-4])
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte{0, 0, 0, 8, 0, 0, 0x40, 0x0c, pad}
	headerSize, payload := 4, ikev2.SK
	if fragment {
		headerSize, payload = 8, ikev2.EncryptedFragment
	}
	size := headerSize + 8 + len(plain) + gcm.Overhead()
	raw := binary.BigEndian.AppendUint64(nil, s.SPIi)
	raw = binary.BigEndian.AppendUint64(raw, s.SPIr)
	raw = append(raw, byte(payload), 0x20, byte(ikev2.IKE_AUTH), flags)
	raw = binary.BigEndian.AppendUint32(raw, 3)
	raw = binary.BigEndian.AppendUint32(raw, uint32(28+size))
	raw = append(raw, byte(ikev2.N), 0)
	raw = binary.BigEndian.AppendUint16(raw, uint16(size))
	if fragment {
		raw = append(raw, 0, 1, 0, 1)
	}
	iv := bytes.Repeat([]byte{0x63}, 8)
	nonce := append(bytes.Clone(key[len(key)-4:]), iv...)
	sealed := gcm.Seal(nil, nonce, plain, raw)
	raw = append(raw, iv...)
	return append(raw, sealed...)
}

func TestReceiveAEADAuthenticatesPayloadHeadersAndPadding(t *testing.T) {
	for _, role := range []bool{false, true} {
		for _, fragment := range []bool{false, true} {
			name := fmtRole(role) + "/SK"
			if fragment {
				name += "F"
			}
			t.Run(name, func(t *testing.T) {
				s := receiveGCMFixture(t, role)
				raw := independentGCMFrame(t, s, fragment, 0)
				if _, payloads, err := s.decryptAndParse(raw); err != nil || len(payloads) != 1 || payloads[0].Type() != ikev2.N {
					t.Fatalf("independent GCM peer rejected: %v", err)
				}
				for _, offset := range []int{28, 29, len(raw) - 1} {
					bad := bytes.Clone(raw)
					bad[offset] ^= 1
					if _, _, err := s.decryptAndParse(bad); err == nil {
						t.Fatal("unauthenticated GCM header/tag accepted")
					}
				}
				badPad := independentGCMFrame(t, s, fragment, 255)
				if _, _, err := s.decryptAndParse(badPad); err == nil {
					t.Fatal("invalid authenticated GCM padding accepted")
				}
			})
		}
	}
}

func TestReceiveAEADOutgoingMatchesIndependentPeer(t *testing.T) {
	for _, role := range []bool{false, true} {
		t.Run(fmtRole(role), func(t *testing.T) {
			s := receiveGCMFixture(t, role)
			body := []byte{0, 0, 0, 8, 0, 0, 0x40, 0x0c}
			payloads := []ikev2.Payload{&ikev2.EncryptedPayloadNotify{NotifyType: ikev2.MOBIKE_SUPPORTED}}
			for _, fragment := range []bool{false, true} {
				var raw []byte
				var err error
				offset := 32
				if fragment {
					raw, err = s.buildSKFPacket(body, 1, 1, 3, ikev2.IKE_AUTH, ikev2.N)
					offset = 36
				} else {
					raw, err = s.encryptAndWrapWithMsgID(payloads, ikev2.IKE_AUTH, 3, false)
				}
				if err != nil {
					t.Fatal(err)
				}
				key := s.Keys.SK_ei
				if role {
					key = s.Keys.SK_er
				}
				block, err := aes.NewCipher(key[:len(key)-4])
				if err != nil {
					t.Fatal(err)
				}
				gcm, err := cipher.NewGCM(block)
				if err != nil {
					t.Fatal(err)
				}
				nonce := append(bytes.Clone(key[len(key)-4:]), raw[offset:offset+8]...)
				plain, err := gcm.Open(nil, nonce, raw[offset+8:], raw[:offset])
				if err != nil || !bytes.Equal(plain, append(bytes.Clone(body), 0)) {
					t.Fatalf("independent peer cannot authenticate/decode outgoing GCM: %v", err)
				}
			}
		})
	}
}

func TestReceiveSKFBuilderKeepsFollowingPlaintextUnchanged(t *testing.T) {
	for _, aead := range []bool{false, true} {
		s, _ := newPostEAPSession(t)
		if aead {
			s = receiveGCMFixture(t, false)
		}
		plain := bytes.Repeat([]byte{0x41}, 64)
		before := bytes.Clone(plain)
		if _, err := s.buildSKFPacket(plain[:8], 1, 2, 3, ikev2.IKE_AUTH, ikev2.N); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(plain, before) {
			t.Fatal("SKF padding overwrote subsequent plaintext fragments")
		}
	}
}

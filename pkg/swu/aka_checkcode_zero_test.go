package swu

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/1239t/swu-go/pkg/eap"
	"github.com/1239t/swu-go/pkg/ikev2"
)

func Test_AKACheckcode_zeroExchanges_whenChallengeOrReauth(t *testing.T) {
	for _, subtype := range []byte{1, 13} {
		for _, scenario := range []struct {
			name  string
			attr  []byte
			valid bool
		}{
			{"absent", nil, true},
			{"empty", []byte{134, 1, 0x12, 0x34}, true},
			{"digest", append([]byte{134, 6, 0, 0}, bytes.Repeat([]byte{1}, 20)...), false},
			{"wrong-length", []byte{134, 2, 0, 0, 1, 2, 3, 4}, false},
			{"duplicate", []byte{134, 1, 0, 0, 134, 1, 0, 0}, false},
		} {
			t.Run(fmt.Sprintf("%d/%s", subtype, scenario.name), func(t *testing.T) {
				sess, provider := identitySession(t)
				keys := referenceAKAKeys(provider, false)
				sess.fastReauthCtx.SaveReauthData("old-public-identity", bytes.Repeat([]byte{3}, 20), keys[:16], keys[16:32])
				sess.MSK = []byte("prior-msk-sentinel")
				sess.eapKAut = []byte("prior-kaut-sentinel")
				callbackCalls := 0
				sess.cfg.OnFastReauthUpdate = func(_ string, _, _, _ []byte) { callbackCalls++ }
				before := snapReauth(sess)
				priorKAut := bytes.Clone(sess.eapKAut)
				var raw []byte
				if subtype == 1 {
					next := (&eap.Attribute{Type: eap.AT_NEXT_REAUTH_ID, Value: append([]byte{0, 6}, []byte("public")...)}).Encode()
					raw = identityChallenge(t, keys[16:32], append(bytes.Clone(scenario.attr), next...))
				} else {
					raw = type23ReauthRequest(0xce, 1, bytes.Repeat([]byte{4}, 16), make([]byte, 16), []uint8{21, 19, 11})
					raw = append(raw[:len(raw)-20], append(bytes.Clone(scenario.attr), raw[len(raw)-20:]...)...)
					binary.BigEndian.PutUint16(raw[2:4], uint16(len(raw)))
					copy(raw[len(raw)-16:], independentType23ReauthRequestMAC(keys[16:32], raw))
				}

				payloads, err := sess.handleEAP(raw)

				if err != nil || len(payloads) != 1 {
					t.Fatalf("expected EAP response: %v", err)
				}
				response := payloads[0].(*ikev2.EncryptedPayloadEAP).EAPMessage
				if scenario.valid {
					if response[5] != subtype || len(sess.MSK) != 64 {
						t.Fatal("absent/empty CHECKCODE rejected with zero exchanges")
					}
					return
				}
				after := snapReauth(sess)
				if response[5] != 14 || !before.equalCache(after) || !bytes.Equal(before.msk, after.msk) ||
					!bytes.Equal(priorKAut, sess.eapKAut) || callbackCalls != 0 || provider.calls != 0 {
					t.Fatal("invalid zero-exchange CHECKCODE accepted or changed keys/cache/callback/SIM")
				}
			})
		}
	}
}

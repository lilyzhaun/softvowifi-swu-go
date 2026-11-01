package swu

import (
	"bytes"
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
					base := identityChallenge(t, keys[16:32], scenario.attr)
					raw = independentProtectedAKARequest(t, 1, independentIdentityAttribute(eap.AT_NEXT_REAUTH_ID, "public"), keys[:16], keys[16:32], base[8:len(base)-20])
				} else {
					sess.akaIdentity.outer = []byte("old-public-identity")
					inner := append([]byte{eap.AT_COUNTER, 1, 0, 1, eap.AT_NONCE_S, 5, 0, 0}, bytes.Repeat([]byte{4}, 16)...)
					raw = independentProtectedAKARequest(t, 13, inner, keys[:16], keys[16:32], scenario.attr)
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

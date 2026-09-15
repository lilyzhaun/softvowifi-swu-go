package swu

import (
	"bytes"
	"context"
	"crypto/sha1"
	"errors"
	"fmt"
	"testing"

	"github.com/1239t/swu-go/pkg/ikev2"
)

func Test_AKAIdentity_sequences_whenRepeatedRequests(t *testing.T) {
	for _, sequence := range [][]byte{{13, 17, 10}, {13, 13}, {17, 17}, {17, 13}, {10, 10}, {10, 17}, {13, 17, 10, 10}} {
		t.Run(fmt.Sprint(sequence), func(t *testing.T) {
			sess, _ := identitySession(t)
			for index, kind := range sequence {
				response := identityEAP(t, sess, identityRequest(byte(index), kind, 1, 0, 0))
				invalid := index > 0 && (kind == 13 || sequence[index-1] == 10 || (kind == 17 && sequence[index-1] == 17))
				if invalid {
					if response[5] != 14 || len(sess.akaIdentity.exchanges) != index {
						t.Fatal("invalid sequence accepted or transcript changed")
					}
				} else if !bytes.Equal(response, identityResponse(byte(index), identityNAI)) {
					t.Fatal("valid sequence rejected")
				}
			}
		})
	}
}

func Test_AKAIdentity_transcriptOwnsWire_whenRetransmitted(t *testing.T) {
	sess, provider := identitySession(t)
	request := identityRequest(0xcd, 13, 1, 0x12, 0x34, 250, 1, 0x56, 0x78)
	request[6], request[7] = 0x90, 0xab
	original := bytes.Clone(request)
	response := identityEAP(t, sess, request)
	digest := sha1.Sum(append(bytes.Clone(original), response...))
	response[12] ^= 1
	request[6] ^= 1
	retransmit := identityEAP(t, sess, original)
	if !bytes.Equal(retransmit, identityResponse(0xcd, identityNAI)) || len(sess.akaIdentity.exchanges) != 1 {
		t.Fatal("retransmission changed identity or was counted twice")
	}
	checkcode := append([]byte{134, 6, 0, 0}, digest[:]...)
	keys := referenceAKAKeys(provider, false)
	identityEAP(t, sess, identityChallenge(t, keys[16:32], checkcode))
	if len(sess.MSK) != 64 {
		t.Fatal("raw reserved bytes, extension, or copy ownership lost")
	}
}

func Test_AKAIdentity_rejectsChangedIdentifierReuse(t *testing.T) {
	sess, _ := identitySession(t)
	identityEAP(t, sess, identityRequest(1, 13, 1, 0, 0))
	response := identityEAP(t, sess, identityRequest(1, 17, 1, 0, 0))
	if response[5] != 14 || len(sess.akaIdentity.exchanges) != 1 {
		t.Fatal("changed request reused identifier")
	}
}

func Test_AKAIdentity_resetAtActualAttempt_whenTransportFails(t *testing.T) {
	sess, provider := identitySession(t)
	if _, err := sess.buildIKEAuthInitPayloads(); err != nil {
		t.Fatal(err)
	}
	identityEAP(t, sess, identityRequest(1, 13, 1, 0, 0, 250, 1, 0, 0))
	sess.eapKAut = []byte{1}
	sess.MSK = []byte{2}
	sess.akaIdentity.failed = true
	transportErr := errors.New("synthetic transport unavailable")
	sess.cfg.TransportFactory = func(_, _ string) (Transport, error) { return nil, transportErr }
	sess.ctx = context.Background()
	err := sess.connectOnce()
	if sess.taskMgr != nil {
		sess.taskMgr.Stop()
	}
	if err == nil || len(sess.akaIdentity.exchanges) != 0 || sess.akaIdentity.extended || sess.akaIdentity.failed ||
		len(sess.akaIdentity.outer) != 0 || len(sess.akaIdentity.selected) != 0 || sess.localIDiBody != nil || sess.eapKAut != nil || sess.MSK != nil {
		t.Fatal("new attempt retained identity or authentication material")
	}
	keys := referenceAKAKeys(provider, false)
	identityEAP(t, sess, identityChallenge(t, keys[16:32], []byte{134, 1, 0, 0}))
	if len(sess.MSK) != 64 {
		t.Fatal("direct challenge failed after actual attempt reset")
	}
}

func Test_AKAIdentity_directChallengeMatchesOfficialAOSP_whenOuterIdentityUsed(t *testing.T) {
	sess, _ := identitySession(t)
	sess.fastReauthCtx.SaveReauthData("test@android.net", make([]byte, 20), make([]byte, 16), make([]byte, 16))
	outer := identityEAP(t, sess, []byte{1, 1, 0, 5, 1})
	if string(outer[5:]) != "test@android.net" {
		t.Fatal("outer identity differs from official vector")
	}
	request := referenceHex(t, "019b00441701000001050000a789798e3e75560ea3ea5e41a043753a02050000236c38dd8772000165a96f168f5c14e20b050000b66f674a14d96d358e8682230df86253")
	got := identityEAP(t, sess, request)
	want := referenceHex(t, "029b003017010000030500802b1c2593f5af288a3766cada9ce23fb90b050000631beabb876f072b49d453b660fae748")
	if !bytes.Equal(got, want) || !bytes.Equal(sess.eapKAut, referenceHex(t, "f035d5ca7512389f4f96454ea6737b7a")) {
		t.Fatal("official AOSP full response or K_aut differs")
	}
}

func Test_AKAIdentity_permanentChoiceDoesNotReloadStaleConfig_whenNewAUTH1(t *testing.T) {
	sess, _ := identitySession(t)
	sess.cfg.FastReauthID = "stale-config-identity"
	sess.cfg.FastReauthMK = make([]byte, 20)
	identityEAP(t, sess, identityRequest(1, 17, 1, 0, 0))
	sess.resetAKAIdentity()
	payloads, err := sess.buildIKEAuthInitPayloads()
	if err != nil {
		t.Fatal(err)
	}
	for _, payload := range payloads {
		if identity, ok := payload.(*ikev2.EncryptedPayloadID); ok && identity.IsInitiator {
			if string(identity.IDData) != identityNAI {
				t.Fatal("new AUTH1 reloaded stale user cache")
			}
			return
		}
	}
	t.Fatal("missing initiator identity")
}

func Test_AKAIdentity_rejectsMethodSwitch_whenType50FollowsIdentity(t *testing.T) {
	sess, provider := identitySession(t)
	identityEAP(t, sess, identityRequest(1, 13, 1, 0, 0))
	request := identityChallenge(t, referenceAKAKeys(provider, false)[16:32], nil)
	request[4] = 50
	if _, err := sess.handleEAP(request); err == nil || provider.calls != 0 {
		t.Fatal("Type50 must not consume Type23 identity state or invoke SIM")
	}
}

func Test_AKAIdentity_rejectsIdentityAfterChallenge(t *testing.T) {
	sess, provider := identitySession(t)
	identityEAP(t, sess, identityChallenge(t, referenceAKAKeys(provider, false)[16:32], nil))
	response := identityEAP(t, sess, identityRequest(1, 13, 1, 0, 0))
	if response[5] != 14 || len(sess.akaIdentity.exchanges) != 0 {
		t.Fatal("identity renegotiated after challenge")
	}
}

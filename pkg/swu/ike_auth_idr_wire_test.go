package swu

import (
	"bytes"
	"errors"
	"testing"

	"github.com/1239t/swu-go/pkg/ikev2"
)

// Supply wire bytes independently of the production ID encoder, which must
// always send zero RESERVED bytes. The peer's SK protection uses the existing
// standard-library CBC/HMAC encoder.
type wireIDrBody []byte

func (p wireIDrBody) Type() ikev2.PayloadType { return ikev2.IDr }
func (p wireIDrBody) Encode() ([]byte, error) { return bytes.Clone(p), nil }

func TestResponderAUTHBindsReceivedIDrBody(t *testing.T) {
	for _, placement := range []string{"final", "eap-success", "repeated", "zero-reserved"} {
		t.Run(placement, func(t *testing.T) {
			sess, _ := newPostEAPSession(t)
			sess.peerIDrBody = nil
			body := append([]byte{ikev2.ID_FQDN, 0x91, 0x42, 0xf3}, []byte(testIDrFQDN)...)
			if placement == "zero-reserved" {
				clear(body[1:4])
			}
			auth := &ikev2.EncryptedPayloadAuth{AuthMethod: ikev2.AuthMethodSharedKey,
				AuthData: independentResponderAUTH(sess.MSK, sess.Keys.SK_pr, body, sess.saInitResp, sess.ni)}
			final := []ikev2.Payload{auth, testChildSA()}
			if placement != "eap-success" {
				final = append([]ikev2.Payload{wireIDrBody(body)}, final...)
			}
			var err error
			if placement == "eap-success" || placement == "repeated" {
				first := wrapAuth(t, sess, []ikev2.Payload{wireIDrBody(body), eapSuccessPayload()})
				err = sess.completePostEAP(first, func(sent []ikev2.Payload) ([]byte, error) {
					assertInitiatorAUTHSent(t, sent)
					return wrapAuth(t, sess, final), nil
				})
			} else {
				err = sess.handleIKEAuthFinalResp(wrapAuth(t, sess, final))
			}
			if err != nil || sess.ChildSAOut == nil {
				t.Fatalf("AUTH over received IDr body did not commit Child SA: %v", err)
			}
			if !bytes.Equal(sess.peerIDrBody, body) {
				t.Fatal("committed IDr transcript differs from received bytes")
			}
		})
	}
}

func TestResponderAUTHRejectsNormalizedIDrMAC(t *testing.T) {
	sess, ticketCB := newPostEAPSession(t)
	sess.peerIDrBody = nil
	body := append([]byte{ikev2.ID_FQDN, 0x91, 0x42, 0xf3}, []byte(testIDrFQDN)...)
	normalized := bytes.Clone(body)
	clear(normalized[1:4])
	auth := &ikev2.EncryptedPayloadAuth{AuthMethod: ikev2.AuthMethodSharedKey,
		AuthData: independentResponderAUTH(sess.MSK, sess.Keys.SK_pr, normalized, sess.saInitResp, sess.ni)}
	before := snapPostEAP(sess, *ticketCB)
	payloads := append([]ikev2.Payload{wireIDrBody(body), auth, testChildSA()}, mutationNotifies()[:3]...)
	err := sess.handleIKEAuthFinalResp(wrapAuth(t, sess, payloads))
	if !errors.Is(err, ErrIKEAuthFailed) || authReason(err) != "mismatch" {
		t.Fatalf("AUTH over normalized bytes was not rejected: %v", err)
	}
	assertSnapUnchanged(t, before, snapPostEAP(sess, *ticketCB))
}

func TestConnectResponderAUTHBindsReceivedIDrReserved(t *testing.T) {
	for _, layout := range []string{"idr-reserved-plain", "idr-reserved-fragmented"} {
		t.Run(layout, func(t *testing.T) { testAKAIdentityAUTH(t, layout) })
	}
}

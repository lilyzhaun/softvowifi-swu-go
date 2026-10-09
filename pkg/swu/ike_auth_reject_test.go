package swu

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/1239t/swu-go/pkg/ikev2"
)

// RFC 7296 sections 1.2 and 3.15.4: a failed address assignment can
// produce a final IKE_AUTH error without a Child SA.
func TestFinalIKEAuthErrorWithoutChildSA(t *testing.T) {
	for _, code := range []uint16{ikev2.INTERNAL_ADDRESS_FAILURE, ikev2.TS_UNACCEPTABLE, NotifyUserUnknown} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			sess, calls := newPostEAPSession(t)
			before := snapPostEAP(sess, *calls)
			payloads := append(mutationNotifies(), &ikev2.EncryptedPayloadNotify{
				ProtocolID: ikev2.ProtoIKE,
				NotifyType: code,
			})
			err := sess.handleIKEAuthFinalResp(wrapAuth(t, sess, payloads))
			var rej *RejectError
			if !errors.As(err, &rej) || rej.NotifyType != code {
				t.Fatalf("want typed reject %d, got %v", code, err)
			}
			if errors.Is(err, errIKEAuthNeedInitiatorAUTH) {
				t.Fatal("terminal rejection requested another initiator AUTH")
			}
			assertSnapUnchanged(t, before, snapPostEAP(sess, *calls))
		})
	}
}

func TestFinalIKEAuthCorruptedRejectIsNotAccepted(t *testing.T) {
	sess, calls := newPostEAPSession(t)
	before := snapPostEAP(sess, *calls)
	raw := wrapAuth(t, sess, []ikev2.Payload{&ikev2.EncryptedPayloadNotify{NotifyType: ikev2.INTERNAL_ADDRESS_FAILURE}})
	raw[len(raw)-1] ^= 1
	err := sess.handleIKEAuthFinalResp(raw)
	var rej *RejectError
	if err == nil || errors.As(err, &rej) {
		t.Fatalf("corrupted encrypted error accepted: %v", err)
	}
	assertSnapUnchanged(t, before, snapPostEAP(sess, *calls))
}

func TestInternalAddressFailureDescription(t *testing.T) {
	err := ClassifyReject(ikev2.INTERNAL_ADDRESS_FAILURE, []byte("not-for-logs"))
	if err.Category != RejectTransient || !strings.Contains(err.Error(), "INTERNAL_ADDRESS_FAILURE") || strings.Contains(err.Error(), "not-for-logs") {
		t.Fatalf("address failure lost its safe meaning: %v", err)
	}
}

package swu

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/1239t/swu-go/pkg/ikev2"
)

func Test_classifyIKERekeyError_peerReject_whenNotify14(t *testing.T) {
	// Given a wrapped peer notify 14
	err := fmt.Errorf("IKE SA Rekey 被拒绝: %w", ikeRekeyPeerReject(14))

	// When
	got := classifyIKERekeyError(err)

	// Then
	if got.class != SessionDownIKERekeyPeerReject {
		t.Fatalf("class=%s want %s", got.class, SessionDownIKERekeyPeerReject)
	}
	if got.notifyType != 14 {
		t.Fatalf("notify=%d want 14", got.notifyType)
	}
	var typed *ikeRekeyError
	if !errors.As(err, &typed) || typed.notifyType != 14 {
		t.Fatalf("errors.As notify=%v", typed)
	}
}

func Test_classifyIKERekeyError_canceled_whenContextCanceled(t *testing.T) {
	// Given
	err := fmt.Errorf("IKE SA Rekey CREATE_CHILD_SA 发送失败: %w", context.Canceled)

	// When
	got := classifyIKERekeyError(err)

	// Then
	if got.class != SessionDownLocalCancel {
		t.Fatalf("class=%s want %s", got.class, SessionDownLocalCancel)
	}
	if got.class == SessionDownIKERekeyTimeout {
		t.Fatal("canceled mapped to timeout")
	}
	if got.notifyType != 0 {
		t.Fatalf("notify=%d want 0", got.notifyType)
	}
}

func Test_classifyIKERekeyError_timeout_whenWindowTimeout(t *testing.T) {
	// Given
	err := fmt.Errorf("IKE SA Rekey CREATE_CHILD_SA 发送失败: %w", ErrWindowTimeout)

	// When
	got := classifyIKERekeyError(err)

	// Then
	if got.class != SessionDownIKERekeyTimeout {
		t.Fatalf("class=%s want %s", got.class, SessionDownIKERekeyTimeout)
	}
	if got.notifyType != 0 {
		t.Fatalf("notify=%d want 0", got.notifyType)
	}
}

func Test_classifyIKERekeyError_invalidResponse_whenMatchRejected(t *testing.T) {
	// Given
	err := fmt.Errorf("IKE SA Rekey 响应与当前提案不一致: %w", errIKERekeyResponse)

	// When
	got := classifyIKERekeyError(err)

	// Then
	if got.class != SessionDownIKERekeyInvalidResponse {
		t.Fatalf("class=%s want %s", got.class, SessionDownIKERekeyInvalidResponse)
	}
}

func Test_classifyIKERekeyError_unknown_whenSecretBearingMessage(t *testing.T) {
	// Given
	secret := errors.New("nonce=aabbccdd IMSI=123 identity=x@epdg.example")

	// When
	got := classifyIKERekeyError(secret)

	// Then
	if got.class != SessionDownIKERekeyFailed {
		t.Fatalf("class=%s want %s not guessed reject", got.class, SessionDownIKERekeyFailed)
	}
	if strings.Contains(got.Error(), "nonce=") || strings.Contains(got.Error(), "IMSI") {
		t.Fatalf("secret echoed in Error: %q", got.Error())
	}
}

func Test_handleRekeyIKESAResp_observePeerReject_whenEncodedNotify14(t *testing.T) {
	// Given an encoded CREATE_CHILD_SA error notify 14
	sess := newLebaraRekeyCryptoSession(t)
	var class SessionDownReason
	var notify uint16
	sess.OnIKERekeyFailure = func(c SessionDownReason, n uint16) {
		class, notify = c, n
	}
	pkt := encodeRekeyResponse(t, sess, &ikev2.EncryptedPayloadNotify{
		NotifyType: ikev2.NO_PROPOSAL_CHOSEN,
	})

	// When
	err := sess.handleRekeyIKESAResp(pkt, []byte("ni"), sess.DH, 9, sess.Keys.SK_d, sess.SPIi, sess.SPIr)
	got := sess.observeIKERekeyFailure(err)

	// Then
	if got != SessionDownIKERekeyPeerReject || class != SessionDownIKERekeyPeerReject || notify != 14 {
		t.Fatalf("got=%s class=%s notify=%d err=%v", got, class, notify, err)
	}
}

func Test_observeIKERekeyFailure_passesNotify_whenPeerReject14(t *testing.T) {
	// Given
	sess := newClosedTestSession(t)
	var class SessionDownReason
	var notify uint16
	sess.OnIKERekeyFailure = func(c SessionDownReason, n uint16) {
		class, notify = c, n
	}

	// When
	got := sess.observeIKERekeyFailure(ikeRekeyPeerReject(14))

	// Then
	if got != SessionDownIKERekeyPeerReject || class != SessionDownIKERekeyPeerReject || notify != 14 {
		t.Fatalf("got=%s class=%s notify=%d", got, class, notify)
	}
}

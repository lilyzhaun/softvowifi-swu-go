package swu

import (
	"errors"
	"testing"
)

// 永久拒绝错误码 → NO_RETRY
func TestClassifyRejectNoRetry(t *testing.T) {
	noRetryCodes := []uint16{
		NotifyNoEpdgAvailable,
		NotifyEpdgNonAllowed,
		NotifyNoAlternativeEpdg,
		NotifyRefusedByEpdg,
		NotifyNoEpdgOtherPlmn,
		NotifyUserUnknown,
	}
	for _, code := range noRetryCodes {
		rej := ClassifyReject(code, nil)
		if rej.Category != RejectNoRetry {
			t.Fatalf("错误码 %d 应分类为 NO_RETRY，得到 %s", code, rej.Category)
		}
	}
}

func TestClassifyNetworkFailureIsNotPermanentAuthenticationFailure(t *testing.T) {
	if NotifyAuthenticationFailed != 10500 || NotifyNetworkFailure != 10500 {
		t.Fatal("legacy numeric API changed")
	}
	if rej := ClassifyReject(10500, nil); rej.Category != RejectTransient {
		t.Fatal("standard NETWORK_FAILURE was guessed into permanent account/auth rejection")
	}
}

// BACKOFF_TIMER 带 data → BACKOFF + 秒数
func TestClassifyRejectBackoff(t *testing.T) {
	data := []byte{1, 0xa2} // 2 * one-minute units, TS24.302/24.008.
	rej := ClassifyReject(NotifyBackoffTimer, data)
	if rej.Category != RejectBackoff {
		t.Fatalf("BACKOFF_TIMER 应分类为 BACKOFF，得到 %s", rej.Category)
	}
	if rej.Backoff != 120 {
		t.Fatalf("BACKOFF_TIMER 应解析出 120s，得到 %d", rej.Backoff)
	}
}

// Missing timer is malformed, never an invented 60-second deadline.
func TestClassifyRejectBackoffNoData(t *testing.T) {
	rej := ClassifyReject(NotifyBackoffTimer, nil)
	if rej.Category != RejectTransient {
		t.Fatalf("malformed timer changed fallback classification: %s", rej.Category)
	}
	if rej.Backoff != 0 {
		t.Fatal("missing timer manufactured a default deadline")
	}
}

// 其他错误码 → TRANSIENT
func TestClassifyRejectTransient(t *testing.T) {
	rej := ClassifyReject(1, nil)
	if rej.Category != RejectTransient {
		t.Fatalf("未知错误码应分类为 TRANSIENT，得到 %s", rej.Category)
	}
}

// RejectError 可通过 errors.As 提取
func TestRejectErrorErrorsAs(t *testing.T) {
	err := ClassifyReject(NotifyNoEpdgAvailable, nil)
	var rej *RejectError
	if !errors.As(err, &rej) {
		t.Fatalf("RejectError 应可通过 errors.As 提取")
	}
	if rej.NotifyType != NotifyNoEpdgAvailable {
		t.Fatalf("NotifyType 不匹配: %d", rej.NotifyType)
	}
}

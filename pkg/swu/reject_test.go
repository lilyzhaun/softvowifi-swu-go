package swu

import (
	"encoding/binary"
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
		NotifyAuthenticationFailed,
	}
	for _, code := range noRetryCodes {
		rej := ClassifyReject(code, nil)
		if rej.Category != RejectNoRetry {
			t.Fatalf("错误码 %d 应分类为 NO_RETRY，得到 %s", code, rej.Category)
		}
	}
}

// BACKOFF_TIMER 带 data → BACKOFF + 秒数
func TestClassifyRejectBackoff(t *testing.T) {
	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data, 120)
	rej := ClassifyReject(NotifyBackoffTimer, data)
	if rej.Category != RejectBackoff {
		t.Fatalf("BACKOFF_TIMER 应分类为 BACKOFF，得到 %s", rej.Category)
	}
	if rej.Backoff != 120 {
		t.Fatalf("BACKOFF_TIMER 应解析出 120s，得到 %d", rej.Backoff)
	}
}

// BACKOFF_TIMER 无 data → BACKOFF + 默认 60s
func TestClassifyRejectBackoffNoData(t *testing.T) {
	rej := ClassifyReject(NotifyBackoffTimer, nil)
	if rej.Category != RejectBackoff {
		t.Fatalf("无 data 的 BACKOFF_TIMER 应分类为 BACKOFF，得到 %s", rej.Category)
	}
	if rej.Backoff != 60 {
		t.Fatalf("无 data 的 BACKOFF_TIMER 应默认 60s，得到 %d", rej.Backoff)
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

package swu

import (
	"encoding/binary"
	"fmt"

	"github.com/1239t/swu-go/pkg/ikev2"
)

// 3GPP TS 24.302 §7.2.2.2 错误码分类
// ePDG 在 IKE_AUTH 中通过 Notify 返回 3GPP 错误码，决定客户端重试策略

const (
	// NO_EPDG_AVAILABLE - 当前 PLMN 无可用 ePDG，不应重试
	NotifyNoEpdgAvailable uint16 = 9000
	// EPDG_NON_ALLOWED - ePDG 不允许访问
	NotifyEpdgNonAllowed uint16 = 9001
	// NO_ALTERNATIVE_EPDG_AVAILABLE - 无替代 ePDG
	NotifyNoAlternativeEpdg uint16 = 9002
	// P_CSCF_RESELECTION_SUPPORTED - P-CSCF 重选支持
	NotifyPCSCFReselection uint16 = 9003
	// REFUSED_BY_EPDG - 被 ePDG 拒绝
	NotifyRefusedByEpdg uint16 = 9006
	// NO_EPDG_AVAILABLE_OTHER_PLMN - 其他 PLMN 无可用 ePDG
	NotifyNoEpdgOtherPlmn uint16 = 11001
	// USER_UNKNOWN - 用户未知
	NotifyUserUnknown uint16 = 11011
	// AUTHENTICATION_FAILED - 认证失败
	NotifyAuthenticationFailed uint16 = 10500
	// BACKOFF_TIMER - 临时拒绝，携带退避时间（秒，4 字节 data）
	NotifyBackoffTimer uint16 = 41041
)

// RejectCategory 拒绝分类，决定重试策略
type RejectCategory int

const (
	// RejectNoRetry 永久拒绝（同一 PLMN 不应重试）
	RejectNoRetry RejectCategory = iota
	// RejectBackoff 临时拒绝，需等待 BACKOFF_TIMER
	RejectBackoff
	// RejectTransient 临时错误，可立即重试（指数退避）
	RejectTransient
)

func (c RejectCategory) String() string {
	switch c {
	case RejectNoRetry:
		return "no_retry"
	case RejectBackoff:
		return "backoff"
	case RejectTransient:
		return "transient"
	}
	return "unknown"
}

// RejectError 结构化拒绝错误，supervisor 层通过 errors.As 提取
type RejectError struct {
	// NotifyType 原始 3GPP 错误码
	NotifyType uint16
	// Category 拒绝分类
	Category RejectCategory
	// Backoff 退避秒数（仅 Category==RejectBackoff 时有意义）
	Backoff uint32
}

func (e *RejectError) Error() string {
	switch e.Category {
	case RejectNoRetry:
		return fmt.Sprintf("ePDG 永久拒绝: type=%d (%s)", e.NotifyType, rejectTypeName(e.NotifyType))
	case RejectBackoff:
		return fmt.Sprintf("ePDG 临时拒绝: type=%d backoff=%ds", e.NotifyType, e.Backoff)
	default:
		if e.NotifyType == ikev2.INTERNAL_ADDRESS_FAILURE {
			return "ePDG address allocation failed: type=36 (INTERNAL_ADDRESS_FAILURE)"
		}
		return fmt.Sprintf("ePDG 拒绝: type=%d", e.NotifyType)
	}
}

// ClassifyReject 按 TS 24.302 §7.2.2.2 分类 3GPP 错误码
func ClassifyReject(notifyType uint16, data []byte) *RejectError {
	switch notifyType {
	case NotifyNoEpdgAvailable, NotifyEpdgNonAllowed, NotifyNoAlternativeEpdg,
		NotifyRefusedByEpdg, NotifyNoEpdgOtherPlmn, NotifyUserUnknown,
		NotifyAuthenticationFailed:
		return &RejectError{NotifyType: notifyType, Category: RejectNoRetry}
	case NotifyBackoffTimer:
		backoff := uint32(0)
		if len(data) >= 4 {
			backoff = binary.BigEndian.Uint32(data[:4])
		}
		if backoff == 0 {
			// 无有效退避时间，按临时处理
			backoff = 60
		}
		return &RejectError{NotifyType: notifyType, Category: RejectBackoff, Backoff: backoff}
	default:
		// 其他 <16384 错误码：临时错误，指数退避重试
		return &RejectError{NotifyType: notifyType, Category: RejectTransient}
	}
}

func rejectTypeName(t uint16) string {
	switch t {
	case NotifyNoEpdgAvailable:
		return "NO_EPDG_AVAILABLE"
	case NotifyEpdgNonAllowed:
		return "EPDG_NON_ALLOWED"
	case NotifyNoAlternativeEpdg:
		return "NO_ALTERNATIVE_EPDG_AVAILABLE"
	case NotifyPCSCFReselection:
		return "P_CSCF_RESELECTION_SUPPORTED"
	case NotifyRefusedByEpdg:
		return "REFUSED_BY_EPDG"
	case NotifyNoEpdgOtherPlmn:
		return "NO_EPDG_AVAILABLE_OTHER_PLMN"
	case NotifyUserUnknown:
		return "USER_UNKNOWN"
	case NotifyAuthenticationFailed:
		return "AUTHENTICATION_FAILED"
	case NotifyBackoffTimer:
		return "BACKOFF_TIMER"
	}
	return fmt.Sprintf("unknown(%d)", t)
}

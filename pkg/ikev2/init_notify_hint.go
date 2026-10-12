package ikev2

import (
	"encoding/binary"
	"fmt"
)

// InitNotifyHintError is diagnostic metadata from a rejected, unauthenticated
// single-Notify INIT response. It never authorizes a proposal or DH change.
// Raw notification data, identifiers and endpoints are deliberately not retained.
type InitNotifyHintError struct {
	NotifyType       uint16
	DataLen          int
	SuggestedDHGroup uint16
}

func (h InitNotifyHintError) Error() string {
	text := fmt.Sprintf("unauthenticated IKE_SA_INIT notify type=%d dataLen=%d", h.NotifyType, h.DataLen)
	if h.NotifyType == INVALID_KE_PAYLOAD {
		text += fmt.Sprintf(" suggestedDHGroup=%d", h.SuggestedDHGroup)
	}
	return text
}

func (h InitNotifyHintError) Unwrap() error { return ErrInitResponse }

func initNotifyHint(notify *EncryptedPayloadNotify) error {
	if notify.NotifyType == 0 || notify.NotifyType >= 16384 {
		return ErrInitResponse
	}
	hint := &InitNotifyHintError{NotifyType: notify.NotifyType, DataLen: len(notify.NotifyData)}
	if notify.NotifyType == INVALID_KE_PAYLOAD {
		if len(notify.NotifyData) != 2 {
			return ErrInitResponse
		}
		hint.SuggestedDHGroup = binary.BigEndian.Uint16(notify.NotifyData)
	}
	return hint
}

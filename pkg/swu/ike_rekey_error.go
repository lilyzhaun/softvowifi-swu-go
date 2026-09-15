package swu

import (
	"context"
	"errors"
)

type ikeRekeyError struct {
	class      SessionDownReason
	notifyType uint16
}

func (e *ikeRekeyError) Error() string {
	return string(e.class)
}

func ikeRekeyPeerReject(notify uint16) error {
	return &ikeRekeyError{class: SessionDownIKERekeyPeerReject, notifyType: notify}
}

func classifyIKERekeyError(err error) *ikeRekeyError {
	var typed *ikeRekeyError
	if errors.As(err, &typed) {
		return typed
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return &ikeRekeyError{class: SessionDownLocalCancel}
	}
	if errors.Is(err, ErrWindowTimeout) {
		return &ikeRekeyError{class: SessionDownIKERekeyTimeout}
	}
	if errors.Is(err, errIKERekeyResponse) {
		return &ikeRekeyError{class: SessionDownIKERekeyInvalidResponse}
	}
	return &ikeRekeyError{class: SessionDownIKERekeyFailed}
}

func (s *Session) observeIKERekeyFailure(err error) SessionDownReason {
	fail := classifyIKERekeyError(err)
	class := ParseSessionDownReason(string(fail.class))
	if s.OnIKERekeyFailure != nil {
		s.OnIKERekeyFailure(class, fail.notifyType)
	}
	return class
}

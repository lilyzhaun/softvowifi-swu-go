package swu

import "context"

// SessionClosedError identifies an established session's terminal event.
// RedirectTo is set only for a parsed, protected runtime REDIRECT; consumers
// must create a new Session after cleanup instead of reusing the old SA.
type SessionClosedError struct {
	Reason     SessionDownReason
	RedirectTo string
}

func (e *SessionClosedError) Error() string { return "session closed: " + string(e.Reason) }
func (e *SessionClosedError) Unwrap() error { return context.Canceled }
func (e *SessionClosedError) Is(target error) bool {
	return target == ErrReauth && e.Reason == SessionDownReauthentication
}

type SessionDownReason string

const (
	SessionDownIKERekeyFailed          SessionDownReason = "ike_rekey_failed"
	SessionDownIKERekeyPeerReject      SessionDownReason = "ike_rekey_peer_reject"
	SessionDownIKERekeyTimeout         SessionDownReason = "ike_rekey_timeout"
	SessionDownIKERekeyInvalidResponse SessionDownReason = "ike_rekey_invalid_response"
	SessionDownChildRekeyFailed        SessionDownReason = "child_rekey_failed"
	SessionDownDPDExhausted            SessionDownReason = "dpd_exhausted"
	SessionDownDPDFailed               SessionDownReason = "dpd_failed"
	SessionDownPeerIKEDelete           SessionDownReason = "peer_ike_delete"
	SessionDownPeerChildDelete         SessionDownReason = "peer_child_delete"
	SessionDownReauthentication        SessionDownReason = "reauthentication"
	SessionDownKernelHardExpire        SessionDownReason = "kernel_hard_expire"
	SessionDownRedirect                SessionDownReason = "redirect"
	SessionDownLocalCancel             SessionDownReason = "local_cancel"
	SessionDownInternalTransport       SessionDownReason = "internal_transport"
	SessionDownUnknown                 SessionDownReason = "unknown"
)

func ParseSessionDownReason(raw string) SessionDownReason {
	reason := SessionDownReason(raw)
	switch reason {
	case SessionDownIKERekeyFailed,
		SessionDownIKERekeyPeerReject,
		SessionDownIKERekeyTimeout,
		SessionDownIKERekeyInvalidResponse,
		SessionDownChildRekeyFailed,
		SessionDownDPDExhausted,
		SessionDownDPDFailed,
		SessionDownPeerIKEDelete,
		SessionDownPeerChildDelete,
		SessionDownReauthentication,
		SessionDownKernelHardExpire,
		SessionDownRedirect,
		SessionDownLocalCancel,
		SessionDownInternalTransport,
		SessionDownUnknown:
		return reason
	default:
		return SessionDownUnknown
	}
}

func (s *Session) observeClosed(reason SessionDownReason) {
	if s.OnClosedReason == nil {
		return
	}
	s.OnClosedReason(ParseSessionDownReason(string(reason)))
}

func dpdClosedReason(ctx context.Context) SessionDownReason {
	if ctx != nil && ctx.Err() != nil {
		return SessionDownLocalCancel
	}
	return SessionDownDPDFailed
}

func (s *Session) onHardExpire() {
	s.endSession(SessionDownKernelHardExpire, "")
}

// endSession owns cancellation. Observers run after cancellation and outside
// Once so a blocking or reentrant observer cannot suppress/reenter termination.
// Protected peer requests call this only after attempting their response.
func (s *Session) endSession(reason SessionDownReason, redirect string) {
	first := false
	s.terminalOnce.Do(func() {
		first = true
		if s.cancelCause != nil {
			s.cancelCause(&SessionClosedError{Reason: reason, RedirectTo: redirect})
		} else if s.cancel != nil {
			s.cancel()
		}
	})
	if !first {
		return
	}
	if reason != SessionDownLocalCancel && s.OnSessionDown != nil {
		go s.OnSessionDown()
	}
	s.observeClosed(reason)
}

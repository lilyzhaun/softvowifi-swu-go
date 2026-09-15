package swu

import "context"

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
	if s.OnSessionDown != nil {
		go s.OnSessionDown()
	} else if s.cancel != nil {
		s.cancel()
	}
	s.observeClosed(SessionDownKernelHardExpire)
}

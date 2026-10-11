package swu

import (
	"crypto/hmac"
	"errors"
	"fmt"

	"github.com/1239t/swu-go/pkg/eap"
	"github.com/1239t/swu-go/pkg/ikev2"
)

var (
	ErrIKEAuthFailed            = errors.New("IKE AUTH verification failed")
	ErrResumeAuthUnsupported    = errors.New("SESSION_RESUME AUTH signed material unverified")
	errIKEAuthNeedInitiatorAUTH = errors.New("IKE AUTH incomplete")
)

type IKEAuthFailure struct {
	Reason string
}

func (e *IKEAuthFailure) Error() string {
	return "IKE AUTH: " + e.Reason
}

func (e *IKEAuthFailure) Unwrap() error {
	return ErrIKEAuthFailed
}

func authFail(reason string) error {
	return &IKEAuthFailure{Reason: reason}
}

func ikeAuthHasChildSA(payloads []ikev2.Payload) bool {
	for _, pl := range payloads {
		sa, ok := pl.(*ikev2.EncryptedPayloadSA)
		if ok && len(sa.Proposals) > 0 {
			return true
		}
	}
	return false
}

func extractIDrBody(payloads []ikev2.Payload) ([]byte, error) {
	var body []byte
	for _, pl := range payloads {
		id, ok := pl.(*ikev2.EncryptedPayloadID)
		if !ok || id.IsInitiator {
			continue
		}
		encoded, err := id.Encode()
		if err != nil {
			return nil, fmt.Errorf("encode IDr: %w", err)
		}
		if body != nil && !hmac.Equal(body, encoded) {
			return nil, authFail("idr")
		}
		body = encoded
	}
	return body, nil
}

func (s *Session) captureEAPIDr(payloads []ikev2.Payload) error {
	body, err := extractIDrBody(payloads)
	if err != nil {
		return err
	}
	if body == nil {
		return nil
	}
	if len(s.peerIDrBody) > 0 && !hmac.Equal(s.peerIDrBody, body) {
		return authFail("idr")
	}
	s.peerIDrBody = append([]byte(nil), body...)
	return nil
}

func (s *Session) lookupIDrBody(payloads []ikev2.Payload) ([]byte, error) {
	body, err := extractIDrBody(payloads)
	if err != nil {
		return nil, err
	}
	if body != nil {
		if len(s.peerIDrBody) > 0 && !hmac.Equal(s.peerIDrBody, body) {
			return nil, authFail("idr")
		}
		return body, nil
	}
	if len(s.peerIDrBody) == 0 {
		return nil, authFail("idr")
	}
	return s.peerIDrBody, nil
}

func parseSingleSharedKeyAUTH(payloads []ikev2.Payload) (*ikev2.EncryptedPayloadAuth, error) {
	var found *ikev2.EncryptedPayloadAuth
	count := 0
	for _, pl := range payloads {
		auth, ok := pl.(*ikev2.EncryptedPayloadAuth)
		if !ok {
			continue
		}
		count++
		found = auth
	}
	if count == 0 {
		return nil, authFail("missing")
	}
	if count > 1 {
		return nil, authFail("multiple")
	}
	if found.AuthMethod != ikev2.AuthMethodSharedKey {
		return nil, authFail("method")
	}
	if len(found.AuthData) == 0 || eapReauthAllZero(found.AuthData) {
		return nil, authFail("zero")
	}
	return found, nil
}

func (s *Session) verifyPostEAPResponderAUTH(payloads []ikev2.Payload) ([]byte, error) {
	if s.PRFAlg == nil || s.Keys == nil || len(s.Keys.SK_pr) == 0 {
		return nil, authFail("msk")
	}
	if err := requirePostEAPMSK(s.MSK); err != nil {
		return nil, err
	}
	if len(s.saInitResp) == 0 || len(s.ni) == 0 {
		return nil, authFail("mismatch")
	}
	auth, err := parseSingleSharedKeyAUTH(payloads)
	if err != nil {
		return nil, err
	}
	idrBody, err := s.lookupIDrBody(payloads)
	if err != nil {
		return nil, err
	}
	expected, err := computeResponderIKEAuthData(s.PRFAlg, s.MSK, s.Keys.SK_pr, idrBody, s.saInitResp, s.ni)
	if err != nil {
		return nil, fmt.Errorf("compute responder AUTH: %w", err)
	}
	if !hmac.Equal(expected, auth.AuthData) {
		return nil, authFail("mismatch")
	}
	return idrBody, nil
}

func (s *Session) processIKEAuthEAPRound(payloads []ikev2.Payload) ([]ikev2.Payload, bool, error) {
	if rej := s.ikeAuthErrorNotify(payloads); rej != nil {
		return nil, false, rej
	}
	var equipment *ikev2.EncryptedPayloadNotify
	var eapPayload *ikev2.EncryptedPayloadEAP
	for _, pl := range payloads {
		switch p := pl.(type) {
		case *ikev2.EncryptedPayloadEAP:
			if eapPayload != nil {
				return nil, false, errors.New("multiple EAP payloads in AUTH round")
			}
			eapPayload = p
		case *ikev2.EncryptedPayloadNotify:
			if p.NotifyType != ikev2.DEVICE_IDENTITY && p.NotifyType != ikev2.DEVICE_IDENTITY_3GPP {
				continue
			}
			if equipment != nil || len(p.SPI) != 0 || p.ProtocolID > ikev2.ProtoIKE || len(p.NotifyData) != 3 || p.NotifyData[0] != 0 || p.NotifyData[1] != 1 || (p.NotifyData[2] != 1 && p.NotifyData[2] != 2) {
				return nil, false, errors.New("invalid DEVICE_IDENTITY request")
			}
			equipment = p
		}
	}
	if equipment != nil && !s.eapNotification.authenticated {
		if eapPayload == nil {
			return nil, false, errors.New("DEVICE_IDENTITY before network authentication")
		}
		p, err := eap.Parse(eapPayload.EAPMessage)
		if err != nil || p.Code != eap.CodeRequest || (p.Type != eap.TypeAKA && p.Type != eap.TypeAKAPrime) || (p.Subtype != eap.SubtypeChallenge && p.Subtype != eap.SubtypeNotificationAlt) {
			return nil, false, errors.New("DEVICE_IDENTITY before network authentication")
		}
	}
	if err := s.captureEAPIDr(payloads); err != nil {
		return nil, false, err
	}
	var response []ikev2.Payload
	done := false
	if eapPayload != nil {
		var err error
		response, err = s.handleEAP(eapPayload.EAPMessage)
		if err != nil {
			return nil, false, err
		}
		done = response == nil
	}
	// A verified failure must be acknowledged, never accompanied by equipment
	// identity; Connect then follows the existing terminal notification path.
	if equipment != nil && s.eapNotification.failure == nil {
		if !s.eapNotification.authenticated {
			return nil, false, errors.New("DEVICE_IDENTITY before network authentication")
		}
		identity, err := s.buildDeviceIdentityResponse(equipment.NotifyData[2])
		if err != nil {
			return nil, false, err
		}
		identity[0].(*ikev2.EncryptedPayloadNotify).NotifyType = equipment.NotifyType
		response = append(response, identity...)
	}
	return response, done, nil
}

func requirePostEAPMSK(msk []byte) error {
	if len(msk) == 0 || eapReauthAllZero(msk) {
		return authFail("msk")
	}
	return nil
}

func (s *Session) ikeAuthErrorNotify(payloads []ikev2.Payload) error {
	var rejected *RejectError
	errorCount := 0
	var timer *ikev2.EncryptedPayloadNotify
	for _, pl := range payloads {
		notify, ok := pl.(*ikev2.EncryptedPayloadNotify)
		if !ok {
			continue
		}
		if notify.NotifyType < 16384 {
			errorCount++
			if rejected == nil {
				rejected = ClassifyReject(notify.NotifyType, notify.NotifyData)
			}
		}
		if notify.NotifyType == NotifyBackoffTimer {
			if timer != nil || len(notify.SPI) != 0 || notify.ProtocolID > ikev2.ProtoIKE {
				return errAuthBackoff
			}
			timer = notify
		}
	}
	if timer != nil {
		seconds, deactivated, err := decodeBackoffTimer(timer.NotifyData)
		if err != nil || errorCount != 1 || !s.eapNotification.authenticated {
			return errAuthBackoff
		}
		// Permanent errors remain stricter than a finite timer. NO_APN has its
		// own Tw3 rules; NETWORK_FAILURE is transient, not account rejection.
		if rejected.Category == RejectNoRetry && rejected.NotifyType != NotifyNoAPNSubscription {
			return rejected
		}
		rejected.Category, rejected.Backoff, rejected.BackoffDeactivated = RejectBackoff, seconds, deactivated
		if deactivated {
			rejected.Category = RejectNoRetry
		}
	}
	if rejected == nil {
		return nil
	}
	return rejected
}

func (s *Session) completePostEAP(respData []byte, sendFinal func([]ikev2.Payload) ([]byte, error)) error {
	message, err := s.decodeProtectedIKE(respData)
	if err != nil {
		return err
	}
	if message == nil {
		return errFragmentIncomplete
	}
	return s.completePostEAPMessage(message, func(payloads []ikev2.Payload) (*protectedIKEMessage, error) {
		raw, err := sendFinal(payloads)
		if err != nil {
			return nil, err
		}
		final, err := s.decodeProtectedIKE(raw)
		if err == nil && final == nil {
			err = errFragmentIncomplete
		}
		return final, err
	})
}

func (s *Session) completePostEAPMessage(message *protectedIKEMessage, sendFinal func([]ikev2.Payload) (*protectedIKEMessage, error)) error {
	payloads := message.payloads
	s.logIKEAuthMetadata(ikeAuthPhaseEAPLoop, payloads)
	if rej := s.ikeAuthErrorNotify(payloads); rej != nil {
		return rej
	}
	if err := s.captureEAPIDr(payloads); err != nil {
		return err
	}
	if err := requirePostEAPMSK(s.MSK); err != nil {
		return err
	}
	authPayloads, err := s.buildIKEAuthFinalPayloads()
	if err != nil {
		return fmt.Errorf("failed to build final AUTH: %w", err)
	}
	final, err := sendFinal(authPayloads)
	if err != nil {
		return fmt.Errorf("failed to send final AUTH: %w", err)
	}
	return s.handleIKEAuthFinalParsed(final.payloads)
}

func (s *Session) resetIKEAuthTranscripts() {
	s.fragmentBuf.clear()
	s.initialChildRequest = nil
	s.localIDiBody = nil
	s.saInitResp = nil
	s.peerIDrBody = nil
	s.resumeAuthPending = false
}

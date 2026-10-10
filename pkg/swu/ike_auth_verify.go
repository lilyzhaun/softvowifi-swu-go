package swu

import (
	"crypto/hmac"
	"errors"
	"fmt"

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
	if err := s.captureEAPIDr(payloads); err != nil {
		return nil, false, err
	}
	var eapPayload *ikev2.EncryptedPayloadEAP
	for _, pl := range payloads {
		if e, ok := pl.(*ikev2.EncryptedPayloadEAP); ok {
			eapPayload = e
		}
	}
	if eapPayload == nil {
		return nil, false, nil
	}
	resp, err := s.handleEAP(eapPayload.EAPMessage)
	if err != nil {
		return nil, false, err
	}
	if resp == nil {
		return nil, true, nil
	}
	return resp, false, nil
}

func requirePostEAPMSK(msk []byte) error {
	if len(msk) == 0 || eapReauthAllZero(msk) {
		return authFail("msk")
	}
	return nil
}

func ikeAuthErrorNotify(payloads []ikev2.Payload) *RejectError {
	for _, pl := range payloads {
		notify, ok := pl.(*ikev2.EncryptedPayloadNotify)
		if !ok {
			continue
		}
		if notify.NotifyType < 16384 {
			return ClassifyReject(notify.NotifyType, notify.NotifyData)
		}
	}
	return nil
}

func (s *Session) completePostEAP(respData []byte, sendFinal func([]ikev2.Payload) ([]byte, error)) error {
	_, payloads, err := s.decryptAndParse(respData)
	if err != nil {
		return fmt.Errorf("解析 IKE_AUTH EAP 完成消息失败: %v", err)
	}
	s.logIKEAuthMetadata(ikeAuthPhaseEAPLoop, payloads)
	if rej := ikeAuthErrorNotify(payloads); rej != nil {
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
	return s.handleIKEAuthFinalResp(final)
}

func (s *Session) resetIKEAuthTranscripts() {
	s.initialChildRequest = nil
	s.localIDiBody = nil
	s.saInitResp = nil
	s.peerIDrBody = nil
	s.resumeAuthPending = false
}

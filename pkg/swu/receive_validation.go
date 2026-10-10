package swu

import (
	"errors"

	"github.com/1239t/swu-go/pkg/ikev2"
)

var ErrInvalidProtectedIKE = errors.New("invalid protected IKE message")

// Peer packets must match the local role in the current IKE SA and be bound to
// both negotiated SPIs and protected before any state, pending or activity commit.
func (s *Session) protectedHeader(data []byte) (*ikev2.IKEHeader, error) {
	h, err := ikev2.DecodeHeader(data)
	if err != nil {
		return nil, err
	}
	if len(data) < ikev2.IKE_HEADER_LEN+4 || len(data) > 65535 || int(h.Length) != len(data) ||
		h.Version>>4 != 2 || (h.Flags&ikev2.FlagInitiator != 0) != s.localResponder || h.SPIi != s.SPIi ||
		s.SPIr == 0 || h.SPIr != s.SPIr || s.Keys == nil || s.EncAlg == nil {
		return nil, ErrInvalidProtectedIKE
	}
	switch h.ExchangeType {
	case ikev2.IKE_AUTH, ikev2.CREATE_CHILD_SA, ikev2.INFORMATIONAL:
	default:
		return nil, ErrInvalidProtectedIKE
	}
	if h.NextPayload != ikev2.SK && h.NextPayload != ikev2.EncryptedFragment {
		return nil, ErrInvalidProtectedIKE
	}
	if !s.ikeIsAEAD && (s.IntegAlg == nil || s.IntegAlg.OutputSize() == 0) {
		return nil, ErrInvalidProtectedIKE
	}
	return h, nil
}

// The bool permits endpoint commit. A strict proposal-number rejection can be
// delivered solely as a fresh-Session retry hint, without accepting its endpoint.
func (s *Session) validateWindowResponse(msg *OutgoingMessage, data []byte) (*protectedIKEMessage, bool, error) {
	if msg.Exchange == ikev2.IKE_SA_INIT {
		if len(msg.Packets) != 1 {
			return nil, false, ikev2.ErrInitResponse
		}
		_, err := ikev2.DecodeInitResponse(data, msg.Packets[0])
		// This strictly rejected response only authorizes a fresh original-suite
		// retry. Deliver the typed error to Connect, never commit its SA state.
		var numbering *ikev2.InitProposalNumberError
		if errors.As(err, &numbering) {
			return nil, false, nil
		}
		return nil, err == nil, err
	}
	message, err := s.decodeProtectedIKE(data)
	if err == nil && message == nil {
		err = errFragmentIncomplete
	}
	return message, err == nil, err
}

package swu

import (
	"bytes"
	"errors"
	"strings"

	"github.com/1239t/swu-go/pkg/eap"
)

// ErrTemporaryIdentityStorage prevents sending a one-time identity without a
// confirmed retirement, and prevents accepting a failed private-state update.
// The underlying storage error is deliberately not exposed.
var ErrTemporaryIdentityStorage = errors.New("AKA temporary identity storage update failed")

// AKATemporaryIdentity is private, subscriber-scoped authentication material.
// Counter is the LAST successfully used counter (zero after full auth), not the
// next expected counter. Do not expose this object through logs or status APIs.
// Callers must bind storage to the SIM and authentication scope, serialize its
// ownership, and persist updates atomically before returning from the callback.
type AKATemporaryIdentity struct {
	Pseudonym string `json:"-"` // UTF-8 username only; the current home realm is appended on use.
	ReauthID  string `json:"-"`
	Counter   uint16 `json:"-"`
	MK        []byte `json:"-"`
	KAut      []byte `json:"-"`
	KEncr     []byte `json:"-"`
}

func (AKATemporaryIdentity) String() string   { return "[private AKA identity state]" }
func (AKATemporaryIdentity) GoString() string { return "[private AKA identity state]" }

func (v *AKATemporaryIdentity) clone() *AKATemporaryIdentity {
	if v == nil {
		return &AKATemporaryIdentity{}
	}
	return &AKATemporaryIdentity{Pseudonym: v.Pseudonym, ReauthID: v.ReauthID, Counter: v.Counter,
		MK: bytes.Clone(v.MK), KAut: bytes.Clone(v.KAut), KEncr: bytes.Clone(v.KEncr)}
}

func (s *Session) updateTemporaryIdentity(v *AKATemporaryIdentity) error {
	if s.ctx != nil && s.ctx.Err() != nil {
		return s.ctx.Err()
	}
	if update := s.cfg.OnTemporaryIdentityUpdate; update != nil {
		if err := update(v.clone()); err != nil {
			// Storage errors may contain private filenames or identifiers.
			return ErrTemporaryIdentityStorage
		}
	}
	return nil
}

func (s *Session) consumeFastIdentity() error {
	if s.akaFastConsumed {
		return nil
	}
	if s.cfg.OnTemporaryIdentityUpdate == nil && (s.akaHasTemporaryIdentity || s.cfg.OnFastReauthUpdate == nil) {
		return ErrTemporaryIdentityStorage
	}
	if err := s.updateTemporaryIdentity(&AKATemporaryIdentity{Pseudonym: s.akaPseudonym}); err != nil {
		return err
	}
	s.akaFastConsumed = true
	s.akaUsedFastID = s.fastReauthCtx.ReauthID
	if s.akaUsedFastID == "" && !s.akaHasTemporaryIdentity {
		s.akaUsedFastID = s.cfg.FastReauthID
	}
	if s.cfg.OnFastReauthUpdate != nil {
		s.cfg.OnFastReauthUpdate("", nil, nil, nil)
	}
	return nil
}

func (s *Session) selectAKAIdentity(request byte) ([]byte, error) {
	if (request == 0 || request == eap.AT_ANY_ID_REQ) && !s.akaPermanentIdentity && s.fastReauthCtx.CanUseReauth() {
		if err := s.consumeFastIdentity(); err != nil {
			return nil, err
		}
		return []byte(s.fastReauthCtx.ReauthID), nil
	}
	imsi, err := s.cfg.SIM.GetIMSI()
	if err != nil {
		return nil, err
	}
	if imsi == "" {
		return nil, errors.New("AKA permanent identity unavailable")
	}
	permanent := buildNAI(imsi, s.cfg)
	if request != eap.AT_PERMANENT_ID_REQ && s.akaPseudonym != "" {
		realm := strings.LastIndexByte(permanent, '@')
		if realm < 0 {
			return nil, errors.New("AKA pseudonym realm unavailable")
		}
		return []byte(s.akaPseudonym + permanent[realm:]), nil
	}
	return []byte(permanent), nil
}

func (s *Session) publishTemporaryIdentity() error {
	if s.akaPending == nil || !s.eapNotification.authenticated {
		return nil
	}
	pending := s.akaPending.clone()
	if err := s.updateTemporaryIdentity(pending); err != nil {
		return err
	}
	s.akaPending = nil
	s.akaPseudonym = pending.Pseudonym
	s.akaFastConsumed = false
	s.akaUsedFastID = ""
	s.akaPermanentIdentity = false
	s.fastReauthCtx = eap.NewFastReauthContext()
	if pending.ReauthID != "" {
		s.fastReauthCtx.SaveReauthData(pending.ReauthID, pending.MK, pending.KEncr, pending.KAut)
		s.fastReauthCtx.Counter = pending.Counter
	}
	if update := s.cfg.OnFastReauthUpdate; update != nil {
		// The legacy callback cannot represent a nonzero counter. It must not
		// persist a fast-auth identity as though it came from a new full auth.
		if pending.Counter == 0 {
			update(pending.ReauthID, bytes.Clone(pending.MK), bytes.Clone(pending.KAut), bytes.Clone(pending.KEncr))
		} else {
			update("", nil, nil, nil)
		}
	}
	return nil
}

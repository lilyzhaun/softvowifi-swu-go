package swu

import (
	"bytes"
	"crypto/sha1"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/1239t/swu-go/pkg/crypto"
	"github.com/1239t/swu-go/pkg/eap"
	"github.com/1239t/swu-go/pkg/ikev2"
	"go.uber.org/zap"
)

func syntheticTemporaryIdentity() *AKATemporaryIdentity {
	return &AKATemporaryIdentity{Pseudonym: "pseudonym", ReauthID: "reauth-synthetic@public.invalid", Counter: 20,
		MK: bytes.Repeat([]byte{0x11}, 20), KAut: bytes.Repeat([]byte{0x22}, 16), KEncr: bytes.Repeat([]byte{0x44}, 16)}
}

// Protocol-only fixtures acknowledge an in-memory retirement. The dedicated
// cross-Session tests below and in aka_temporary_connect_test own their state.
func acceptSyntheticTemporaryIdentity(*AKATemporaryIdentity) error { return nil }

func TestAKATemporaryIdentityConsumesBeforeActualIDiAndNeverReloadsOnReset(t *testing.T) {
	value := syntheticTemporaryIdentity()
	updates := 0
	cfg := &Config{SIM: issue25ReauthSIM{}, APN: "ims", TemporaryIdentity: value,
		OnTemporaryIdentityUpdate: func(next *AKATemporaryIdentity) error {
			updates++
			if next.ReauthID != "" || next.Counter != 0 || len(next.MK) != 0 || next.Pseudonym != value.Pseudonym {
				t.Fatal("one-time identity was not retired before exposure")
			}
			return nil
		}}
	s := NewSession(cfg, zap.NewNop())
	value.MK[0] ^= 1
	if s.fastReauthCtx.MK[0] != 0x11 || s.fastReauthCtx.Counter != 20 {
		t.Fatal("restored keys alias the caller or lose the last counter")
	}
	payloads, err := s.buildIKEAuthInitPayloads()
	if err != nil || updates != 1 {
		t.Fatal("actual AUTH1 did not synchronously consume the one-time identity")
	}
	if id := payloads[0].(*ikev2.EncryptedPayloadID); string(id.IDData) != value.ReauthID {
		t.Fatal("actual AUTH1 did not use the captured fast identity")
	}
	response := identityEAP(t, s, []byte{1, 1, 0, 5, 1})
	if string(response[5:]) != value.ReauthID || updates != 1 {
		t.Fatal("same exchange must reuse its already-consumed identity without consuming twice")
	}
	s.resetAKAIdentity()
	s.resetIKEAuthTranscripts()
	payloads, err = s.buildIKEAuthInitPayloads()
	wantPseudonym := value.Pseudonym + "@" + strings.SplitN(buildNAI("001010000000001", cfg), "@", 2)[1]
	if err != nil || string(payloads[0].(*ikev2.EncryptedPayloadID).IDData) != wantPseudonym || updates != 1 {
		t.Fatal("new attempt resurrected the one-time identity from immutable Config")
	}
}

func TestAKATemporaryIdentityStorageFailureStopsBeforeExposure(t *testing.T) {
	s := NewSession(&Config{SIM: issue25ReauthSIM{}, APN: "ims", TemporaryIdentity: syntheticTemporaryIdentity(),
		OnTemporaryIdentityUpdate: func(*AKATemporaryIdentity) error { return errors.New("PRIVATE-storage-path") }}, zap.NewNop())
	if payloads, err := s.buildIKEAuthInitPayloads(); err == nil || len(payloads) != 0 || strings.Contains(err.Error(), "PRIVATE") {
		t.Fatal("failed retirement exposed an identity or a private storage error")
	}
}

func TestAKATemporaryIdentityMethodRequestsSelectFastPseudonymPermanent(t *testing.T) {
	s := NewSession(&Config{SIM: issue25ReauthSIM{}, TemporaryIdentity: syntheticTemporaryIdentity(), OnTemporaryIdentityUpdate: acceptSyntheticTemporaryIdentity}, zap.NewNop())
	permanent := buildNAI("001010000000001", s.cfg)
	want := []string{"reauth-synthetic@public.invalid", "pseudonym@" + strings.SplitN(permanent, "@", 2)[1], permanent}
	for index, kind := range []byte{eap.AT_ANY_ID_REQ, eap.AT_FULLAUTH_ID_REQ, eap.AT_PERMANENT_ID_REQ} {
		got := identityEAP(t, s, identityRequest(byte(index), kind, 1, 0, 0))
		if !bytes.Equal(got, identityResponse(byte(index), want[index])) {
			t.Fatal("method identity did not respect the request category")
		}
	}
}

func TestAKATemporaryIdentityDoesNotAppearInFormattingOrJSON(t *testing.T) {
	v := syntheticTemporaryIdentity()
	raw, err := json.Marshal(v)
	if err != nil || string(raw) != "{}" {
		t.Fatal("private state was serialized by the default JSON encoder")
	}
	for _, text := range []string{fmt.Sprint(v), fmt.Sprintf("%+v", v), fmt.Sprintf("%#v", v)} {
		if strings.Contains(text, "public.invalid") || strings.Contains(text, "MK:") {
			t.Fatal("private state escaped through formatting")
		}
	}
}

func TestAKAFullAuthTemporaryIdentityRejectsCleartextAndStagesProtectedValues(t *testing.T) {
	for _, protected := range []bool{false, true} {
		t.Run(fmt.Sprint(protected), func(t *testing.T) {
			s, provider := identitySession(t)
			updates := 0
			s.cfg.OnFastReauthUpdate = func(string, []byte, []byte, []byte) { updates++ }
			keys := referenceAKAKeys(provider, false)
			base, err := eap.Parse(identityChallenge(t, keys[16:32], nil))
			if err != nil {
				t.Fatal(err)
			}
			var attrs []byte
			for offset := 0; offset < len(base.Data); {
				n := int(base.Data[offset+1]) * 4
				if base.Data[offset] != eap.AT_MAC {
					attrs = append(attrs, base.Data[offset:offset+n]...)
				}
				offset += n
			}
			inner := append(independentIdentityAttribute(eap.AT_NEXT_REAUTH_ID, "next@public.invalid"), independentIdentityAttribute(eap.AT_NEXT_PSEUDONYM, "pseudo")...)
			var raw []byte
			if protected {
				raw = independentProtectedAKARequest(t, 1, inner, keys[:16], keys[16:32], attrs)
			} else {
				attrs = append(attrs, inner...)
				attrs = append(attrs, eap.AT_MAC, 5, 0, 0)
				attrs = append(attrs, make([]byte, 16)...)
				raw = (&eap.EAPPacket{Code: 1, Identifier: 7, Type: 23, Subtype: 1, Data: attrs}).Encode()
				copy(raw[len(raw)-16:], independentType23ReauthRequestMAC(keys[16:32], raw))
			}
			payloads, err := s.handleEAP(raw)
			if !protected {
				if err == nil || len(payloads) != 0 || updates != 0 || len(s.MSK) != 0 {
					t.Fatal("cleartext next identity accepted or published")
				}
				return
			}
			if err != nil || len(payloads) != 1 || updates != 0 || s.fastReauthCtx.CanUseReauth() || s.akaPending == nil {
				t.Fatal("protected identity was not staged until final authentication")
			}
			if s.akaPending.ReauthID != "next@public.invalid" || s.akaPending.Pseudonym != "pseudo" || s.akaPending.Counter != 0 || !bytes.Equal(s.akaPending.KEncr, keys[:16]) {
				t.Fatal("protected temporary identities or full-auth keys differ")
			}
		})
	}
}

func TestAKAReauthTooSmallMustContinueWithFullChallengeNotSuccess(t *testing.T) {
	v := syntheticTemporaryIdentity()
	s := NewSession(&Config{SIM: issue25ReauthSIM{}, TemporaryIdentity: v}, zap.NewNop())
	s.akaIdentity.outer = []byte(v.ReauthID)
	_, err := s.handleEAP(encryptedReauthRequest(t, 20, bytes.Repeat([]byte{0x33}, 16), v.KEncr, v.KAut))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.handleEAP([]byte{3, 7, 0, 4}); err == nil {
		t.Fatal("counter fallback accepted EAP Success without full authentication")
	}
	// A separate fallback exchange can complete full auth using the same identity.
	s = NewSession(&Config{SIM: issue25ReauthSIM{}, TemporaryIdentity: v}, zap.NewNop())
	s.akaIdentity.outer = []byte(v.ReauthID)
	if _, err := s.handleEAP(encryptedReauthRequest(t, 20, bytes.Repeat([]byte{0x33}, 16), v.KEncr, v.KAut)); err != nil {
		t.Fatal(err)
	}
	h := sha1.New()
	h.Write([]byte(v.ReauthID))
	h.Write(bytes.Repeat([]byte{0x49}, 16))
	h.Write(bytes.Repeat([]byte{0x43}, 16))
	keys := crypto.NewFIPS1862PRFSHA1(h.Sum(nil)).Bytes(nil, 96)
	response, err := s.handleEAP(identityChallenge(t, keys[16:32], nil))
	if err != nil || len(response) != 1 || !bytes.Equal(s.MSK, keys[32:96]) {
		t.Fatal("protected counter fallback did not continue to full Challenge")
	}
}

func TestAKAFullChallengeRetransmissionDoesNotRepeatSIMOrPublish(t *testing.T) {
	s, provider := identitySession(t)
	keys := referenceAKAKeys(provider, false)
	raw := identityChallenge(t, keys[16:32], nil)
	first := identityEAP(t, s, raw)
	second := identityEAP(t, s, bytes.Clone(raw))
	if !bytes.Equal(first, second) || provider.calls != 1 || s.fastReauthCtx.CanUseReauth() {
		t.Fatal("retransmitted Challenge changed the reply, repeated SIM or published state")
	}
}

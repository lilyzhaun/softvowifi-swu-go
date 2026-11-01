package swu

import (
	"bytes"
	"crypto/sha1"
	"testing"

	"github.com/1239t/swu-go/pkg/eap"
	"github.com/1239t/swu-go/pkg/ikev2"
)

func TestAKATemporaryIdentityWithoutWriterCannotRepeatAcrossSessions(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		value := syntheticTemporaryIdentity()
		cfg := &Config{SIM: issue25ReauthSIM{}, APN: "ims", TemporaryIdentity: value}
		if legacy {
			cfg.TemporaryIdentity = nil
			cfg.FastReauthID, cfg.FastReauthMK = value.ReauthID, value.MK
			cfg.FastReauthKAut, cfg.FastReauthKEncr = value.KAut, value.KEncr
		}
		for range 2 {
			s := NewSession(cfg, nil)
			if payloads, err := s.buildIKEAuthInitPayloads(); err == nil || len(payloads) != 0 || len(s.localIDiBody) != 0 {
				t.Fatal("missing writer permitted a one-time identity to leave either Session")
			}
		}
	}
}

func TestAKAReauthTooSmallIgnoresNextIdentityContentsAndContinuesFull(t *testing.T) {
	v := syntheticTemporaryIdentity()
	s := NewSession(&Config{SIM: issue25ReauthSIM{}, TemporaryIdentity: v}, nil)
	s.akaIdentity.outer = []byte(v.ReauthID)
	nonce := bytes.Repeat([]byte{0x33}, 16)
	inner := append([]byte{eap.AT_COUNTER, 1, 0, 20, eap.AT_NONCE_S, 5, 0, 0}, nonce...)
	// Valid TLV, unusable identity content: MUST be ignored for too-small.
	inner = append(inner, eap.AT_NEXT_REAUTH_ID, 1, 0, 0)
	payloads, err := s.handleEAP(independentProtectedAKARequest(t, 13, inner, v.KEncr, v.KAut, nil))
	if err != nil {
		t.Fatal("too-small parsed the ignored next-identity content")
	}
	assertEncryptedReauthResponse(t, payloads, 20, nonce, v.KEncr, v.KAut, true)
	if len(s.MSK) != 0 || s.akaPending != nil {
		t.Fatal("too-small published fast keys or next identity")
	}
	// The real full-Challenge consumer must remain available in this exchange.
	_, provider := identitySession(t)
	s.cfg.SIM = provider
	h := sha1.New()
	h.Write([]byte(v.ReauthID))
	h.Write(provider.ik)
	h.Write(provider.ck)
	keys := referenceExpansion(h.Sum(nil))
	if response, err := s.handleEAP(identityChallenge(t, keys[16:32], nil)); err != nil || len(response) != 1 || !bytes.Equal(s.MSK, keys[32:96]) {
		t.Fatal("ignored next identity prevented full Challenge continuation")
	}
}

func TestAKAProtectedIdentityRejectsOversizedPaddingAndUnknownRequiredOuter(t *testing.T) {
	for _, scenario := range []string{"oversized-padding", "unknown-required"} {
		t.Run(scenario, func(t *testing.T) {
			s, provider := identitySession(t)
			keys := referenceAKAKeys(provider, false)
			base := identityChallenge(t, keys[16:32], nil)
			outer := bytes.Clone(base[8 : len(base)-20])
			inner := independentIdentityAttribute(eap.AT_NEXT_REAUTH_ID, "next@public.invalid")
			if scenario == "oversized-padding" {
				// A legal-size alignment followed by an oversized final zero padding.
				n := 32 - len(inner)%16
				inner = append(inner, eap.AT_PADDING, byte(n/4))
				inner = append(inner, make([]byte, n-2)...)
			} else {
				outer = append(outer, 100, 1, 0, 0)
			}
			if payloads, err := s.handleEAP(independentProtectedAKARequest(t, 1, inner, keys[:16], keys[16:32], outer)); err == nil || len(payloads) != 0 || s.akaPending != nil {
				t.Fatalf("invalid %s accepted in a protected identity Challenge", scenario)
			}
		})
	}
}

func TestAKADiagnosticMACBypassNeverDecryptsTemporaryIdentity(t *testing.T) {
	s, provider := identitySession(t)
	s.cfg.DisableEAPMACValidation = true
	keys := referenceAKAKeys(provider, false)
	base := identityChallenge(t, keys[16:32], nil)
	// Correct CBC envelope but invalid nested TLV. A diagnostic bypass must
	// ignore protected identity material entirely, not attempt to interpret it.
	inner := []byte{eap.AT_NEXT_REAUTH_ID, 0, 0, 0}
	raw := independentProtectedAKARequest(t, 1, inner, keys[:16], keys[16:32], base[8:len(base)-20])
	clear(raw[len(raw)-16:])
	if payloads, err := s.handleEAP(raw); err != nil || len(payloads) != 1 || s.akaPending != nil || s.eapNotification.authenticated {
		t.Fatal("diagnostic bypass interpreted encrypted identities or published authentication")
	}
}

func TestAKATemporaryIdentityCallbackMayReplaceTheCallerConfig(t *testing.T) {
	value := syntheticTemporaryIdentity()
	cfg := &Config{SIM: issue25ReauthSIM{}, APN: "ims", TemporaryIdentity: value}
	cfg.OnTemporaryIdentityUpdate = func(next *AKATemporaryIdentity) error {
		cfg.TemporaryIdentity = next.clone()
		// This returned object is caller-owned, not the Session's key slice.
		next.ReauthID = "mutated@public.invalid"
		return nil
	}
	s := NewSession(cfg, nil)
	payloads, err := s.buildIKEAuthInitPayloads()
	if err != nil || string(payloads[0].(*ikev2.EncryptedPayloadID).IDData) != value.ReauthID || cfg.TemporaryIdentity.ReauthID != "" {
		t.Fatal("retirement callback changed the in-flight captured identity")
	}
	next := NewSession(cfg, nil)
	payloads, err = next.buildIKEAuthInitPayloads()
	if err != nil || string(payloads[0].(*ikev2.EncryptedPayloadID).IDData) == value.ReauthID || next.fastReauthCtx.CanUseReauth() {
		t.Fatal("later Session resurrected the retired caller state")
	}
}

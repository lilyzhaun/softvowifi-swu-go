package swu

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/1239t/swu-go/pkg/ikev2"
	"go.uber.org/zap"
)

const policyIKE128 = "ike-cbc128-sha256-prfsha256-dh14"
const policyIKE256 = "ike-cbc256-sha256-prfsha256-dh14"
const policyESP128 = "esp-gcm128-noesn"

func TestProposalPolicyInvalidInputStopsBeforeSocket(t *testing.T) {
	for name, change := range map[string]func(*Config){
		"unknown-ike":     func(c *Config) { c.IKEProposals = []string{"not-a-suite"} },
		"unknown-child":   func(c *Config) { c.ESPProposals = []string{"not-a-suite"} },
		"empty-ike":       func(c *Config) { c.IKEProposals = []string{} },
		"empty-child":     func(c *Config) { c.ESPProposals = []string{} },
		"duplicate-ike":   func(c *Config) { c.IKEProposals = []string{policyIKE128, policyIKE128} },
		"duplicate-child": func(c *Config) { c.ESPProposals = []string{policyESP128, policyESP128} },
		"mixed-dh":        func(c *Config) { c.IKEProposals = []string{policyIKE128, "ike-cbc256-sha256-prfsha256-dh2"} },
		"conflicting-dh":  func(c *Config) { c.IKEProposals = []string{policyIKE128}; c.IKEDHGroup = 2 },
		"widening-combined": func(c *Config) {
			c.IKEProposals = []string{policyIKE128, "ike-cbc256-sha384-prfsha384-dh14"}
			c.IKEProposalLayout = "single-combined"
		},
		"unknown-layout":      func(c *Config) { c.IKEProposals = []string{policyIKE128}; c.IKEProposalLayout = "unknown" },
		"legacy-ike-number":   func(c *Config) { c.IKEProposals = []string{policyIKE128}; c.InitialIKEProposalNumber = 1 },
		"legacy-child-number": func(c *Config) { c.ESPProposals = []string{policyESP128}; c.InitialChildProposalNumber = 2 },
		"unsupported-esn":     func(c *Config) { c.ESPProposals = []string{policyESP128}; c.EnableESN = true },
	} {
		t.Run(name, func(t *testing.T) {
			opened := false
			c := &Config{EpDGAddr: "127.0.0.1", EpDGPort: 4501, LocalAddr: "127.0.0.1",
				SocketControl: func(string, string, syscall.RawConn) error { opened = true; return errors.New("socket reached") }}
			change(c)
			s := NewSession(c, zap.NewNop())
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			err := s.Connect(ctx)
			s.Shutdown()
			if opened || err == nil || !strings.Contains(err.Error(), "invalid proposal policy") {
				t.Fatal("invalid explicit policy did not fail before socket setup")
			}
		})
	}
}

func TestProposalPolicyCapturesOrderedCompleteSuitesAndCookie(t *testing.T) {
	c := &Config{LocalAddr: "127.0.0.1", EpDGAddr: "127.0.0.1", EpDGPort: 4501,
		IKEProposals: []string{policyIKE256, policyIKE128}, ESPProposals: []string{policyESP128}}
	s := NewSession(c, zap.NewNop())
	first, err := s.buildIKESAInitPacket()
	if err != nil {
		t.Fatal(err)
	}
	sa, ke, _ := decodeInitSA(t, first)
	if len(sa.Proposals) != 2 || ke.DHGroup != 14 {
		t.Fatal("explicit complete policy was ignored or aliased")
	}
	for n, bits := range []uint16{256, 128} {
		p := sa.Proposals[n]
		if p.ProposalNum != uint8(n+1) || len(p.Transforms) != 4 || p.Transforms[0].Attributes[0].Val != bits ||
			p.Transforms[1].ID != ikev2.AUTH_HMAC_SHA2_256_128 || p.Transforms[2].ID != ikev2.PRF_HMAC_SHA2_256 {
			t.Fatal("wire changed a complete suite or its order")
		}
	}
	// First protocol use captures the group. OnReady is intentionally assigned
	// after NewSession by existing callers, so Config itself stays caller-owned.
	c.IKEProposals[0], c.ESPProposals[0] = "not-a-suite", "not-a-suite"
	c.IKEProposalLayout, c.IKEDHGroup = "single-combined", 2
	c.FastReauthID = "synthetic@invalid"
	c.OnTemporaryIdentityUpdate = acceptSyntheticTemporaryIdentity
	payloads, err := s.buildIKEAuthInitPayloads()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, payload := range payloads {
		if child, ok := payload.(*ikev2.EncryptedPayloadSA); ok {
			found = len(child.Proposals) == 1 && child.Proposals[0].Transforms[0].ID == ikev2.ENCR_AES_GCM_16 &&
				child.Proposals[0].Transforms[0].Attributes[0].Val == 128
		}
	}
	if !found {
		t.Fatal("Child offer was not captured with the initial IKE policy")
	}
	s.cookie, s.sendCookie = []byte{1, 2, 3}, true
	retry, err := s.buildIKESAInitPacket()
	if err != nil {
		t.Fatal(err)
	}
	a, _ := ikev2.DecodePacket(first)
	b, _ := ikev2.DecodePacket(retry)
	if len(b.Payloads) != len(a.Payloads)+1 {
		t.Fatal("cookie changed payload count")
	}
	for n, pl := range a.Payloads {
		x, _ := pl.Encode()
		y, _ := b.Payloads[n+1].Encode()
		if !bytes.Equal(x, y) {
			t.Fatal("cookie widened or changed captured offer")
		}
	}
	proposals, err := s.localChildProposals([]byte{1, 2, 3, 4})
	if err == nil || proposals != nil {
		t.Fatal("rekey without an allowed negotiated suite was accepted")
	}
}

func TestProposalPolicyCombinedLayoutDoesNotCrossSuites(t *testing.T) {
	for _, dh := range []string{"14", "2"} {
		t.Run("dh"+dh, func(t *testing.T) {
			s := newInitTestSession("single-combined")
			s.cfg.IKEProposals = []string{"ike-cbc256-sha256-prfsha256-dh" + dh, "ike-cbc128-sha256-prfsha256-dh" + dh}
			raw, err := s.buildIKESAInitPacket()
			if err != nil {
				t.Fatal(err)
			}
			sa, ke, _ := decodeInitSA(t, raw)
			wantDH := uint16(14)
			if dh == "2" {
				wantDH = 2
			}
			if len(sa.Proposals) != 1 || len(sa.Proposals[0].Transforms) != 5 || uint16(ke.DHGroup) != wantDH {
				t.Fatal("lossless combined policy changed its exact alternatives or KE group")
			}
		})
	}
}

func TestProposalPolicyChildRekeyDoesNotRestoreDefaultAlternatives(t *testing.T) {
	s := newInitTestSession("")
	s.cfg.ESPProposals = []string{"esp-gcm256-noesn", "esp-cbc128-sha256-noesn", policyESP128}
	s.childEncrID, s.childIntegID, s.childEncrKeyLenBits = uint16(ikev2.ENCR_AES_CBC), uint16(ikev2.AUTH_HMAC_SHA2_256_128), 128
	got, err := s.localChildProposals([]byte{1, 2, 3, 4})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || !sameCompleteChildProposal(got[0], s.currentChildProposal(nil)) {
		t.Fatal("rekey broadened the policy")
	}
	if got[1].Transforms[0].ID != ikev2.ENCR_AES_GCM_16 || got[1].Transforms[0].Attributes[0].Val != 256 ||
		got[2].Transforms[0].Attributes[0].Val != 128 {
		t.Fatal("rekey reordered allowed alternatives")
	}
}

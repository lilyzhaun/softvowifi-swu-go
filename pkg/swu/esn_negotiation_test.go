package swu

import (
	"strconv"
	"strings"
	"testing"

	"github.com/1239t/swu-go/pkg/ikev2"
)

func esnSelectedProposal(number uint8, value ikev2.AlgorithmType) *ikev2.Proposal {
	p := ikev2.CreateMultiProposalESP([]byte{0x22, 0x22, 0x22, 0x22})[number-1]
	for _, transform := range p.Transforms {
		if transform.Type == ikev2.TransformTypeESN {
			transform.ID = value
		}
	}
	return p
}

func TestESNInitialAUTHCapturesModeInEncodedOffer(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(strconv.FormatBool(enabled), func(t *testing.T) {
			s, _ := newPostEAPSession(t, func(c *Config) { c.EnableESN = enabled })
			// The first real builder already captured this policy. Neither this
			// later mutation nor a second build may change an existing owner.
			s.cfg.EnableESN = !enabled
			if _, err := s.buildIKEAuthInitPayloads(); err != nil {
				t.Fatal(err)
			}
			request, err := ikev2.DecodePacket(s.initialChildRequest)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, payload := range request.Payloads {
				if sa, ok := payload.(*ikev2.EncryptedPayloadSA); ok {
					found = true
					if len(sa.Proposals) != 6 {
						t.Fatal("legacy mode changed the original complete suite count")
					}
					for _, p := range sa.Proposals {
						count := 0
						for _, transform := range p.Transforms {
							if transform.Type == ikev2.TransformTypeESN {
								count++
								if (transform.ID == 1) != enabled || transform.ID > 1 || len(transform.Attributes) != 0 {
									t.Fatal("actual encoded AUTH offer did not capture the requested ESN mode")
								}
							}
						}
						if count != 1 {
							t.Fatal("complete ESP proposal must have one explicit ESN transform")
						}
					}
				}
			}
			if !found {
				t.Fatal("actual AUTH request has no ESP offer")
			}
		})
	}
}

func TestESNAuthenticatedInitialSelectionCommitsBothSAs(t *testing.T) {
	for number := uint8(1); number <= 6; number++ {
		t.Run(strconv.Itoa(int(number)), func(t *testing.T) {
			s, _ := newPostEAPSession(t, func(c *Config) { c.EnableESN = true })
			s.cfg.EnableESN = false
			payloads := childTransactionPayloads(t, s)
			payloads[3] = &ikev2.EncryptedPayloadSA{Proposals: []*ikev2.Proposal{esnSelectedProposal(number, 1)}}
			if err := s.handleIKEAuthFinalResp(encodePeerPacket(t, s, payloads, ikev2.IKE_AUTH, 3, true)); err != nil {
				t.Fatalf("real protected final AUTH rejected a captured ESN selection: %v", err)
			}
			if !s.childESN || s.ChildSAOut == nil || s.ChildSAIn == nil || !s.ChildSAOut.ESN || !s.ChildSAIn.ESN {
				t.Fatal("authenticated ESN selection did not reach both actual ESP consumers")
			}
		})
	}
}

func TestESNInitialDowngradeAndUnrecognizedModeNeverCommit(t *testing.T) {
	for _, mode := range []ikev2.AlgorithmType{0, 2} {
		t.Run(strconv.Itoa(int(mode)), func(t *testing.T) {
			s, calls := newPostEAPSession(t, func(c *Config) { c.EnableESN = true })
			before := snapPostEAP(s, *calls)
			payloads := childTransactionPayloads(t, s)
			payloads[3] = &ikev2.EncryptedPayloadSA{Proposals: []*ikev2.Proposal{esnSelectedProposal(3, mode)}}
			if err := s.handleIKEAuthFinalResp(encodePeerPacket(t, s, payloads, ikev2.IKE_AUTH, 3, true)); err == nil {
				t.Fatal("unoffered ESN downgrade or unsupported mode was committed")
			}
			assertSnapUnchanged(t, before, snapPostEAP(s, *calls))
			if s.ChildSAIn != nil || s.ChildSAOut != nil || s.childESN {
				t.Fatal("rejected ESN transaction changed Child state")
			}
		})
	}
}

func TestESNExplicitCompleteSuiteNamesRemainIndependentOfPFS(t *testing.T) {
	for _, name := range []string{"esp-gcm256-noesn", "esp-gcm128-noesn", "esp-cbc256-sha256-noesn", "esp-cbc128-sha256-noesn", "esp-cbc128-sha1-noesn", "esp-cbc256-sha512-noesn"} {
		for _, pfs := range []uint16{0, 14} {
			t.Run(name+"/"+strconv.Itoa(int(pfs)), func(t *testing.T) {
				c := &Config{ESPProposals: []string{strings.TrimSuffix(name, "noesn") + "esn"}, ChildPFSGroup: pfs}
				if err := c.ValidateProposalPolicy(); err != nil {
					t.Fatal("supported explicit ESN complete suite was rejected")
				}
			})
		}
	}
}

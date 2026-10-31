package swu

import (
	"strconv"
	"testing"

	"github.com/1239t/swu-go/pkg/ikev2"
)

func TestProposalPolicyAllIKEIDsHaveExactWireTuples(t *testing.T) {
	for _, suite := range []struct {
		name             string
		bits, integ, prf uint16
	}{
		{"ike-cbc128-sha256-prfsha256", 128, 12, 5},
		{"ike-cbc256-sha384-prfsha384", 256, 13, 6},
		{"ike-cbc128-sha1-prfsha1", 128, 2, 2},
		{"ike-cbc256-sha256-prfsha256", 256, 12, 5},
	} {
		for _, dh := range []uint16{2, 14} {
			name := suite.name + "-dh" + strconv.Itoa(int(dh))
			t.Run(name, func(t *testing.T) {
				s := newInitTestSession("")
				s.cfg.IKEProposals = []string{name}
				wire, err := s.buildIKESAInitPacket()
				if err != nil {
					t.Fatal(err)
				}
				sa, ke, _ := decodeInitSA(t, wire)
				if len(sa.Proposals) != 1 || sa.Proposals[0].ProposalNum != 1 || uint16(ke.DHGroup) != dh {
					t.Fatal("explicit IKE selection did not reach SA/KE")
				}
				policyAssertTransforms(t, sa.Proposals[0], [][3]uint16{{1, 12, suite.bits}, {3, suite.integ, 0}, {2, suite.prf, 0}, {4, dh, 0}})
			})
		}
	}
}

func TestProposalPolicyAllChildIDsHaveExactWireTuples(t *testing.T) {
	for _, suite := range []struct {
		name              string
		encr, bits, integ uint16
	}{
		{"esp-gcm256-noesn", 20, 256, 0}, {"esp-gcm128-noesn", 20, 128, 0},
		{"esp-cbc256-sha256-noesn", 12, 256, 12}, {"esp-cbc128-sha256-noesn", 12, 128, 12},
		{"esp-cbc128-sha1-noesn", 12, 128, 2}, {"esp-cbc256-sha512-noesn", 12, 256, 14},
	} {
		t.Run(suite.name, func(t *testing.T) {
			s := newInitTestSession("")
			s.cfg.ESPProposals, s.cfg.FastReauthID = []string{suite.name}, "synthetic@invalid"
			payloads, err := s.buildIKEAuthInitPayloads()
			if err != nil {
				t.Fatal(err)
			}
			for _, pl := range payloads {
				if sa, ok := pl.(*ikev2.EncryptedPayloadSA); ok {
					encoded, err := sa.Encode()
					if err != nil {
						t.Fatal(err)
					}
					decoded, err := ikev2.DecodePayloadSA(encoded)
					if err != nil {
						t.Fatal(err)
					}
					if len(decoded.Proposals) != 1 || decoded.Proposals[0].ProposalNum != 1 || len(decoded.Proposals[0].SPI) != 4 {
						t.Fatal("Child selection did not reach encoded AUTH payload")
					}
					expected := [][3]uint16{{1, suite.encr, suite.bits}}
					if suite.integ != 0 {
						expected = append(expected, [3]uint16{3, suite.integ, 0})
					}
					policyAssertTransforms(t, decoded.Proposals[0], append(expected, [3]uint16{5, 0, 0}))
					return
				}
			}
			t.Fatal("Child SA missing from AUTH")
		})
	}
}

func policyAssertTransforms(t *testing.T, p *ikev2.Proposal, expected [][3]uint16) {
	t.Helper()
	if len(p.Transforms) != len(expected) {
		t.Fatal("unexpected transform count")
	}
	for n, tr := range p.Transforms {
		want := expected[n]
		if uint16(tr.Type) != want[0] || uint16(tr.ID) != want[1] {
			t.Fatal("wire transform differs from independent tuple")
		}
		if want[2] == 0 {
			if len(tr.Attributes) != 0 {
				t.Fatal("unexpected transform attribute")
			}
		} else if len(tr.Attributes) != 1 || tr.Attributes[0].Type != 14 || tr.Attributes[0].Val != want[2] {
			t.Fatal("wire key length differs from independent tuple")
		}
	}
}

func TestProposalPolicyEncryptedChildRekeyCommitsOnlyAnAllowedSuite(t *testing.T) {
	for _, reject := range []bool{false, true} {
		t.Run(strconv.FormatBool(reject), func(t *testing.T) {
			s, pipe := childRekeySession(t)
			s.cfg.ESPProposals = []string{"esp-cbc128-sha256-noesn", policyESP128}
			before := snapshotChildRekey(s)
			err := exerciseChildRekey(t, s, s.RekeyChildSA, func(payloads []ikev2.Payload) []ikev2.Payload {
				if reject {
					// Valid in the old default offer, excluded by this policy.
					sa := payloads[0].(*ikev2.EncryptedPayloadSA)
					sa.Proposals[0] = ikev2.CreateMultiProposalESP(sa.Proposals[0].SPI)[5]
				}
				return payloads
			})
			if reject {
				if err == nil {
					t.Fatal("rekey accepted an excluded default suite")
				}
				before.assertUncommitted(t, s)
				if len(pipe.sent) != 0 {
					t.Fatal("rejected policy retired the existing Child")
				}
			} else if err != nil || s.ChildSAOut == before.out || s.childEncrID != 12 || s.childEncrKeyLenBits != 128 || s.childIntegID != 12 {
				t.Fatal("allowed protected rekey did not commit its negotiated suite")
			}
		})
	}
}

package swu

import (
	"fmt"
	"testing"

	"github.com/1239t/swu-go/pkg/ikev2"
)

// RFC7296 1.2 permits DH=NONE in the initial IKE_AUTH SA, although it
// recommends omitting that optional transform. No extra KE is negotiated.
func TestInitialChildExplicitDHNoneInAUTHIsLegal(t *testing.T) {
	for number := uint8(1); number <= 6; number++ {
		t.Run(fmt.Sprint(number), func(t *testing.T) {
			s, _ := newPostEAPSession(t)
			payloads := childTransactionPayloads(t, s)
			proposal := ikev2.CreateMultiProposalESP([]byte{0x22, 0x22, 0x22, 0x22})[number-1]
			proposal.AddTransform(ikev2.TransformTypeDH, 0, 0)
			payloads[3] = &ikev2.EncryptedPayloadSA{Proposals: []*ikev2.Proposal{proposal}}
			wire := encodePeerPacket(t, s, payloads, ikev2.IKE_AUTH, 3, true)
			if err := s.handleIKEAuthFinalResp(wire); err != nil {
				t.Fatalf("legal explicit DH=NONE rejected: %v", err)
			}
			if s.ChildSAIn == nil || s.ChildSAOut == nil || s.cpConfig == nil || s.childESN || s.childEncrID != uint16(proposal.Transforms[0].ID) {
				t.Fatal("optional NONE changed the original suite or prevented complete commit")
			}
		})
	}
}

func TestInitialChildDHNoneWithAttributesNeverCommits(t *testing.T) {
	s, calls := newPostEAPSession(t)
	payloads := childTransactionPayloads(t, s)
	p := payloads[3].(*ikev2.EncryptedPayloadSA).Proposals[0]
	p.AddTransform(ikev2.TransformTypeDH, 0, 0)
	p.Transforms[len(p.Transforms)-1].Attributes = []*ikev2.TransformAttribute{{Type: ikev2.AttributeKeyLength, Val: 256}}
	before := snapPostEAP(s, *calls)
	if err := s.handleIKEAuthFinalResp(encodePeerPacket(t, s, payloads, ikev2.IKE_AUTH, 3, true)); err == nil {
		t.Fatal("attributed DH=NONE accepted")
	}
	assertSnapUnchanged(t, before, snapPostEAP(s, *calls))
}

func TestInitialChildDuplicateDHNoneNeverCommits(t *testing.T) {
	s, calls := newPostEAPSession(t)
	payloads := childTransactionPayloads(t, s)
	p := payloads[3].(*ikev2.EncryptedPayloadSA).Proposals[0]
	p.AddTransform(ikev2.TransformTypeDH, 0, 0)
	p.AddTransform(ikev2.TransformTypeDH, 0, 0)
	before := snapPostEAP(s, *calls)
	if err := s.handleIKEAuthFinalResp(encodePeerPacket(t, s, payloads, ikev2.IKE_AUTH, 3, true)); err == nil {
		t.Fatal("duplicate optional DH=NONE accepted")
	}
	assertSnapUnchanged(t, before, snapPostEAP(s, *calls))
}

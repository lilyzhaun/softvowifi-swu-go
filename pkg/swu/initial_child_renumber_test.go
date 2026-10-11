package swu

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/1239t/swu-go/pkg/ikev2"
)

func TestInitialChildRenumberedCompleteOfferIsRejectedWithFreshRetryHint(t *testing.T) {
	s, calls := newPostEAPSession(t)
	payloads := childTransactionPayloads(t, s)
	p := payloads[3].(*ikev2.EncryptedPayloadSA).Proposals[0]
	p.ProposalNum = 1
	before := snapPostEAP(s, *calls)
	err := s.handleIKEAuthFinalResp(encodePeerPacket(t, s, payloads, ikev2.IKE_AUTH, 3, true))
	var hint *InitialChildProposalNumberError
	if err == nil || !strings.Contains(err.Error(), "initial Child proposal numbering mismatch") {
		t.Fatalf("complete rejected third offer lacks fresh retry eligibility: %v", err)
	}
	if !errors.Is(err, errInitialChild) || !errors.As(err, &hint) || hint.OfferedNumber != 3 {
		t.Fatal("numbering hint lost strict rejection or original suite")
	}
	assertSnapUnchanged(t, before, snapPostEAP(s, *calls))
}

func TestInitialChildFreshSingleOfferKeepsTheOriginalSuite(t *testing.T) {
	s, _ := newPostEAPSession(t)
	original, err := s.buildIKEAuthInitPayloads()
	if err != nil {
		t.Fatal(err)
	}
	s.cfg.InitialChildProposalNumber = 3
	single, err := s.buildIKEAuthInitPayloads()
	if err != nil {
		t.Fatal(err)
	}
	var oldOffer *ikev2.EncryptedPayloadSA
	for _, payload := range original {
		if sa, ok := payload.(*ikev2.EncryptedPayloadSA); ok {
			oldOffer = sa
		}
	}
	for index, payload := range single {
		if sa, ok := payload.(*ikev2.EncryptedPayloadSA); ok {
			if len(sa.Proposals) != 1 || sa.Proposals[0].ProposalNum != 1 || !reflect.DeepEqual(sa.Proposals[0].Transforms, oldOffer.Proposals[2].Transforms) {
				t.Fatal("single retry did not keep original complete third ESP offer")
			}
		} else if !reflect.DeepEqual(payload, original[index]) {
			t.Fatal("single Child offer changed identity, CP, TS or notifications")
		}
	}
	payloads := childTransactionPayloads(t, s)
	payloads[3].(*ikev2.EncryptedPayloadSA).Proposals[0].ProposalNum = 1
	if err := s.handleIKEAuthFinalResp(encodePeerPacket(t, s, payloads, ikev2.IKE_AUTH, 3, true)); err != nil {
		t.Fatalf("fresh correctly numbered complete offer was rejected: %v", err)
	}
}

func TestInitialChildRenumberHintRequiresTheWholeAuthenticatedTransaction(t *testing.T) {
	for _, variant := range []string{"wrong key length", "missing ESN", "nonzero DH", "bad CP", "foreign TSi", "bad notification", "bad responder AUTH", "arbitrary number"} {
		t.Run(variant, func(t *testing.T) {
			s, calls := newPostEAPSession(t)
			payloads := childTransactionPayloads(t, s)
			p := payloads[3].(*ikev2.EncryptedPayloadSA).Proposals[0]
			p.ProposalNum = 1
			switch variant {
			case "wrong key length":
				p.Transforms[0].Attributes[0].Val = 192
			case "missing ESN":
				p.Transforms = p.Transforms[:2]
			case "nonzero DH":
				p.AddTransform(ikev2.TransformTypeDH, ikev2.MODP_2048_bit, 0)
			case "bad CP":
				payloads[2].(*ikev2.EncryptedPayloadCP).Attributes[0].Value = []byte{192, 0, 2}
			case "foreign TSi":
				payloads[4].(*ikev2.EncryptedPayloadTS).TrafficSelectors[0].StartAddr = []byte{192, 0, 2, 99}
			case "bad notification":
				payloads = append(payloads, &ikev2.EncryptedPayloadNotify{NotifyType: ikev2.AUTH_LIFETIME, NotifyData: []byte{1}})
			case "bad responder AUTH":
				payloads[1].(*ikev2.EncryptedPayloadAuth).AuthData[0] ^= 1
			case "arbitrary number":
				p.ProposalNum = 99
			}
			before := snapPostEAP(s, *calls)
			err := s.handleIKEAuthFinalResp(encodePeerPacket(t, s, payloads, ikev2.IKE_AUTH, 3, true))
			if err == nil || strings.Contains(err.Error(), "initial Child proposal numbering mismatch") {
				t.Fatalf("invalid transaction gained retry eligibility: %v", err)
			}
			assertSnapUnchanged(t, before, snapPostEAP(s, *calls))
		})
	}
}

package swu

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/1239t/swu-go/pkg/ikev2"
)

func Test_InitRenumberedCompleteOfferRemainsRejectedWithRetryHint(t *testing.T) {
	sess, response := initSelectionFixture(t)
	offered, _, _ := decodeInitSA(t, sess.msgBuffer)
	chosen := *offered.Proposals[3]
	chosen.ProposalNum = 1
	response.Payloads[0] = &ikev2.EncryptedPayloadSA{Proposals: []*ikev2.Proposal{&chosen}}
	raw, err := response.Encode()
	if err != nil {
		t.Fatal(err)
	}
	err = sess.handleIKESAInitResp(raw, sess.msgBuffer)
	if !errors.Is(err, ikev2.ErrInitResponse) || !strings.Contains(err.Error(), "proposal number mismatch (offered 4)") {
		t.Fatalf("expected rejected complete-offer retry hint, got %v", err)
	}
	var hint *ikev2.InitProposalNumberError
	if !errors.As(err, &hint) || hint.OfferedNumber != 4 {
		t.Fatalf("missing typed complete-offer hint: %v", err)
	}
	if sess.SPIr != 0 || sess.Keys != nil || sess.PRFAlg != nil || len(sess.nr) != 0 {
		t.Fatal("renumbered response committed unvalidated SA")
	}
}

func Test_InitSingleOriginalOfferUsesCorrectNumberWithoutNewTransforms(t *testing.T) {
	sess := newInitTestSession("")
	original, err := sess.buildIKESAInitPacket()
	if err != nil {
		t.Fatal(err)
	}
	before, err := ikev2.DecodePacket(original)
	if err != nil {
		t.Fatal(err)
	}
	sess.cfg.InitialIKEProposalNumber = 4
	retry, err := sess.buildIKESAInitPacket()
	if err != nil {
		t.Fatal(err)
	}
	after, err := ikev2.DecodePacket(retry)
	if err != nil {
		t.Fatal(err)
	}
	proposals := after.Payloads[0].(*ikev2.EncryptedPayloadSA).Proposals
	if len(proposals) != 1 || proposals[0].ProposalNum != 1 {
		t.Fatalf("single-offer retry proposals: %+v", proposals)
	}
	want := *before.Payloads[0].(*ikev2.EncryptedPayloadSA).Proposals[3]
	want.ProposalNum = 1
	wantWire, err := (&ikev2.EncryptedPayloadSA{Proposals: []*ikev2.Proposal{&want}}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	gotWire, err := after.Payloads[0].Encode()
	if err != nil || !bytes.Equal(wantWire, gotWire) {
		t.Fatal("single offer changed the complete original suite")
	}
	if before.Header.SPIi != after.Header.SPIi || len(before.Payloads) != len(after.Payloads) {
		t.Fatal("builder changed unrelated init fields")
	}
	for index := 1; index < len(before.Payloads); index++ {
		want, err := before.Payloads[index].Encode()
		if err != nil {
			t.Fatal(err)
		}
		got, err := after.Payloads[index].Encode()
		if err != nil || !bytes.Equal(want, got) {
			t.Fatalf("unrelated payload %d changed", index)
		}
	}
}

func Test_InitRenumberHintDoesNotMaskOtherInvalidSelections(t *testing.T) {
	for name, mutate := range map[string]func(*ikev2.IKEPacket){
		"unknown proposal number": func(p *ikev2.IKEPacket) { selectedInitProposal(p).ProposalNum = 99 },
		"another proposal number": func(p *ikev2.IKEPacket) { selectedInitProposal(p).ProposalNum = 2 },
		"foreign SPI":             func(p *ikev2.IKEPacket) { p.Header.SPIi++ },
		"zero responder SPI":      func(p *ikev2.IKEPacket) { p.Header.SPIr = 0 },
		"cross-offer hybrid":      func(p *ikev2.IKEPacket) { selectedInitProposal(p).Transforms[2].ID = 6 },
		"short nonce":             func(p *ikev2.IKEPacket) { p.Payloads[2].(*ikev2.EncryptedPayloadNonce).NonceData = []byte{1} },
		"invalid DH":              func(p *ikev2.IKEPacket) { p.Payloads[1].(*ikev2.EncryptedPayloadKE).KEData = make([]byte, 256) },
		"weak DH":                 func(p *ikev2.IKEPacket) { p.Payloads[1].(*ikev2.EncryptedPayloadKE).DHGroup = 2 },
		"extra SA":                func(p *ikev2.IKEPacket) { p.Payloads = append(p.Payloads, p.Payloads[0]) },
		"cookie with selection": func(p *ikev2.IKEPacket) {
			p.Payloads = append(p.Payloads, &ikev2.EncryptedPayloadNotify{NotifyType: ikev2.COOKIE, NotifyData: []byte{1}})
		},
	} {
		t.Run(name, func(t *testing.T) {
			sess, response := initSelectionFixture(t)
			offered, _, _ := decodeInitSA(t, sess.msgBuffer)
			chosen := *offered.Proposals[3]
			chosen.ProposalNum = 1
			response.Payloads[0] = &ikev2.EncryptedPayloadSA{Proposals: []*ikev2.Proposal{&chosen}}
			mutate(response)
			raw, err := response.Encode()
			if err != nil {
				t.Fatal(err)
			}
			err = sess.handleIKESAInitResp(raw, sess.msgBuffer)
			var hint *ikev2.InitProposalNumberError
			if !errors.Is(err, ikev2.ErrInitResponse) || errors.As(err, &hint) {
				t.Fatalf("invalid response incorrectly eligible for retry: %v", err)
			}
			if sess.SPIr != 0 || sess.Keys != nil || sess.PRFAlg != nil || len(sess.nr) != 0 {
				t.Fatal("invalid response mutated session")
			}
		})
	}
}

func Test_InitSingleOriginalOfferRejectsMissingOrCombinedProposal(t *testing.T) {
	for _, layout := range []string{"multiple-complete", "single-combined"} {
		for _, number := range []uint8{1, 4, 99} {
			if layout == "multiple-complete" && number != 99 {
				continue
			}
			sess := newInitTestSession(layout)
			sess.cfg.InitialIKEProposalNumber = number
			if _, err := sess.buildIKESAInitPacket(); err == nil {
				t.Fatalf("accepted non-complete original proposal %d in %s", number, layout)
			}
		}
	}
}

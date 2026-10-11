package swu

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"testing"

	"github.com/1239t/swu-go/pkg/ikev2"
)

func childPrivateCPPayloads(t *testing.T, s *Session, size int) []ikev2.Payload {
	t.Helper()
	payloads := childTransactionPayloads(t, s)
	v6 := net.ParseIP("2001:db8::10").To16()
	cp := payloads[2].(*ikev2.EncryptedPayloadCP)
	cp.Attributes = []*ikev2.CPAttribute{
		{Type: ikev2.INTERNAL_IP6_ADDRESS, Value: append(bytes.Clone(v6), 64)},
		{Type: ikev2.P_CSCF_IP6_ADDRESS, Value: net.ParseIP("2001:db8::9").To16()},
		{Type: ikev2.P_CSCF_IP6_ADDRESS, Value: net.ParseIP("2001:db8::19").To16()},
		{Type: ikev2.ASSIGNED_PCSCF_IP6_ADDRESS, Value: bytes.Repeat([]byte{0x77}, size)},
		{Type: ikev2.ASSIGNED_PCSCF_IP6_ADDRESS, Value: bytes.Repeat([]byte{0x88}, size)},
	}
	p := ikev2.CreateMultiProposalESP([]byte{0x22, 0x22, 0x22, 0x22})[3]
	payloads[3] = &ikev2.EncryptedPayloadSA{Proposals: []*ikev2.Proposal{p}}
	payloads[4].(*ikev2.EncryptedPayloadTS).TrafficSelectors = []*ikev2.TrafficSelector{ikev2.NewTrafficSelectorIPV6(v6, v6, 0, 65535)}
	payloads[5].(*ikev2.EncryptedPayloadTS).TrafficSelectors = []*ikev2.TrafficSelector{ikev2.NewTrafficSelectorIPV6(net.IPv6zero, bytes.Repeat([]byte{255}, 16), 0, 65535)}
	return payloads
}

func TestInitialChildUnsupportedPrivateCPDoesNotRejectStandardConfiguration(t *testing.T) {
	for _, mode := range []string{"original number", "renumbered rejected hint", "fresh single offer"} {
		for _, size := range []int{0, 1, 15, 17, 32} {
			t.Run(fmt.Sprintf("%s/%d", mode, size), func(t *testing.T) {
				s, calls := newPostEAPSession(t)
				if mode == "fresh single offer" {
					s.cfg.InitialChildProposalNumber = 4
					if _, err := s.buildIKEAuthInitPayloads(); err != nil {
						t.Fatal(err)
					}
				}
				payloads := childPrivateCPPayloads(t, s, size)
				if mode != "original number" {
					payloads[3].(*ikev2.EncryptedPayloadSA).Proposals[0].ProposalNum = 1
				}
				before := snapPostEAP(s, *calls)
				err := s.handleIKEAuthFinalResp(encodePeerPacket(t, s, payloads, ikev2.IKE_AUTH, 3, true))
				if mode == "renumbered rejected hint" {
					var hint *InitialChildProposalNumberError
					if !errors.Is(err, errInitialChild) || !errors.As(err, &hint) || hint.OfferedNumber != 4 {
						t.Fatalf("unsupported private CP suppressed otherwise complete fresh retry hint: %v", err)
					}
					assertSnapUnchanged(t, before, snapPostEAP(s, *calls))
					return
				}
				if err != nil {
					t.Fatalf("unsupported private CP rejected complete standard transaction: %v", err)
				}
				if s.ChildSAIn == nil || s.ChildSAOut == nil || len(s.cpConfig.IPv6PCSCF) != 2 || !s.cpConfig.IPv6PCSCF[0].Equal(net.ParseIP("2001:db8::9")) || len(s.cpConfig.IPv4Addresses) != 0 || len(s.tsi) != 1 || len(s.tsr) != 1 {
					t.Fatal("standard IPv6 state was lost or private format consumed")
				}
			})
		}
	}
}

func TestInitialChildPrivateCPDoesNotBypassStandardOrAuthenticationChecks(t *testing.T) {
	for _, variant := range []string{"standard DNS short", "standard P-CSCF long", "standard DHCP long", "bad address prefix", "bad AUTH", "foreign TSi", "missing ESN", "unoffered key length", "bad notification"} {
		t.Run(variant, func(t *testing.T) {
			s, calls := newPostEAPSession(t)
			payloads := childPrivateCPPayloads(t, s, 17)
			payloads[3].(*ikev2.EncryptedPayloadSA).Proposals[0].ProposalNum = 1
			cp := payloads[2].(*ikev2.EncryptedPayloadCP)
			switch variant {
			case "standard DNS short":
				cp.Attributes = append(cp.Attributes, &ikev2.CPAttribute{Type: ikev2.INTERNAL_IP6_DNS, Value: make([]byte, 15)})
			case "standard P-CSCF long":
				cp.Attributes[1].Value = append(cp.Attributes[1].Value, 64)
			case "standard DHCP long":
				cp.Attributes = append(cp.Attributes, &ikev2.CPAttribute{Type: ikev2.INTERNAL_IP6_DHCP, Value: make([]byte, 17)})
			case "bad address prefix":
				cp.Attributes[0].Value[16] = 129
			case "bad AUTH":
				payloads[1].(*ikev2.EncryptedPayloadAuth).AuthData[0] ^= 1
			case "foreign TSi":
				tsi := payloads[4].(*ikev2.EncryptedPayloadTS).TrafficSelectors[0]
				tsi.StartAddr = net.ParseIP("2001:db8::99").To16()
				tsi.EndAddr = bytes.Clone(tsi.StartAddr)
			case "missing ESN":
				p := payloads[3].(*ikev2.EncryptedPayloadSA).Proposals[0]
				p.Transforms = p.Transforms[:2]
			case "unoffered key length":
				payloads[3].(*ikev2.EncryptedPayloadSA).Proposals[0].Transforms[0].Attributes[0].Val = 192
			case "bad notification":
				payloads = append(payloads, &ikev2.EncryptedPayloadNotify{NotifyType: ikev2.AUTH_LIFETIME, NotifyData: []byte{1}})
			}
			before := snapPostEAP(s, *calls)
			err := s.handleIKEAuthFinalResp(encodePeerPacket(t, s, payloads, ikev2.IKE_AUTH, 3, true))
			var hint *InitialChildProposalNumberError
			if err == nil || errors.As(err, &hint) {
				t.Fatalf("invalid transaction was accepted or gained a retry hint: %v", err)
			}
			assertSnapUnchanged(t, before, snapPostEAP(s, *calls))
		})
	}
}

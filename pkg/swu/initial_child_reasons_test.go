package swu

import (
	"errors"
	"strings"
	"testing"

	"github.com/1239t/swu-go/pkg/ikev2"
)

func TestInitialChildRejectionNamesFailedInvariantWithoutValues(t *testing.T) {
	for _, variant := range []struct{ name, reason string }{
		{"number", "proposal number"}, {"integrity", "transform count"}, {"CP length", "CP address length"}, {"TSi host", "TSi assigned address"},
	} {
		t.Run(variant.name, func(t *testing.T) {
			s, _ := newPostEAPSession(t)
			payloads := childTransactionPayloads(t, s)
			switch variant.name {
			case "number":
				payloads[3].(*ikev2.EncryptedPayloadSA).Proposals[0].ProposalNum = 99
			case "integrity":
				p := payloads[3].(*ikev2.EncryptedPayloadSA).Proposals[0]
				p.Transforms = p.Transforms[:1]
			case "CP length":
				payloads[2].(*ikev2.EncryptedPayloadCP).Attributes[0].Value = []byte{192, 0, 2}
			case "TSi host":
				ts := payloads[4].(*ikev2.EncryptedPayloadTS).TrafficSelectors[0]
				ts.StartAddr = []byte{192, 0, 2, 11}
				ts.EndAddr = []byte{192, 0, 2, 11}
			}
			err := s.handleIKEAuthFinalResp(encodePeerPacket(t, s, payloads, ikev2.IKE_AUTH, 3, true))
			if !errors.Is(err, errInitialChild) || !strings.Contains(err.Error(), variant.reason) {
				t.Fatalf("missing precise rejection reason: %v", err)
			}
			for _, value := range []string{"192.0.2", testIDrFQDN, string(s.MSK), "ticket"} {
				if strings.Contains(err.Error(), value) {
					t.Fatal("rejection exposed private protocol value")
				}
			}
		})
	}
}

func TestInitialChildSourceRejectionNamesAllocationFamily(t *testing.T) {
	for _, allocated := range []bool{true, false} {
		s, _ := newPostEAPSession(t)
		payloads := childTransactionPayloads(t, s)
		want := "IPv4 outside allocation"
		if allocated {
			ts := payloads[4].(*ikev2.EncryptedPayloadTS).TrafficSelectors[0]
			ts.StartAddr = []byte{192, 0, 2, 11}
			ts.EndAddr = []byte{192, 0, 2, 11}
		} else {
			// IPv6 selector in the original dual-stack offer; this response only
			// assigned IPv4. Observe the distinct existing rejection, not relax it.
			want = "IPv6 without allocation"
			payloads[4].(*ikev2.EncryptedPayloadTS).TrafficSelectors = []*ikev2.TrafficSelector{{TSType: ikev2.TS_IPV6_ADDR_RANGE, StartAddr: make([]byte, 16), EndAddr: []byte{255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255}, EndPort: 65535}}
		}
		err := s.handleIKEAuthFinalResp(encodePeerPacket(t, s, payloads, ikev2.IKE_AUTH, 3, true))
		if !errors.Is(err, errInitialChild) || !strings.Contains(err.Error(), want) {
			t.Fatalf("missing non-private source-family rejection: %v", err)
		}
	}
}

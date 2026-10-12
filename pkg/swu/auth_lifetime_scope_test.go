package swu

import (
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/1239t/swu-go/pkg/ikev2"
)

func TestFinalAUTHLifetimeAcceptsAuthenticatedIKEScope(t *testing.T) {
	for _, protocol := range []ikev2.ProtocolID{0, ikev2.ProtoIKE} {
		for _, lifetime := range []uint32{0, 300, 3600} {
			t.Run(fmt.Sprintf("protocol_%d_lifetime_%d", protocol, lifetime), func(t *testing.T) {
				s, calls := newPostEAPSession(t)
				payloads := childTransactionPayloads(t, s)
				data := make([]byte, 4)
				binary.BigEndian.PutUint32(data, lifetime)
				payloads = append(payloads, &ikev2.EncryptedPayloadNotify{NotifyType: ikev2.AUTH_LIFETIME, ProtocolID: protocol, NotifyData: data})
				if err := s.handleIKEAuthFinalResp(encodePeerPacket(t, s, payloads, ikev2.IKE_AUTH, 3, true)); err != nil {
					t.Fatalf("authenticated IKE-wide advisory rejected: %v", err)
				}
				if s.authLifetime != lifetime || s.ChildSAIn == nil || s.ChildSAOut == nil || s.cpConfig == nil || len(s.tsi) != 1 || len(s.tsr) != 1 || *calls != 0 {
					t.Fatal("advisory did not keep complete Child transaction and exact lifetime")
				}
			})
		}
	}
}

func TestFinalAUTHLifetimeIKEScopeStillRejectsInvalidTransaction(t *testing.T) {
	for _, scenario := range []string{"AH", "ESP", "unknown_protocol", "nonempty_spi", "short_data", "long_data", "duplicate", "bad_auth", "bad_cp", "bad_selector", "unoffered_algorithm", "mobike_ike_scope", "ticket_ike_scope", "redirect_ike_scope"} {
		t.Run(scenario, func(t *testing.T) {
			s, calls := newPostEAPSession(t)
			payloads := childTransactionPayloads(t, s)
			notify := &ikev2.EncryptedPayloadNotify{NotifyType: ikev2.AUTH_LIFETIME, ProtocolID: ikev2.ProtoIKE, NotifyData: []byte{0, 0, 0x0e, 0x10}}
			payloads = append(payloads, notify)
			switch scenario {
			case "AH":
				notify.ProtocolID = ikev2.ProtoAH
			case "ESP":
				notify.ProtocolID = ikev2.ProtoESP
			case "unknown_protocol":
				notify.ProtocolID = 99
			case "nonempty_spi":
				notify.SPI = []byte{1, 2, 3, 4}
			case "short_data":
				notify.NotifyData = notify.NotifyData[:3]
			case "long_data":
				notify.NotifyData = append(notify.NotifyData, 0)
			case "duplicate":
				payloads = append(payloads, &ikev2.EncryptedPayloadNotify{NotifyType: ikev2.AUTH_LIFETIME, NotifyData: []byte{0, 0, 0, 1}})
			case "bad_auth":
				payloads[1].(*ikev2.EncryptedPayloadAuth).AuthData[0] ^= 1
			case "bad_cp":
				payloads[2].(*ikev2.EncryptedPayloadCP).Attributes[0].Value = []byte{192, 0, 2}
			case "bad_selector":
				payloads[4].(*ikev2.EncryptedPayloadTS).TrafficSelectors[0].StartAddr = []byte{198, 51, 100, 10}
			case "unoffered_algorithm":
				payloads[3].(*ikev2.EncryptedPayloadSA).Proposals[0].Transforms[0].Attributes[0].Val = 192
			case "mobike_ike_scope":
				payloads = append(payloads, &ikev2.EncryptedPayloadNotify{NotifyType: ikev2.MOBIKE_SUPPORTED, ProtocolID: ikev2.ProtoIKE})
			case "ticket_ike_scope":
				payloads = append(payloads, &ikev2.EncryptedPayloadNotify{NotifyType: ikev2.TICKET_OPAQUE, ProtocolID: ikev2.ProtoIKE, NotifyData: []byte("synthetic-ticket")})
			case "redirect_ike_scope":
				payloads = append(payloads, &ikev2.EncryptedPayloadNotify{NotifyType: ikev2.REDIRECT, ProtocolID: ikev2.ProtoIKE, NotifyData: []byte{1, 4, 192, 0, 2, 1}})
			}
			before := snapPostEAP(s, *calls)
			if err := s.handleIKEAuthFinalResp(encodePeerPacket(t, s, payloads, ikev2.IKE_AUTH, 3, true)); err == nil {
				t.Fatal("IKE-scoped lifetime bypassed an invalid transaction")
			}
			assertSnapUnchanged(t, before, snapPostEAP(s, *calls))
		})
	}
}

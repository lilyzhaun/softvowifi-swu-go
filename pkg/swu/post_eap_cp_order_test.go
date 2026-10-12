package swu

import (
	"bytes"
	"testing"

	"github.com/1239t/swu-go/pkg/ikev2"
)

func TestCompletePostEAPAcceptsSameMessageCPAfterSA(t *testing.T) {
	for _, placement := range []string{"canonical", "cp_last", "notify_first_cp_last"} {
		t.Run(placement, func(t *testing.T) {
			s, calls := newPostEAPSession(t)
			payloads := childTransactionPayloads(t, s)
			if placement != "canonical" {
				cp := payloads[2]
				payloads = append(append(payloads[:2:2], payloads[3:]...), cp)
			}
			if placement == "notify_first_cp_last" {
				payloads = append([]ikev2.Payload{&ikev2.EncryptedPayloadNotify{NotifyType: ikev2.AUTH_LIFETIME, ProtocolID: ikev2.ProtoIKE, NotifyData: []byte{0, 0, 0x0e, 0x10}}}, payloads...)
			}
			original := encodePeerPacket(t, s, payloads, ikev2.IKE_AUTH, 3, true)
			err := s.completePostEAP(wrapAuth(t, s, []ikev2.Payload{testIDrPayload(), eapSuccessPayload()}), func(sent []ikev2.Payload) ([]byte, error) {
				assertInitiatorAUTHSent(t, sent)
				return original, nil
			})
			if err != nil {
				t.Fatalf("post-EAP complete transaction rejected only for representation: %v", err)
			}
			if s.ChildSAIn == nil || s.ChildSAOut == nil || s.cpConfig == nil || len(s.tsi) != 1 || len(s.tsr) != 1 || *calls != 0 {
				t.Fatal("accepted reordered transaction was only partially committed")
			}
			if !samePayloadEncoding(t, s, original, payloads) {
				t.Fatal("ingress normalization changed original authenticated payloads")
			}
		})
	}
}

func samePayloadEncoding(t *testing.T, s *Session, original []byte, payloads []ikev2.Payload) bool {
	t.Helper()
	decoded, err := s.decodeProtectedIKE(original)
	if err != nil || decoded == nil || len(decoded.payloads) != len(payloads) {
		return false
	}
	for index, payload := range payloads {
		if decoded.payloads[index].Type() != payload.Type() {
			return false
		}
		before, err := payload.Encode()
		if err != nil {
			t.Fatal(err)
		}
		after, err := decoded.payloads[index].Encode()
		if err != nil || !bytes.Equal(before, after) {
			return false
		}
	}
	return true
}

func TestCompletePostEAPCPPlacementNeverHidesInvalidContent(t *testing.T) {
	for _, scenario := range []string{"duplicate_cp", "duplicate_sa", "missing_cp", "bad_cp", "bad_auth", "bad_spi", "bad_tsi"} {
		t.Run(scenario, func(t *testing.T) {
			s, calls := newPostEAPSession(t)
			payloads := childTransactionPayloads(t, s)
			cp := payloads[2]
			payloads = append(append(payloads[:2:2], payloads[3:]...), cp)
			switch scenario {
			case "duplicate_cp":
				payloads = append(payloads, cp)
			case "duplicate_sa":
				payloads = append(payloads, payloads[2])
			case "missing_cp":
				payloads = payloads[:len(payloads)-1]
			case "bad_cp":
				cp.(*ikev2.EncryptedPayloadCP).Attributes[0].Value = []byte{192, 0, 2}
			case "bad_auth":
				payloads[1].(*ikev2.EncryptedPayloadAuth).AuthData[0] ^= 1
			case "bad_spi":
				payloads[2].(*ikev2.EncryptedPayloadSA).Proposals[0].SPI = []byte{0, 0, 0, 0}
			case "bad_tsi":
				payloads[3].(*ikev2.EncryptedPayloadTS).TrafficSelectors[0].StartAddr = []byte{198, 51, 100, 10}
			}
			before := snapPostEAP(s, *calls)
			err := s.completePostEAP(wrapAuth(t, s, []ikev2.Payload{testIDrPayload(), eapSuccessPayload()}), func(sent []ikev2.Payload) ([]byte, error) {
				return encodePeerPacket(t, s, payloads, ikev2.IKE_AUTH, 3, true), nil
			})
			if err == nil {
				t.Fatal("CP placement hid invalid content")
			}
			assertSnapUnchanged(t, before, snapPostEAP(s, *calls))
		})
	}
}

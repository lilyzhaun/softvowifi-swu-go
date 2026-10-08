package swu

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"testing"

	"github.com/1239t/swu-go/pkg/ikev2"
)

func TestChildRekeyPreservesState_whenProtectedNotify14(t *testing.T) {
	for _, mode := range []struct {
		name string
		esn  bool
	}{
		{name: "no_esn"},
		{name: "esn_and_fallback", esn: true},
	} {
		t.Run(mode.name, func(t *testing.T) {
			sess, pipe := childRekeySession(t)
			sess.cfg.EnableESN = mode.esn
			snap := snapshotChildRekey(sess)
			kernel := newRekeyKernel()
			response := encodeRekeyResponse(t, sess, &ikev2.EncryptedPayloadNotify{
				NotifyType: ikev2.NO_PROPOSAL_CHOSEN,
			})
			responseHeader, err := ikev2.DecodeHeader(response)
			if err != nil || responseHeader.NextPayload != ikev2.SK || responseHeader.ExchangeType != ikev2.CREATE_CHILD_SA {
				t.Fatal("expected protected CREATE_CHILD_SA rejection")
			}

			result := make(chan error, 1)
			go func() { result <- sess.rekeyChildSA(kernel) }()
			select {
			case request := <-pipe.sent:
				header, err := ikev2.DecodeHeader(request)
				if err != nil || header.NextPayload != ikev2.SK || header.ExchangeType != ikev2.CREATE_CHILD_SA {
					t.Fatal("expected protected CREATE_CHILD_SA request")
				}
				messageID, payloads, err := sess.decryptAndParse(request)
				if err != nil || messageID != header.MessageID || len(payloads) != 5 {
					t.Fatal("request payload decode failed")
				}
				sa, ok := payloads[0].(*ikev2.EncryptedPayloadSA)
				if !ok || len(sa.Proposals) != 2 || len(sa.Proposals[0].SPI) != 4 {
					t.Fatal("expected two ESP proposals with a four-byte SPI")
				}
				cbc := ikev2.NewProposal(1, ikev2.ProtoESP, sa.Proposals[0].SPI)
				cbc.AddTransformWithKeyLen(ikev2.TransformTypeEncr, ikev2.ENCR_AES_CBC, 128)
				cbc.AddTransform(ikev2.TransformTypeInteg, ikev2.AUTH_HMAC_SHA2_256_128, 0)
				gcm := ikev2.NewProposal(2, ikev2.ProtoESP, sa.Proposals[0].SPI)
				gcm.AddTransformWithKeyLen(ikev2.TransformTypeEncr, ikev2.ENCR_AES_GCM_16, 128)
				for _, proposal := range []*ikev2.Proposal{cbc, gcm} {
					if mode.esn {
						proposal.AddTransform(ikev2.TransformTypeESN, 1, 0)
					}
					proposal.AddTransform(ikev2.TransformTypeESN, 0, 0)
				}
				expectedSA := &ikev2.EncryptedPayloadSA{Proposals: []*ikev2.Proposal{cbc, gcm}}
				expectedBytes, err := expectedSA.Encode()
				if err != nil {
					t.Fatal(err)
				}
				actualBytes, err := sa.Encode()
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(actualBytes, expectedBytes) {
					t.Error("current CBC/GCM proposal set changed")
				}
				nonce, ok := payloads[1].(*ikev2.EncryptedPayloadNonce)
				if !ok || len(nonce.NonceData) != 32 {
					t.Error("expected 32-byte nonce")
				}
				notify, ok := payloads[2].(*ikev2.EncryptedPayloadNotify)
				if !ok || notify.NotifyType != ikev2.REKEY_SA || notify.ProtocolID != ikev2.ProtoESP || len(notify.SPI) != 4 || binary.BigEndian.Uint32(notify.SPI) != snap.in.SPI || len(notify.NotifyData) != 0 {
					t.Error("REKEY_SA did not preserve the RFC 7296 inbound old-SPI direction")
				}
				tsi, ok := payloads[3].(*ikev2.EncryptedPayloadTS)
				if !ok || !tsi.IsInitiator || !reflect.DeepEqual(tsi.TrafficSelectors, sess.tsr) {
					t.Error("current initiator traffic selector changed")
				}
				tsr, ok := payloads[4].(*ikev2.EncryptedPayloadTS)
				if !ok || tsr.IsInitiator || !reflect.DeepEqual(tsr.TrafficSelectors, sess.tsr) {
					t.Error("current responder traffic selector changed")
				}
				if responseHeader.MessageID != header.MessageID || !sess.taskMgr.HandleResponse(header.MessageID, response) {
					t.Fatal("protected rejection did not match the actual request")
				}
			case <-sess.ctx.Done():
				t.Fatal("request timed out")
			}

			select {
			case err := <-result:
				if err == nil || err.Error() != "CREATE_CHILD_SA 被拒绝，通知类型: 14" {
					t.Fatalf("expected decoded Notify14 rejection, got %v", err)
				}
			case <-sess.ctx.Done():
				t.Fatal("rejection did not return to caller")
			}
			snap.assertUncommitted(t, sess)
			if len(kernel.calls) != 0 || len(kernel.adds) != 0 || len(kernel.policies) != 0 || len(kernel.deletes) != 0 || !reflect.DeepEqual(kernel.live, map[uint32]bool{101: true, 102: true}) {
				t.Error("protected rejection reached XFRM mutation")
			}
			if len(pipe.sent) != 0 {
				t.Error("sent old Child SA DELETE after protected rejection")
			}
		})
	}
}

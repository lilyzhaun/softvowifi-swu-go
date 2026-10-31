package swu

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/1239t/swu-go/pkg/ikev2"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func snapshotSecurityJSON(t *testing.T, s *Session) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(s.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	return fields["Security"]
}

func assertNoNegotiatedSecurity(t *testing.T, s *Session) {
	t.Helper()
	raw := snapshotSecurityJSON(t, s)
	if len(raw) != 0 && !bytes.Equal(raw, []byte("null")) {
		t.Fatal("unconfirmed or retired security was exposed as current")
	}
}

func TestNegotiatedSecuritySnapshotUsesActualAuthenticatedSelection(t *testing.T) {
	for _, name := range []string{"authenticated", "invalid_final_auth", "dataplane_failure"} {
		t.Run(name, func(t *testing.T) {
			accepted := name != "invalid_final_auth"
			peer := newAKAWirePeer(t)
			provider := &akaWireSIM{vectorSIM: vectorSIM{res: []byte{0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67}, ck: bytes.Repeat([]byte{0x43}, 16), ik: bytes.Repeat([]byte{0x49}, 16)}}
			material := referenceAKAKeys(&provider.vectorSIM, false)
			log, output := diagnosticLogger()
			established := make(chan struct{})
			log = log.WithOptions(zap.Hooks(func(entry zapcore.Entry) error {
				if entry.Message == "会话已建立" {
					close(established)
				}
				return nil
			}))
			s := NewSession(&Config{LocalAddr: "127.0.0.1", EpDGAddr: "127.0.0.1", EpDGPort: uint16(peer.conn.LocalAddr().(*net.UDPAddr).Port), APN: "ims", SIM: provider}, log)
			driverFailure := errors.New("synthetic dataplane setup failure")
			if name == "dataplane_failure" {
				s.cfg.EnableDriver = true
				s.cfg.TUNFactory = func(string) (TUN, error) { return nil, driverFailure }
			}
			assertNoNegotiatedSecurity(t, s)
			ctx, cancel := context.WithTimeout(t.Context(), 6*time.Second)
			done := make(chan error, 1)
			go func() { done <- s.Connect(ctx) }()
			t.Cleanup(func() { cancel(); s.Shutdown() })
			// This independent peer selects proposal four: CBC256/SHA256,
			// PRF-SHA256/DH14, not the first proposal or a configured default.
			peer.negotiate(t)
			initial := peer.decrypt(t, peer.receive(t))
			assertAKAWireInitial(t, initial)
			assertNoNegotiatedSecurity(t, s)
			idr := append([]byte{2, 0, 0, 0}, []byte(testIDrFQDN)...)
			peer.send(t, peer.protect(t, []akaWirePayload{{kind: 36, body: idr}, {kind: 48, body: referenceChallenge(material[16:32], false)}}))
			response := peer.decrypt(t, peer.receive(t))
			if len(response) != 1 || response[0].kind != 48 || !bytes.Equal(response[0].body, referenceResponse(provider.res, material[16:32], false)) {
				t.Fatal("independent AKA response differs")
			}
			peer.send(t, peer.protect(t, []akaWirePayload{{kind: 48, body: []byte{3, 0xa7, 0, 4}}}))
			final := peer.decrypt(t, peer.receive(t))
			key := independentHMACSHA256(material[32:96], []byte("Key Pad for IKEv2"))
			signed := append(bytes.Clone(peer.initRequest), peer.responderNonce...)
			signed = append(signed, independentHMACSHA256(peer.keys[160:192], initial[0].body)...)
			if len(final) != 1 || final[0].kind != 39 || !bytes.Equal(final[0].body, append([]byte{2, 0, 0, 0}, independentHMACSHA256(key, signed)...)) {
				t.Fatal("initiator AUTH does not bind its original transcript")
			}
			auth := independentResponderAUTH(material[32:96], peer.keys[192:224], idr, peer.initResponse, peer.initiatorNonce)
			if !accepted {
				auth[0] ^= 1
			}
			child, err := testChildSA().Encode()
			if err != nil {
				t.Fatal(err)
			}
			peer.send(t, peer.protect(t, []akaWirePayload{
				{kind: 39, body: append([]byte{2, 0, 0, 0}, auth...)},
				{kind: 47, body: []byte{2, 0, 0, 0, 0, 1, 0, 4, 192, 0, 2, 10}},
				{kind: 33, body: child},
				{kind: 44, body: []byte{1, 0, 0, 0, 7, 0, 0, 16, 0, 0, 255, 255, 192, 0, 2, 10, 192, 0, 2, 10}},
				{kind: 45, body: []byte{1, 0, 0, 0, 7, 0, 0, 16, 0, 0, 255, 255, 0, 0, 0, 0, 255, 255, 255, 255}},
			}))
			if !accepted {
				select {
				case err := <-done:
					if err == nil || errors.Is(err, context.DeadlineExceeded) || s.ChildSAIn != nil || s.ChildSAOut != nil {
						t.Fatal("invalid AUTH did not fail before Child commit")
					}
				case <-ctx.Done():
					t.Fatal("invalid AUTH did not terminate within the bounded exchange")
				}
				assertNoNegotiatedSecurity(t, s)
				return
			}
			if name == "dataplane_failure" {
				select {
				case err := <-done:
					if !errors.Is(err, driverFailure) {
						t.Fatal("authenticated connection did not reach the injected dataplane failure")
					}
				case <-ctx.Done():
					t.Fatal("dataplane failure did not retire its owner")
				}
				assertNoNegotiatedSecurity(t, s)
				return
			}
			select {
			case <-established:
			case err := <-done:
				t.Fatalf("authenticated loopback Connect failed: %v", err)
			case <-ctx.Done():
				t.Fatal("authenticated Connect did not establish")
			}
			if provider.calls != 1 || !s.Snapshot().Established {
				t.Fatal("selection test did not complete one authenticated Child exchange")
			}
			var got, want any
			const expected = `{"IKE":{"Encryption":12,"KeyBits":256,"Integrity":12,"PRF":5,"DH":14},"Child":{"Encryption":12,"KeyBits":256,"Integrity":12,"ESN":false,"PFS":0}}`
			if json.Unmarshal(snapshotSecurityJSON(t, s), &got) != nil || json.Unmarshal([]byte(expected), &want) != nil || !reflect.DeepEqual(got, want) {
				t.Fatal("authenticated selection is missing or differs from the exact negotiated tuples")
			}
			// Reflection keeps this regression executable against the old API.
			copy := s.Snapshot()
			selection := reflect.ValueOf(&copy).Elem().FieldByName("Security")
			selection.Elem().FieldByName("IKE").FieldByName("KeyBits").SetInt(1)
			if json.Unmarshal(snapshotSecurityJSON(t, s), &got) != nil || !reflect.DeepEqual(got, want) {
				t.Fatal("caller changed the current negotiated state through a returned snapshot")
			}
			before := s.Snapshot()
			rekeyNegotiatedSnapshotChild(t, s, peer)
			after := s.Snapshot()
			if after.Security == nil || after.Security.IKE != before.Security.IKE || after.Security.Child != (NegotiatedChildSecurity{Encryption: 20, KeyBits: 128}) {
				t.Fatal("authenticated Child rekey did not publish its selected GCM128 tuple")
			}
			if before.Security.Child.KeyBits != 256 || before.Security.Child.Integrity != 12 {
				t.Fatal("Child rekey changed an already returned snapshot")
			}
			cancel()
			assertNoNegotiatedSecurity(t, s)
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("negotiated snapshot owner did not retire")
			}
			assertNoNegotiatedSecurity(t, s)
			assertDiagnosticPrivacy(t, output, provider.res, provider.ck, provider.ik, provider.rand, provider.autn)
		})
	}
}

func rekeyNegotiatedSnapshotChild(t *testing.T, s *Session, peer *akaWirePeer) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- s.RekeyChildSA() }()
	raw := peer.receive(t)
	header, err := ikev2.DecodeHeader(raw)
	if err != nil || header.ExchangeType != ikev2.CREATE_CHILD_SA {
		t.Fatal("missing actual protected Child rekey request")
	}
	// Verify the actual wire with the independently derived handshake keys.
	opened := peerChildOpen(t, raw, peer.keys[96:128], peer.keys[32:64])
	if len(opened[byte(ikev2.SA)]) == 0 || len(opened[byte(ikev2.NiNr)]) != 32 {
		t.Fatal("missing Child offer or fresh nonce")
	}
	_, payloads, err := testPeerReceiver(s).decryptAndParse(raw)
	if err != nil {
		t.Fatal(err)
	}
	var selected *ikev2.Proposal
	var selectors []ikev2.Payload
	for _, payload := range payloads {
		switch p := payload.(type) {
		case *ikev2.EncryptedPayloadSA:
			for _, candidate := range p.Proposals {
				for _, transform := range candidate.Transforms {
					if transform.Type == ikev2.TransformTypeEncr && transform.ID == ikev2.ENCR_AES_GCM_16 && len(transform.Attributes) == 1 && transform.Attributes[0].Val == 128 {
						selected = ikev2.NewProposal(candidate.ProposalNum, ikev2.ProtoESP, binary.BigEndian.AppendUint32(nil, 0x33334444))
						selected.Transforms = candidate.Transforms
					}
				}
			}
		case *ikev2.EncryptedPayloadTS:
			selectors = append(selectors, p)
		}
	}
	if selected == nil || len(selectors) != 2 {
		t.Fatal("GCM128 complete suite and both selectors were not actually offered")
	}
	response := append([]ikev2.Payload{
		&ikev2.EncryptedPayloadSA{Proposals: []*ikev2.Proposal{selected}},
		&ikev2.EncryptedPayloadNonce{NonceData: bytes.Repeat([]byte{0x42}, 32)},
	}, selectors...)
	peer.send(t, encodePeerPacket(t, s, response, ikev2.CREATE_CHILD_SA, header.MessageID, true))
	raw = peer.receive(t)
	header, err = ikev2.DecodeHeader(raw)
	if err != nil || header.ExchangeType != ikev2.INFORMATIONAL {
		t.Fatal("missing old Child Delete after real rekey commit")
	}
	if len(peerChildOpen(t, raw, peer.keys[96:128], peer.keys[32:64])[byte(ikev2.D)]) == 0 {
		t.Fatal("retirement request did not contain an authenticated Delete")
	}
	peer.send(t, encodePeerPacket(t, s, nil, ikev2.INFORMATIONAL, header.MessageID, true))
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-s.ctx.Done():
		t.Fatal("real Child rekey did not finish")
	}
}

func TestNegotiatedSecuritySnapshotDoesNotInferAuthenticationFromSAs(t *testing.T) {
	s, _ := childRekeySession(t)
	if !s.Snapshot().Established {
		t.Fatal("fixture did not expose its existing Child pair")
	}
	assertNoNegotiatedSecurity(t, s)
}

package swu

import (
	"testing"

	"github.com/1239t/swu-go/pkg/ikev2"
)

func TestReceiveRoleSwitchesOnPeerInitiatedIKERekey(t *testing.T) {
	s := newLebaraRekeyCryptoSession(t)
	pipe := &pipeTransport{sent: make(chan []byte, 1)}
	s.socket = pipe
	oldPeer := testPeerReceiver(s)
	if _, _, err := s.decryptAndParse(independentSKF(t, s, []byte{0}, ikev2.N, 1, 2, ikev2.INFORMATIONAL, 3, false)); err != nil {
		t.Fatal(err)
	}
	spi := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	request := []ikev2.Payload{
		&ikev2.EncryptedPayloadSA{Proposals: []*ikev2.Proposal{s.ikeRekeyProposal(spi)}},
		&ikev2.EncryptedPayloadNonce{NonceData: make([]byte, 32)},
		&ikev2.EncryptedPayloadKE{DHGroup: 14, KEData: s.DH.PublicKeyBytes()},
	}
	if err := s.HandleRekeyIKESARequest(7, request); err != nil {
		t.Fatal(err)
	}
	if !s.localResponder {
		t.Fatal("peer-initiated rekey did not change local SA role")
	}
	if len(s.fragmentBuf.frags) != 0 || len(s.fragmentBuf.replies) != 0 {
		t.Fatal("old IKE generation fragment state survived peer rekey")
	}
	select {
	case response := <-pipe.sent:
		if _, _, err := oldPeer.decryptAndParse(response); err != nil {
			t.Fatalf("rekey response must use old SA role/keys: %v", err)
		}
	default:
		t.Fatal("missing rekey response")
	}
	response := encodePeerPacket(t, s, nil, ikev2.INFORMATIONAL, 0, true)
	if _, _, err := s.decryptAndParse(response); err != nil {
		t.Fatalf("new SA must accept initiator peer: %v", err)
	}
}

func TestReceiveRoleReturnsToInitiatorOnLocalIKERekey(t *testing.T) {
	s := newLebaraRekeyCryptoSession(t)
	s.localResponder = true
	if _, _, err := s.decryptAndParse(independentSKF(t, s, []byte{0}, ikev2.N, 1, 2, ikev2.INFORMATIONAL, 3, false)); err != nil {
		t.Fatal(err)
	}
	prop := s.ikeRekeyProposal([]byte{1, 2, 3, 4, 5, 6, 7, 8})
	response := encodeRekeyResponse(t, s,
		&ikev2.EncryptedPayloadSA{Proposals: []*ikev2.Proposal{prop}},
		&ikev2.EncryptedPayloadNonce{NonceData: make([]byte, 32)},
		&ikev2.EncryptedPayloadKE{DHGroup: 14, KEData: s.DH.PublicKeyBytes()},
	)
	if err := s.handleRekeyIKESAResp(response, make([]byte, 32), s.DH, 123, s.Keys.SK_d, s.SPIi, s.SPIr); err != nil {
		t.Fatal(err)
	}
	if s.localResponder {
		t.Fatal("locally initiated rekey retained responder SA role")
	}
	if len(s.fragmentBuf.frags) != 0 || len(s.fragmentBuf.replies) != 0 {
		t.Fatal("old IKE generation fragment state survived local rekey")
	}
	valid := encodePeerPacket(t, s, nil, ikev2.INFORMATIONAL, 0, true)
	if _, _, err := s.decryptAndParse(valid); err != nil {
		t.Fatalf("new SA must accept responder peer: %v", err)
	}
}

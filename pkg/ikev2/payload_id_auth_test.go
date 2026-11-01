package ikev2

import (
	"bytes"
	"testing"
)

func TestIDAuthenticationBodyOwnsReceivedBytes(t *testing.T) {
	for _, initiator := range []bool{false, true} {
		wire := append([]byte{ID_FQDN, 0x91, 0x42, 0xf3}, []byte("peer.example.test")...)
		want := bytes.Clone(wire)
		id, err := DecodePayloadID(wire, initiator)
		if err != nil {
			t.Fatal(err)
		}
		wire[0], wire[1], wire[4] = ID_KEY_ID, 0, 'x'
		if id.IDType != ID_FQDN || string(id.IDData) != "peer.example.test" {
			t.Fatal("decoded identity aliases the receive buffer")
		}
		body, err := id.AuthenticationBody()
		if err != nil || !bytes.Equal(body, want) {
			t.Fatal("authentication body differs from received payload")
		}
		body[1], body[4] = 0, 'y'
		id.IDData[0], id.IDType = 'z', ID_KEY_ID
		again, err := id.AuthenticationBody()
		if err != nil || !bytes.Equal(again, want) {
			t.Fatal("returned bytes or decoded fields rewrote the authentication transcript")
		}
		encoded, err := id.Encode()
		if err != nil || encoded[0] != ID_KEY_ID || encoded[4] != 'z' || !bytes.Equal(encoded[1:4], []byte{0, 0, 0}) {
			t.Fatal("outgoing encoding must use current fields and zero RESERVED bytes")
		}
	}
}

func TestIDAuthenticationBodyUsesLocalEncoding(t *testing.T) {
	id := &EncryptedPayloadID{IDType: ID_RFC822_ADDR, IDData: []byte("local@example.test"), IsInitiator: true}
	encoded, err := id.Encode()
	if err != nil {
		t.Fatal(err)
	}
	body, err := id.AuthenticationBody()
	if err != nil || !bytes.Equal(body, encoded) {
		t.Fatal("local identity body differs from its outgoing encoding")
	}
	body[4] = 'x'
	if string(id.IDData) != "local@example.test" {
		t.Fatal("local authentication body aliases identity data")
	}
}

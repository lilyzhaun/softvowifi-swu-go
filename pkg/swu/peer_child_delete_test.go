package swu

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/1239t/swu-go/pkg/ikev2"
	"github.com/1239t/swu-go/pkg/ipsec"
)

func TestPeerChildDeleteIsAnsweredWithPairedSPI(t *testing.T) {
	for _, sendFails := range []bool{false, true} {
		t.Run(map[bool]string{false: "sent", true: "send_failure"}[sendFails], func(t *testing.T) {
			s, pipe := newPeerInformationalSession(t)
			s.ChildSAIn = &ipsec.SecurityAssociation{SPI: 111, RemoteSPI: 222}
			s.ChildSAOut = &ipsec.SecurityAssociation{SPI: 222, RemoteSPI: 111}
			s.ChildSAsIn = map[uint32]*ipsec.SecurityAssociation{111: s.ChildSAIn}
			if sendFails {
				pipe.sendErr = errSendIKE
			}
			pipe.beforeSend = func() {
				if s.ctx.Err() != nil {
					t.Error("canceled before paired Delete response")
				}
			}
			request := encodeInformational(t, s, &ikev2.EncryptedPayloadDelete{ProtocolID: ikev2.ProtoESP, SPISize: 4, NumSPIs: 1, SPIs: binary.BigEndian.AppendUint32(nil, 222)})
			s.dispatchReceivedIKE(request, nil)
			raw := <-pipe.sent
			h := hmac.New(sha256.New, s.Keys.SK_ai)
			h.Write(raw[:len(raw)-16])
			if !hmac.Equal(h.Sum(nil)[:16], raw[len(raw)-16:]) {
				t.Fatal("invalid response ICV")
			}
			block, err := aes.NewCipher(s.Keys.SK_ei)
			if err != nil {
				t.Fatal(err)
			}
			plain := make([]byte, len(raw)-64)
			cipher.NewCBCDecrypter(block, raw[32:48]).CryptBlocks(plain, raw[48:len(raw)-16])
			if raw[28] != byte(ikev2.D) || !bytes.Equal(plain[:12], []byte{0, 0, 0, 12, byte(ikev2.ProtoESP), 4, 0, 1, 0, 0, 0, 111}) {
				t.Fatal("peer-inbound SPI not answered with local-inbound SPI")
			}
			if s.ctx.Err() == nil {
				t.Fatal("last Child pair deletion left session alive")
			}
			cleaned := false
			s.netUndos = []func() error{func() error { cleaned = true; return nil }}
			if err := s.cleanupNetworkConfig(); err != nil || !cleaned {
				t.Fatal("deleted session did not retain its owned cleanup path")
			}
		})
	}
}

func TestPeerChildDeleteMalformedShapeCannotRetireSession(t *testing.T) {
	for _, d := range []*ikev2.EncryptedPayloadDelete{
		{ProtocolID: ikev2.ProtoESP, SPISize: 4, NumSPIs: 1, SPIs: binary.BigEndian.AppendUint32(binary.BigEndian.AppendUint32(nil, 222), 333)},
		{ProtocolID: ikev2.ProtoIKE, SPISize: 4, NumSPIs: 1, SPIs: binary.BigEndian.AppendUint32(nil, 222)},
	} {
		s, pipe := newPeerInformationalSession(t)
		s.ChildSAIn = &ipsec.SecurityAssociation{SPI: 111}
		s.ChildSAOut = &ipsec.SecurityAssociation{SPI: 222}
		s.dispatchReceivedIKE(encodeInformational(t, s, d), nil)
		if s.ctx.Err() != nil {
			t.Fatal("malformed Delete ended session")
		}
		select {
		case <-pipe.sent:
			t.Fatal("malformed Delete acknowledged")
		default:
		}
	}
}

func TestPeerChildDeleteCleanupFailureRemainsFatal(t *testing.T) {
	s, pipe := newPeerInformationalSession(t)
	s.ChildSAIn = &ipsec.SecurityAssociation{SPI: 111}
	s.ChildSAOut = &ipsec.SecurityAssociation{SPI: 222}
	s.netUndos = []func() error{func() error { return errors.New("synthetic cleanup failure") }}
	s.dispatchReceivedIKE(encodeInformational(t, s, &ikev2.EncryptedPayloadDelete{ProtocolID: ikev2.ProtoESP, SPISize: 4, NumSPIs: 1, SPIs: binary.BigEndian.AppendUint32(nil, 222)}), nil)
	<-pipe.sent
	if err := s.cleanupNetworkConfig(); !errors.Is(err, ErrCleanup) || len(s.netUndos) != 1 {
		t.Fatal("peer deletion discarded failed cleanup ownership")
	}
}

func TestPeerIKEAndChildDeleteHasEmptyIKEAcknowledgement(t *testing.T) {
	s, pipe := newPeerInformationalSession(t)
	s.ChildSAIn = &ipsec.SecurityAssociation{SPI: 111}
	s.ChildSAOut = &ipsec.SecurityAssociation{SPI: 222}
	var reason SessionDownReason
	s.OnClosedReason = func(r SessionDownReason) { reason = r }
	s.dispatchReceivedIKE(encodePeerPacket(t, s, []ikev2.Payload{
		&ikev2.EncryptedPayloadDelete{ProtocolID: ikev2.ProtoESP, SPISize: 4, NumSPIs: 1, SPIs: binary.BigEndian.AppendUint32(nil, 222)},
		&ikev2.EncryptedPayloadDelete{ProtocolID: ikev2.ProtoIKE},
	}, ikev2.INFORMATIONAL, 0, false), nil)
	if raw := <-pipe.sent; raw[28] != 0 || reason != SessionDownPeerIKEDelete {
		t.Fatal("IKE Delete did not take precedence over its Child Delete")
	}
}

func TestPeerChildDeleteUnknownOrInboundSPILeavesPairLive(t *testing.T) {
	for _, spi := range []uint32{111, 333} {
		s, pipe := newPeerInformationalSession(t)
		in, out := &ipsec.SecurityAssociation{SPI: 111, RemoteSPI: 222}, &ipsec.SecurityAssociation{SPI: 222, RemoteSPI: 111}
		s.ChildSAIn, s.ChildSAOut = in, out
		s.ChildSAsIn = map[uint32]*ipsec.SecurityAssociation{111: in}
		s.dispatchReceivedIKE(encodeInformational(t, s, &ikev2.EncryptedPayloadDelete{ProtocolID: ikev2.ProtoESP, SPISize: 4, NumSPIs: 1, SPIs: binary.BigEndian.AppendUint32(nil, spi)}), nil)
		<-pipe.sent
		if s.ctx.Err() != nil || s.ChildSAIn != in || s.ChildSAOut != out || s.ChildSAsIn[111] != in {
			t.Fatal("wrong-direction or unknown SPI modified active pair")
		}
	}
}

package swu

import (
	"testing"

	"github.com/1239t/swu-go/pkg/ikev2"
)

func TestRuntimeRedirectRejectsInvalidFramingWithoutEndingSession(t *testing.T) {
	for _, n := range []*ikev2.EncryptedPayloadNotify{
		{NotifyData: []byte{1, 127, 0, 0, 1}},
		{NotifyData: []byte{1, 4, 127, 0, 0, 1, 0}},
		{NotifyData: []byte{3, 0}},
		{ProtocolID: ikev2.ProtoIKE, NotifyData: []byte{1, 4, 127, 0, 0, 1}},
		{SPI: []byte{1}, NotifyData: []byte{1, 4, 127, 0, 0, 1}},
	} {
		s, pipe := newPeerInformationalSession(t)
		n.NotifyType = ikev2.REDIRECT
		if err := s.handleIncomingInformationalParsed(0, []ikev2.Payload{n}); err != nil {
			t.Fatal(err)
		}
		<-pipe.sent
		if s.ctx.Err() != nil {
			t.Fatal("invalid runtime redirect ended session")
		}
	}
}

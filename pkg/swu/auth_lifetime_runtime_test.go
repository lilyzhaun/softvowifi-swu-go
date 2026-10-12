package swu

import (
	"testing"
	"time"

	"github.com/1239t/swu-go/pkg/ikev2"
)

func TestProtectedZeroAuthLifetimeRepliesBeforeReauth(t *testing.T) {
	s, pipe := newPeerInformationalSession(t)
	s.reauthTrigger = make(chan struct{}, 1)
	pipe.beforeSend = func() {
		if len(s.reauthTrigger) != 0 {
			t.Error("reauth triggered before INFORMATIONAL response")
		}
	}
	pipe.ike <- encodeInformational(t, s, &ikev2.EncryptedPayloadNotify{NotifyType: ikev2.AUTH_LIFETIME, NotifyData: []byte{0, 0, 0, 0}})
	select {
	case raw := <-pipe.sent:
		if raw[28] != 0 {
			t.Fatal("AUTH_LIFETIME response is not empty")
		}
	case <-time.After(time.Second):
		t.Fatal("no INFORMATIONAL response")
	}
	select {
	case <-s.reauthTrigger:
	case <-time.After(time.Second):
		t.Fatal("protected zero lifetime never triggered reauthentication")
	}
}

func TestMalformedAuthLifetimeNeverChangesAuthentication(t *testing.T) {
	for _, kind := range []string{"short", "long", "protocol", "spi", "duplicate"} {
		t.Run(kind, func(t *testing.T) {
			s, pipe := newPeerInformationalSession(t)
			s.reauthTrigger = make(chan struct{}, 1)
			n := &ikev2.EncryptedPayloadNotify{NotifyType: ikev2.AUTH_LIFETIME, NotifyData: []byte{0, 0, 0, 0}}
			payloads := []ikev2.Payload{n}
			switch kind {
			case "short":
				n.NotifyData = []byte{0}
			case "long":
				n.NotifyData = make([]byte, 5)
			case "protocol":
				n.ProtocolID = ikev2.ProtoESP
			case "spi":
				n.SPI = []byte{0, 0, 0, 1}
			case "duplicate":
				payloads = append(payloads, n)
			}
			if err := s.handleIncomingInformationalParsed(0, payloads); err == nil {
				t.Fatal("malformed AUTH_LIFETIME accepted")
			}
			if s.ctx.Err() != nil || len(s.reauthTrigger) != 0 {
				t.Fatal("invalid lifetime affected authentication")
			}
			select {
			case <-pipe.sent:
				t.Fatal("invalid lifetime acknowledged")
			default:
			}
		})
	}
}

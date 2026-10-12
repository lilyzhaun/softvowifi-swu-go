package swu

import (
	"context"
	"encoding/binary"
	"testing"
	"time"

	"github.com/1239t/swu-go/pkg/ikev2"
)

func TestAuthenticationDeadlineSurvivesRealPeerIKERekey(t *testing.T) {
	s := newLebaraRekeyCryptoSession(t)
	s.ctx, s.cancel = context.WithCancel(t.Context())
	defer s.cancel()
	s.reauthTrigger = make(chan struct{}, 1)
	pipe := &pipeTransport{sent: make(chan []byte, 4)}
	s.socket = pipe
	// Receipt occurred earlier in this authenticated generation. Keep its
	// original hour-long deadline, with one real second left at this rekey.
	s.setAuthLifetime(3600, time.Now().Add(-3539*time.Second), nil)
	s.startAuthenticationTimer()
	if err := s.HandleRekeyIKESARequest(0, peerRekeyOffer(t, s)); err != nil {
		t.Fatal(err)
	}
	<-pipe.sent
	if !s.localResponder {
		t.Fatal("real peer IKE rekey did not change the role")
	}
	select {
	case <-s.reauthTrigger:
		t.Fatal("authentication retired too early")
	default:
	}
	select {
	case <-s.reauthTrigger:
	case <-time.After(2 * time.Second):
		t.Fatal("IKE rekey extended the original authentication deadline")
	}
	s.startAuthenticationTimer() // The published timer is one-shot per owner.
	select {
	case <-s.reauthTrigger:
		t.Fatal("authentication deadline fired twice")
	default:
	}
}

func TestAuthenticationPolicyUpdateIgnoresReplayAndKeepsEarlierLocalDeadline(t *testing.T) {
	s, pipe := newPeerInformationalSession(t)
	s.startIKEReauthTimer(1200 * time.Millisecond)
	send := func(mid, seconds uint32) {
		p := []ikev2.Payload{&ikev2.EncryptedPayloadNotify{NotifyType: ikev2.AUTH_LIFETIME, NotifyData: binary.BigEndian.AppendUint32(nil, seconds)}}
		if err := s.handleIncomingInformationalParsed(mid, p); err != nil {
			t.Fatal(err)
		}
		<-pipe.sent
	}
	send(10, 1)
	s.authExpiry.mu.Lock()
	deadline := s.authExpiry.server
	s.authExpiry.mu.Unlock()
	send(10, 1)
	send(9, 3600)
	s.authExpiry.mu.Lock()
	unchanged := s.authExpiry.server.Equal(deadline)
	s.authExpiry.mu.Unlock()
	if !unchanged {
		t.Fatal("duplicate or older MID extended authentication")
	}
	send(11, 3600)
	select {
	case <-s.reauthTrigger:
		t.Fatal("new authenticated policy failed to replace old short deadline")
	case <-time.After(900 * time.Millisecond):
	}
	select {
	case <-s.reauthTrigger:
	case <-time.After(time.Second):
		t.Fatal("server extension overrode earlier local authentication policy")
	}
}

func TestInvalidICVCannotScheduleReauthentication(t *testing.T) {
	s, pipe := newPeerInformationalSession(t)
	raw := encodeInformational(t, s, &ikev2.EncryptedPayloadNotify{NotifyType: ikev2.AUTH_LIFETIME, NotifyData: make([]byte, 4)})
	raw[len(raw)-1] ^= 1
	s.dispatchReceivedIKE(raw, nil)
	s.authExpiry.mu.Lock()
	empty := s.authExpiry.server.IsZero()
	s.authExpiry.mu.Unlock()
	if !empty || len(s.reauthTrigger) != 0 {
		t.Fatal("unauthenticated lifetime changed authentication")
	}
	select {
	case <-pipe.sent:
		t.Fatal("unauthenticated lifetime acknowledged")
	default:
	}
}

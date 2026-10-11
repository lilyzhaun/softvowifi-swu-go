package swu

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/1239t/swu-go/pkg/ikev2"
)

// RFC4187 6.1/9.10/9.11 independent wire and HMAC-SHA1-128, not the
// production notification encoder or MAC function.
func notificationWire(code uint16, key []byte) []byte {
	raw := []byte{1, 0x87, 0, 12, 23, 12, 0, 0, 12, 1, byte(code >> 8), byte(code)}
	if key != nil {
		raw = append(raw, 11, 5, 0, 0)
		raw = append(raw, make([]byte, 16)...)
	}
	binary.BigEndian.PutUint16(raw[2:4], uint16(len(raw)))
	if key != nil {
		m := hmac.New(sha1.New, key)
		m.Write(raw)
		copy(raw[len(raw)-16:], m.Sum(nil)[:16])
	}
	return raw
}

func notificationFullSession(t *testing.T, resultInd bool) (*Session, []byte) {
	t.Helper()
	provider := &vectorSIM{res: bytes.Repeat([]byte{0x52}, 8), ck: bytes.Repeat([]byte{0x43}, 16), ik: bytes.Repeat([]byte{0x49}, 16)}
	key := referenceAKAKeys(provider, false)[16:32]
	s := NewSession(&Config{SIM: provider}, nil)
	response, err := s.handleEAP(referenceChallenge(key, resultInd))
	if err != nil || len(response) != 1 || !bytes.Equal(s.eapKAut, key) {
		t.Fatal("independent legitimate Challenge precondition failed")
	}
	return s, key
}

func notificationACK(t *testing.T, pls []ikev2.Payload, key []byte) []byte {
	t.Helper()
	if len(pls) != 1 {
		t.Fatal("missing notification acknowledgement")
	}
	raw := pls[0].(*ikev2.EncryptedPayloadEAP).EAPMessage
	want := []byte{2, 0x87, 0, 8, 23, 12, 0, 0}
	if key != nil {
		want[3] = 28
		want = append(want, 11, 5, 0, 0)
		want = append(want, make([]byte, 16)...)
		m := hmac.New(sha1.New, key)
		m.Write(want)
		copy(want[12:28], m.Sum(nil)[:16])
	}
	if !bytes.Equal(raw, want) {
		t.Fatal("ACK differs from independent Notification wire (or leaked identity)")
	}
	return raw
}

func TestNotificationFailureACKNeverDisclosesIdentity(t *testing.T) {
	for _, code := range []uint16{0x4000, 0x4001, 0x401f} {
		provider := &diagnosticSIM{}
		s := NewSession(&Config{SIM: provider}, nil)
		pls, err := s.handleEAP(notificationWire(code, nil))
		if err != nil {
			t.Fatal(err)
		}
		notificationACK(t, pls, nil)
		if provider.imsiCalls != 0 || provider.akaCalls != 0 {
			t.Fatal("failure notification accessed permanent SIM identity")
		}
		if _, err := s.handleEAP([]byte{3, 0x88, 0, 4}); err == nil {
			t.Fatal("failure notification followed by EAP Success was accepted")
		}
	}
}

func TestNotificationProtectedACKUsesIndependentMAC(t *testing.T) {
	for _, code := range []uint16{0x8000, 0x8001, 0x0000, 0x0402} {
		s, key := notificationFullSession(t, true)
		raw := notificationWire(code, key)
		original := bytes.Clone(raw)
		pls, err := s.handleEAP(raw)
		if err != nil {
			t.Fatal(err)
		}
		notificationACK(t, pls, key)
		if !bytes.Equal(raw, original) {
			t.Fatal("MAC validation changed caller's request")
		}
		_, err = s.handleEAP([]byte{3, 0x87, 0, 4})
		if code&0x8000 == 0 && err == nil {
			t.Fatal("protected failure did not bind terminal state")
		}
		if code == 0x8000 && err != nil {
			t.Fatal("negotiated protected success did not allow matching EAP Success")
		}
	}
}

func TestNotificationRejectsInvalidPhaseMACAndStructure(t *testing.T) {
	for _, variant := range []string{"bad MAC", "missing MAC", "zero MAC", "post before Challenge", "pre after Challenge", "P/S contradiction", "pre with MAC", "success without negotiation", "duplicate notification", "duplicate MAC", "foreign mandatory attr", "bad attr length", "trailing bytes", "method mismatch", "bad Challenge not authenticated"} {
		t.Run(variant, func(t *testing.T) {
			s, key := notificationFullSession(t, true)
			raw := notificationWire(0x8000, key)
			switch variant {
			case "bad MAC":
				raw[len(raw)-1] ^= 1
			case "missing MAC":
				raw = notificationWire(0x8000, nil)
			case "zero MAC":
				clear(raw[16:32])
			case "post before Challenge":
				s = NewSession(&Config{SIM: &diagnosticSIM{}}, nil)
				s.eapKAut = bytes.Clone(key)
			case "pre after Challenge":
				raw = notificationWire(0x4000, nil)
			case "P/S contradiction":
				s = NewSession(&Config{SIM: &diagnosticSIM{}}, nil)
				raw = notificationWire(0xc000, nil)
			case "pre with MAC":
				s = NewSession(&Config{SIM: &diagnosticSIM{}}, nil)
				raw = notificationWire(0x4001, key)
			case "success without negotiation":
				s, key = notificationFullSession(t, false)
				raw = notificationWire(0x8000, key)
			case "duplicate notification":
				raw = append(raw, 12, 1, 0x80, 0)
				binary.BigEndian.PutUint16(raw[2:4], uint16(len(raw)))
			case "duplicate MAC":
				raw = append(raw, 11, 5, 0, 0)
				raw = append(raw, make([]byte, 16)...)
				binary.BigEndian.PutUint16(raw[2:4], uint16(len(raw)))
			case "foreign mandatory attr":
				raw = append(raw, 13, 1, 0, 0)
				binary.BigEndian.PutUint16(raw[2:4], uint16(len(raw)))
			case "bad attr length":
				raw[9] = 0
			case "trailing bytes":
				raw = append(raw, 0)
			case "method mismatch":
				raw[4] = 50
			case "bad Challenge not authenticated":
				provider := &vectorSIM{res: bytes.Repeat([]byte{0x52}, 8), ck: bytes.Repeat([]byte{0x43}, 16), ik: bytes.Repeat([]byte{0x49}, 16)}
				s = NewSession(&Config{SIM: provider}, nil)
				bad := referenceChallenge(key, true)
				bad[len(bad)-1] ^= 1
				if _, err := s.handleEAP(bad); err == nil {
					t.Fatal("invalid Challenge precondition accepted")
				}
				s.eapKAut = bytes.Clone(key)
			}
			if variant == "duplicate notification" || variant == "foreign mandatory attr" {
				clear(raw[16:32])
				m := hmac.New(sha1.New, key)
				m.Write(raw)
				copy(raw[16:32], m.Sum(nil)[:16])
			}
			if _, err := s.handleEAP(raw); err == nil {
				t.Fatal("invalid notification accepted")
			}
		})
	}
}

func TestNotificationMACCoversOriginalReservedBytes(t *testing.T) {
	s, key := notificationFullSession(t, true)
	raw := notificationWire(0x8000, key)
	raw[6], raw[7] = 0xa5, 0xb8
	clear(raw[16:32])
	m := hmac.New(sha1.New, key)
	m.Write(raw)
	copy(raw[16:32], m.Sum(nil)[:16])
	pls, err := s.handleEAP(raw)
	if err != nil {
		t.Fatal("valid reserved bytes were normalized before MAC verification")
	}
	notificationACK(t, pls, key)
}

func TestNotificationOneRoundAndReplayOwnership(t *testing.T) {
	s, key := notificationFullSession(t, true)
	raw := notificationWire(0x8000, key)
	pls, err := s.handleEAP(raw)
	if err != nil {
		t.Fatal(err)
	}
	want := bytes.Clone(notificationACK(t, pls, key))
	pls[0].(*ikev2.EncryptedPayloadEAP).EAPMessage[0] = 100
	pls, err = s.handleEAP(bytes.Clone(raw))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pls[0].(*ikev2.EncryptedPayloadEAP).EAPMessage, want) {
		t.Fatal("replay reply aliases prior caller")
	}
	if _, err := s.handleEAP([]byte{3, 0x88, 0, 4}); err == nil {
		t.Fatal("foreign terminal identifier accepted after Notification")
	}
	other := notificationWire(0x8001, key)
	if _, err := s.handleEAP(other); err == nil {
		t.Fatal("more than one notification round accepted")
	}
	if _, err := s.handleEAP(referenceChallenge(key, true)); err == nil {
		t.Fatal("notification exchange reopened authentication")
	}
	s.resetAKAIdentity()
	if _, err := s.handleEAP(raw); err == nil {
		t.Fatal("old auth generation notification accepted after reset")
	}
}

func TestNotificationNegotiationRequiresSuccessIndication(t *testing.T) {
	s, _ := notificationFullSession(t, true)
	if _, err := s.handleEAP([]byte{3, 0x88, 0, 4}); err == nil {
		t.Fatal("negotiated protected result skipped before EAP Success")
	}
}

func TestNotificationInvalidResultNegotiationStopsBeforeSIM(t *testing.T) {
	for _, method := range []byte{23, 50} {
		provider := &diagnosticSIM{}
		s := NewSession(&Config{SIM: provider}, nil)
		raw := diagnosticChallenge(method)
		raw = append(raw, 135, 2, 0, 0, 0, 0, 0, 0)
		binary.BigEndian.PutUint16(raw[2:4], uint16(len(raw)))
		if _, err := s.handleEAP(raw); err == nil || provider.akaCalls != 0 {
			t.Fatal("invalid result-indication negotiation accessed SIM")
		}
	}
}

type notificationTrackingSIM struct {
	diagnosticSIM
	reads atomic.Int32
}

func (s *notificationTrackingSIM) GetIMSI() (string, error) {
	s.reads.Add(1)
	return s.diagnosticSIM.GetIMSI()
}

func TestNotificationConnectSendsACKThenTerminatesFailure(t *testing.T) {
	peer := newAKAWirePeer(t)
	provider := &notificationTrackingSIM{}
	s := NewSession(&Config{SIM: provider, LocalAddr: "127.0.0.1", EpDGAddr: "127.0.0.1", EpDGPort: uint16(peer.conn.LocalAddr().(*net.UDPAddr).Port), FastReauthID: "synthetic@invalid"}, nil)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	finished := make(chan error, 1)
	done := make(chan struct{})
	go func() { finished <- s.Connect(ctx); close(done) }()
	t.Cleanup(func() { cancel(); s.Shutdown(); <-done })
	peer.negotiate(t)
	peer.decrypt(t, peer.receive(t))
	before := provider.reads.Load()
	request := notificationWire(0x4000, nil)
	peer.send(t, peer.protect(t, []akaWirePayload{{kind: 48, body: request}}))
	ack := peer.decrypt(t, peer.receive(t))
	if len(ack) != 1 || !bytes.Equal(ack[0].body, []byte{2, 0x87, 0, 8, 23, 12, 0, 0}) {
		t.Fatal("normal Connect did not transmit the exact failure ACK")
	}
	// Even a valid protected Success cannot reverse a Notification failure.
	peer.send(t, peer.protect(t, []akaWirePayload{{kind: 48, body: []byte{3, 0x88, 0, 4}}}))
	select {
	case err := <-finished:
		if err == nil || !strings.Contains(err.Error(), "notification failure") {
			t.Fatal("ACK was not followed by terminal notification failure")
		}
	case <-ctx.Done():
		t.Fatal("notification failure did not terminate")
	}
	if provider.reads.Load() != before || provider.akaCalls != 0 || s.ChildSAOut != nil {
		t.Fatal("failure notification read SIM or committed Child")
	}
}

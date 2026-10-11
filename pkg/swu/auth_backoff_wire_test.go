package swu

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/1239t/swu-go/pkg/eap"
	"github.com/1239t/swu-go/pkg/ikev2"
)

// TS24.302 8.2.9.1: one length octet, then the value part of
// TS24.008 10.5.7.4a GPRS Timer3. These are literal independent vectors,
// never four-byte seconds or the production timer encoder.
func TestAUTHBackoffClassifierUsesCanonicalTimerValues(t *testing.T) {
	for _, vector := range []struct {
		value    byte
		seconds  uint32
		category RejectCategory
	}{
		{0x01, 600, RejectBackoff}, {0x21, 3600, RejectBackoff}, {0x41, 36000, RejectBackoff},
		{0x61, 2, RejectBackoff}, {0x81, 30, RejectBackoff}, {0xa1, 60, RejectBackoff},
		{0x00, 0, RejectBackoff}, {0x1f, 18600, RejectBackoff}, {0x3f, 111600, RejectBackoff},
		{0x5f, 1116000, RejectBackoff}, {0x7f, 62, RejectBackoff}, {0x9f, 930, RejectBackoff},
		{0xbf, 1860, RejectBackoff}, {0xe0, 0, RejectNoRetry}, {0xff, 0, RejectNoRetry},
	} {
		t.Run(fmt.Sprintf("%02x", vector.value), func(t *testing.T) {
			rej := ClassifyReject(41041, []byte{1, vector.value})
			if rej.Category != vector.category || rej.Backoff != vector.seconds {
				t.Fatal("canonical Timer3 vector changed unit/value/zero/deactivation semantics")
			}
		})
	}
}

func TestAUTHBackoffClassifierNeverGuessesSixtySeconds(t *testing.T) {
	for _, data := range [][]byte{nil, {1}, {0, 0x21}, {2, 0x21}, {1, 0x21, 0}, {0, 0, 14, 16}, {1, 0xc1}} {
		rej := ClassifyReject(41041, data)
		if rej.Category != RejectTransient || rej.Backoff != 0 {
			t.Fatal("invalid timer synthesized a retry deadline")
		}
	}
}

func backoffAUTHSession(t *testing.T, authenticated bool) *Session {
	t.Helper()
	s, _ := newPostEAPSession(t)
	if authenticated {
		s.completedEAPMethod(eap.TypeAKA, bytes.Repeat([]byte{3}, 16), false, false, 0, nil)
	}
	return s
}

func backoffAUTHInput() []ikev2.Payload {
	return []ikev2.Payload{&ikev2.EncryptedPayloadNotify{NotifyType: 10500}, &ikev2.EncryptedPayloadNotify{NotifyType: 41041, NotifyData: []byte{1, 0x21}}}
}

func TestAUTHBackoffFinalAndEAPPathsCombineErrorAndTimer(t *testing.T) {
	for _, final := range []bool{false, true} {
		for _, reverse := range []bool{false, true} {
			s := backoffAUTHSession(t, true)
			input := backoffAUTHInput()
			if reverse {
				input[0], input[1] = input[1], input[0]
			}
			var err error
			if final {
				err = s.handleIKEAuthFinalResp(wrapAuth(t, s, input))
			} else {
				_, _, err = s.processIKEAuthEAPRound(input)
			}
			var rejected *RejectError
			if !errors.As(err, &rejected) || rejected.NotifyType != 10500 || rejected.Category != RejectBackoff || rejected.Backoff != 3600 {
				t.Fatal("AUTH path lost the authenticated error/timer association")
			}
			if s.ChildSAOut != nil || s.ChildSAIn != nil {
				t.Fatal("error/timer committed Child SA")
			}
		}
	}
}

func TestAUTHBackoffRejectsInvalidOrUnboundTimer(t *testing.T) {
	for _, variant := range []string{"pre-auth", "timer alone", "duplicate timer", "multiple errors", "bad length", "old four bytes", "SPI present", "wrong protocol", "periodic-only unit"} {
		t.Run(variant, func(t *testing.T) {
			s := backoffAUTHSession(t, variant != "pre-auth")
			input := backoffAUTHInput()
			timer := input[1].(*ikev2.EncryptedPayloadNotify)
			switch variant {
			case "timer alone":
				input = input[1:]
			case "duplicate timer":
				input = append(input, &ikev2.EncryptedPayloadNotify{NotifyType: 41041, NotifyData: []byte{1, 0x21}})
			case "multiple errors":
				input = append(input, &ikev2.EncryptedPayloadNotify{NotifyType: 9001})
			case "bad length":
				timer.NotifyData = []byte{2, 0x21}
			case "old four bytes":
				timer.NotifyData = []byte{0, 0, 14, 16}
			case "SPI present":
				timer.SPI = []byte{1}
			case "wrong protocol":
				timer.ProtocolID = 3
			case "periodic-only unit":
				timer.NotifyData = []byte{1, 0xc1}
			}
			err := s.handleIKEAuthFinalResp(wrapAuth(t, s, input))
			var rejected *RejectError
			if err == nil || errors.As(err, &rejected) || !strings.Contains(err.Error(), "BACKOFF_TIMER") {
				t.Fatal("invalid or unbound timer did not fail at its own boundary")
			}
		})
	}
}

func TestAUTHBackoffUnknownStatusDoesNotBecomeError(t *testing.T) {
	s := backoffAUTHSession(t, true)
	err := s.handleIKEAuthFinalResp(wrapAuth(t, s, []ikev2.Payload{&ikev2.EncryptedPayloadNotify{NotifyType: 41042, NotifyData: []byte{1, 0x21}}}))
	var rejected *RejectError
	if errors.As(err, &rejected) {
		t.Fatal("unknown status notify broadened into rejection")
	}
}

func TestAUTHBackoffConnectConsumesIndependentProtectedTimer(t *testing.T) {
	peer := newAKAWirePeer(t)
	p := &vectorSIM{res: bytes.Repeat([]byte{0x52}, 8), ck: bytes.Repeat([]byte{0x43}, 16), ik: bytes.Repeat([]byte{0x49}, 16)}
	key := referenceAKAKeys(p, false)[16:32]
	s := NewSession(&Config{SIM: p, LocalAddr: "127.0.0.1", EpDGAddr: "127.0.0.1", EpDGPort: uint16(peer.conn.LocalAddr().(*net.UDPAddr).Port)}, nil)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	finished := make(chan error, 1)
	done := make(chan struct{})
	go func() { finished <- s.Connect(ctx); close(done) }()
	t.Cleanup(func() { cancel(); s.Shutdown(); <-done })
	peer.negotiate(t)
	peer.decrypt(t, peer.receive(t))
	peer.send(t, peer.protect(t, []akaWirePayload{{kind: 48, body: referenceChallenge(key, false)}}))
	response := peer.decrypt(t, peer.receive(t))
	if len(response) != 1 || !bytes.Equal(response[0].body, referenceResponse(p.res, key, false)) {
		t.Fatal("independent valid Challenge/MAC precondition failed")
	}
	peer.send(t, peer.protect(t, []akaWirePayload{{kind: 41, body: []byte{1, 0, 0x29, 0x04}}, {kind: 41, body: []byte{1, 0, 0xa0, 0x51, 1, 0x21}}}))
	select {
	case err := <-finished:
		var rejected *RejectError
		if !errors.As(err, &rejected) || rejected.NotifyType != 10500 || rejected.Category != RejectBackoff || rejected.Backoff != 3600 {
			t.Fatal("normal Connect did not preserve independent authenticated network-failure timer")
		}
	case <-ctx.Done():
		t.Fatal("timer terminal did not complete Connect")
	}
	if p.calls != 1 || s.ChildSAOut != nil {
		t.Fatal("timer rejection retriggered SIM or committed Child")
	}
}

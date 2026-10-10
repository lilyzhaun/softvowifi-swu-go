package swu

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/1239t/swu-go/pkg/ikev2"
)

func TestFragmentPMTUProbeReplacesOnlyAfterAuthentication(t *testing.T) {
	s, _ := newPostEAPSession(t)
	inner := []byte{0, 0, 0, 8, 0, 0, 0x40, 0x0c}
	first := independentSKF(t, s, inner[:4], ikev2.N, 1, 2, ikev2.IKE_AUTH, 9, true)
	if _, _, err := s.decryptAndParse(first); err != nil {
		t.Fatal(err)
	}
	// A larger total authenticated by the peer resets every old fragment,
	// even when the new probe's last fragment arrives first.
	probe := independentSKF(t, s, inner[5:], 0, 3, 3, ikev2.IKE_AUTH, 9, true)
	bad := bytes.Clone(probe)
	bad[len(bad)-1] ^= 1
	if _, _, err := s.decryptAndParse(bad); err == nil {
		t.Fatal("unauthenticated PMTU reset accepted")
	}
	for _, set := range s.fragmentBuf.frags {
		if set.total != 2 || len(set.received) != 1 {
			t.Fatal("invalid ICV reset the existing probe")
		}
	}
	if _, _, err := s.decryptAndParse(probe); err != nil {
		t.Fatal(err)
	}
	for _, set := range s.fragmentBuf.frags {
		if set.total != 3 || len(set.received) != 1 || set.first != 0 {
			t.Fatal("new probe retained an old first fragment")
		}
	}
	if _, _, err := s.decryptAndParse(first); err == nil {
		t.Fatal("old smaller PMTU probe mixed with new probe")
	}
	for number, chunk := range [][]byte{inner[:2], inner[2:5]} {
		firstType := ikev2.NoNextPayload
		if number == 0 {
			firstType = ikev2.N
		}
		_, payloads, err := s.decryptAndParse(independentSKF(t, s, chunk, firstType, uint16(number+1), 3, ikev2.IKE_AUTH, 9, true))
		if err != nil {
			t.Fatal(err)
		}
		if number == 0 && len(payloads) != 0 || number == 1 && len(payloads) != 1 {
			t.Fatal("new probe did not reassemble its own first type")
		}
	}
}

func TestFragmentSizeCountOwnershipAndExpiry(t *testing.T) {
	s, _ := newPostEAPSession(t)
	for _, pair := range [][2]uint16{{0, 2}, {1, 0}, {3, 2}, {1, 256}} {
		if _, _, err := s.decryptAndParse(independentSKF(t, s, []byte{0}, ikev2.N, pair[0], pair[1], ikev2.IKE_AUTH, 9, true)); err == nil {
			t.Fatal("invalid fragment number/total accepted")
		}
	}
	if len(s.fragmentBuf.frags) != 0 {
		t.Fatal("invalid fragment metadata allocated state")
	}
	key := fragmentKey{spii: 1, spir: 2, keys: s.Keys, exchange: ikev2.IKE_AUTH, mid: 9, flags: ikev2.FlagResponse}
	now := time.Unix(100, 0)
	plain := []byte{0, 0, 0, 8}
	if _, _, err := s.fragmentBuf.addFragment(key, ikev2.N, 1, 2, plain, now); err != nil {
		t.Fatal(err)
	}
	plain[0] = 100
	set := s.fragmentBuf.frags[key]
	if set.received[1][0] != 0 {
		t.Fatal("fragment buffer aliases its decoded input")
	}
	if _, _, err := s.fragmentBuf.addFragment(key, ikev2.N, 1, 2, []byte{0, 0, 0, 8}, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if !set.expires.Equal(now.Add(fragmentTimeout)) {
		t.Fatal("duplicate extended queue lifetime")
	}
	s.fragmentBuf.expire(now.Add(fragmentTimeout))
	if len(s.fragmentBuf.frags) != 0 {
		t.Fatal("expired partial message retained")
	}
	if _, _, err := s.fragmentBuf.addFragment(key, ikev2.N, 1, 2, bytes.Repeat([]byte{1}, maxFragmentedPacket), now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.fragmentBuf.addFragment(key, 0, 2, 2, []byte{0}, now); err == nil {
		t.Fatal("oversized fragmented message accepted")
	}
	if len(s.fragmentBuf.frags) != 0 {
		t.Fatal("oversized partial message not discarded")
	}
}

func TestFragmentWindowTimeoutAndSKCompletionDropPartial(t *testing.T) {
	for _, variant := range []string{"timeout", "stop", "SK completion"} {
		t.Run(variant, func(t *testing.T) {
			s, _ := newPostEAPSession(t)
			manager, _ := newIdleWindow(t, 1)
			s.taskMgr = manager
			manager.responseValidator = s.validateWindowResponse
			manager.responseCleanup = func(msg *OutgoingMessage) { s.fragmentBuf.discardResponse(msg.Exchange, msg.MsgID) }
			completion := manager.EnqueueRequest(9, ikev2.IKE_AUTH, nil, nil)
			s.dispatchReceivedIKE(independentSKF(t, s, []byte{0, 0}, ikev2.N, 1, 2, ikev2.IKE_AUTH, 9, true), nil)
			if len(s.fragmentBuf.frags) != 1 {
				t.Fatal("missing authenticated partial response")
			}
			switch variant {
			case "timeout":
				manager.pending[9].Deadline = time.Unix(0, 0)
				manager.pending[9].RetryCount = manager.pending[9].MaxRetries
				manager.checkTimeouts()
			case "stop":
				manager.Stop()
				manager.windowLoop()
			case "SK completion":
				s.dispatchReceivedIKE(encodePeerPacket(t, s, nil, ikev2.IKE_AUTH, 9, true), nil)
			}
			select {
			case <-completion:
			default:
				t.Fatal("terminal request did not complete")
			}
			if len(s.fragmentBuf.frags) != 0 {
				t.Fatal("terminal request leaked partial response")
			}
		})
	}
}

func TestFragmentCancellationAndAuthGenerationClear(t *testing.T) {
	for _, variant := range []string{"reset", "shutdown", "dispatcher canceled", "dispatcher socket closed"} {
		t.Run(variant, func(t *testing.T) {
			s, _ := newPostEAPSession(t)
			_, _, err := s.decryptAndParse(independentSKF(t, s, []byte{0}, ikev2.N, 1, 2, ikev2.INFORMATIONAL, 9, false))
			if err != nil {
				t.Fatal(err)
			}
			switch variant {
			case "reset":
				s.resetIKEAuthTranscripts()
			case "shutdown":
				s.Shutdown()
			default:
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				s.ctx = ctx
				transport := &pipeTransport{ike: make(chan []byte)}
				s.socket = transport
				if variant == "dispatcher canceled" {
					cancel()
				} else {
					close(transport.ike)
				}
				s.ikeDispatchLoop()
			}
			if len(s.fragmentBuf.frags) != 0 {
				t.Fatal("old SA/auth lifecycle leaked fragment queue")
			}
		})
	}
}

func TestFragmentIncomingControlWaitsAndUsesParsedMessage(t *testing.T) {
	s, _ := newPostEAPSession(t)
	transport := &pipeTransport{sent: make(chan []byte, 4)}
	s.socket = transport
	s.ikeControlAlive = true
	inner := []byte{0, 0, 0, 8, 0, 0, 0x40, 0x0c}
	one := independentSKF(t, s, inner[:3], ikev2.N, 1, 2, ikev2.INFORMATIONAL, 9, false)
	two := independentSKF(t, s, inner[3:], 0, 2, 2, ikev2.INFORMATIONAL, 9, false)
	commits := 0
	s.dispatchReceivedIKE(two, func() error { commits++; return nil })
	if len(transport.sent) != 0 || commits != 0 {
		t.Fatal("incomplete request interpreted as empty DPD")
	}
	s.dispatchReceivedIKE(one, func() error { commits++; return nil })
	if len(transport.sent) != 1 || commits != 1 {
		t.Fatal("complete request failed after a second destructive decryption")
	}
	raw := <-transport.sent
	if mid, _, err := testPeerReceiver(s).decryptAndParse(raw); err != nil || mid != 9 {
		t.Fatal("protected response lost original MID")
	}
	s.dispatchReceivedIKE(two, func() error { commits++; return nil })
	if len(transport.sent) != 0 || commits != 1 {
		t.Fatal("non-first replay reexecuted or retransmitted the response")
	}
	s.dispatchReceivedIKE(one, func() error { commits++; return nil })
	if len(transport.sent) != 1 || commits != 1 || !bytes.Equal(<-transport.sent, raw) {
		t.Fatal("first replay did not retransmit only the cached response")
	}
}

func TestFragmentRawFinalHandlerCannotConsumePartial(t *testing.T) {
	s, calls := newPostEAPSession(t)
	before := snapPostEAP(s, *calls)
	raw := independentSKF(t, s, []byte{0}, ikev2.AUTH, 1, 2, ikev2.IKE_AUTH, 9, true)
	if err := s.handleIKEAuthFinalResp(raw); !errors.Is(err, errFragmentIncomplete) {
		t.Fatal("raw final handler accepted incomplete response")
	}
	assertSnapUnchanged(t, before, snapPostEAP(s, *calls))
}

func TestFragmentWindowRetransmitsAllRequestPieces(t *testing.T) {
	s, _ := newPostEAPSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	s.ctx = ctx
	s.fragmentationSupported, s.ikeFragmentMTU = true, 128
	manager, sent := newIdleWindow(t, 1)
	s.taskMgr = manager
	manager.responseValidator = s.validateWindowResponse
	result := make(chan error, 1)
	go func() {
		message, err := s.sendEncryptedWithRetry([]ikev2.Payload{&ikev2.EncryptedPayloadNotify{NotifyType: 16432, NotifyData: bytes.Repeat([]byte{3}, 200)}}, ikev2.INFORMATIONAL)
		if err == nil && (message == nil || len(message.payloads) != 1 || message.payloads[0].Type() != ikev2.N) {
			err = errors.New("complete reply payloads not delivered")
		}
		result <- err
	}()
	var packets [][]byte
	select {
	case packets = <-sent:
	case <-ctx.Done():
		t.Fatal("missing outgoing fragmented request")
	}
	if len(packets) < 2 {
		t.Fatal("fragmentation path was not exercised")
	}
	var mid uint32
	for _, raw := range packets {
		h, err := ikev2.DecodeHeader(raw)
		if err != nil || h.NextPayload != ikev2.EncryptedFragment {
			t.Fatal("bad outgoing fragment")
		}
		if mid == 0 {
			mid = h.MessageID
		}
		if mid != h.MessageID {
			t.Fatal("fragment request changed MID")
		}
	}
	manager.mu.Lock()
	manager.pending[mid].Deadline = time.Unix(0, 0)
	manager.mu.Unlock()
	manager.checkTimeouts()
	select {
	case retry := <-sent:
		if len(retry) != len(packets) {
			t.Fatal("retransmission lost fragments")
		}
		for index := range retry {
			if !bytes.Equal(retry[index], packets[index]) {
				t.Fatal("retry reallocated or reencrypted the request")
			}
		}
	default:
		t.Fatal("missing whole-request retry")
	}
	inner := []byte{0, 0, 0, 8, 0, 0, 0x40, 0x0c}
	s.dispatchReceivedIKE(independentSKF(t, s, inner[:3], ikev2.N, 1, 2, ikev2.INFORMATIONAL, mid, true), nil)
	select {
	case <-result:
		t.Fatal("incomplete response released sender")
	default:
	}
	s.dispatchReceivedIKE(independentSKF(t, s, inner[3:], 0, 2, 2, ikev2.INFORMATIONAL, mid, true), nil)
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("sender did not receive the parsed complete response")
	}
}

func TestFragmentWaiterReceivesOnlyCompleteParsedMessage(t *testing.T) {
	s, _ := newPostEAPSession(t)
	ch := make(chan *protectedIKEMessage, 1)
	s.ikeWaiters[ikeWaitKey{exchangeType: ikev2.INFORMATIONAL, msgID: 9}] = ch
	inner := []byte{0, 0, 0, 8, 0, 0, 0x40, 0x0c}
	s.dispatchReceivedIKE(independentSKF(t, s, inner[:4], ikev2.N, 1, 2, ikev2.INFORMATIONAL, 9, true), nil)
	if len(ch) != 0 {
		t.Fatal("waiter got incomplete fragment")
	}
	s.dispatchReceivedIKE(independentSKF(t, s, inner[4:], 0, 2, 2, ikev2.INFORMATIONAL, 9, true), nil)
	select {
	case msg := <-ch:
		if msg.msgID != 9 || len(msg.payloads) != 1 {
			t.Fatal("waiter lost complete payloads")
		}
	default:
		t.Fatal("complete waiter not fulfilled")
	}
}

func TestFragmentReplyCacheBoundAndExpiry(t *testing.T) {
	fb := newFragmentBuffer()
	now := time.Unix(100, 0)
	for mid := uint32(0); mid <= maxFragmentSets; mid++ {
		fb.processed(fragmentKey{mid: mid}, now.Add(time.Duration(mid)*time.Second))
	}
	if len(fb.replies) != maxFragmentSets {
		t.Fatal("completed request cache unbounded")
	}
	if _, exists := fb.replies[fragmentKey{mid: 0}]; exists {
		t.Fatal("oldest completed request not evicted")
	}
	fb.expire(now.Add(fragmentTimeout + maxFragmentSets*time.Second))
	if len(fb.replies) != 0 {
		t.Fatal("completed request replies survived expiry")
	}
}

package swu

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	swucrypto "github.com/1239t/swu-go/pkg/crypto"
	"github.com/1239t/swu-go/pkg/ikev2"
)

type midHookEncryption struct {
	swucrypto.Encrypter
	hook func()
	once atomic.Bool
}

func (e *midHookEncryption) Encrypt(plain, key, iv, aad []byte) ([]byte, error) {
	if e.once.CompareAndSwap(false, true) {
		e.hook()
	}
	return e.Encrypter.Encrypt(plain, key, iv, aad)
}

func newMIDTransactionSession(t *testing.T, aead bool) (*Session, chan [][]byte) {
	t.Helper()
	s := fragmentFixture(t, aead, false)
	s.SequenceNumber.Store(1)
	s.ctx, s.cancel = context.WithTimeout(t.Context(), 2*time.Second)
	wire := make(chan [][]byte, 8)
	s.taskMgr = NewTaskManager(s.ctx, &RetryConfig{MaxRetries: 1, InitialTimeout: time.Hour, BackoffFactor: 2}, 5, func(packets [][]byte) error { wire <- packets; return nil })
	s.taskMgr.responseValidator = s.validateWindowResponse
	s.taskMgr.responseCleanup = func(msg *OutgoingMessage) { s.fragmentBuf.discardResponse(msg.Exchange, msg.MsgID) }
	t.Cleanup(func() { s.cancel(); s.taskMgr.Stop() })
	return s, wire
}

func midRequestPackets(t *testing.T, s *Session, wire <-chan [][]byte) [][]byte {
	t.Helper()
	select {
	case packets := <-wire:
		return packets
	case <-s.ctx.Done():
		t.Fatal("request was not sent on the window")
		return nil
	}
}

func TestMIDTransactionKeepsAllocatedNotLatestNumber(t *testing.T) {
	for _, aead := range []bool{false, true} {
		for _, fragmented := range []bool{false, true} {
			t.Run(fmt.Sprintf("AEAD=%v/fragmented=%v", aead, fragmented), func(t *testing.T) {
				s, wire := newMIDTransactionSession(t, aead)
				s.EncAlg = &midHookEncryption{Encrypter: s.EncAlg, hook: func() { s.NextSequenceNumber() }}
				var payloads []ikev2.Payload
				if fragmented {
					s.fragmentationSupported, s.ikeFragmentMTU = true, 128
					payloads = []ikev2.Payload{&ikev2.EncryptedPayloadNotify{NotifyType: 16432, NotifyData: bytes.Repeat([]byte{1}, 200)}}
				}
				finished := make(chan error, 1)
				go func() {
					message, err := s.sendEncryptedWithRetry(payloads, ikev2.INFORMATIONAL)
					if err == nil && message.msgID != 1 {
						err = fmt.Errorf("wrong response MID %d", message.msgID)
					}
					finished <- err
				}()
				packets := midRequestPackets(t, s, wire)
				if fragmented && len(packets) < 2 || !fragmented && len(packets) != 1 {
					t.Fatal("fragment path precondition changed")
				}
				for _, raw := range packets {
					h, err := ikev2.DecodeHeader(raw)
					if err != nil || h.MessageID != 1 {
						t.Fatal("wire did not use originally allocated MID")
					}
				}
				s.taskMgr.mu.Lock()
				request := s.taskMgr.pending[1]
				count := len(s.taskMgr.pending)
				s.taskMgr.mu.Unlock()
				if request == nil || count != 1 {
					t.Fatal("window inferred MID from the later global sequence")
				}
				if s.lastEncryptedMsgID != 1 {
					t.Fatal("debug retransmission state lost allocated MID")
				}
				s.dispatchReceivedIKE(independentSKF(t, s, nil, 0, 1, 1, ikev2.INFORMATIONAL, 1, true), nil)
				select {
				case err := <-finished:
					if err != nil {
						t.Fatal(err)
					}
				case <-s.ctx.Done():
					t.Fatal("original MID response cannot complete request")
				}
			})
		}
	}
}

func TestMIDTransactionTwoConcurrentRequestsCompleteSeparately(t *testing.T) {
	s, wire := newMIDTransactionSession(t, false)
	start := make(chan struct{})
	type completion struct {
		mid uint32
		err error
	}
	results := make(chan completion, 2)
	var workers sync.WaitGroup
	for range 2 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			message, err := s.sendEncryptedWithRetry(nil, ikev2.INFORMATIONAL)
			var mid uint32
			if message != nil {
				mid = message.msgID
			}
			results <- completion{mid, err}
		}()
	}
	t.Cleanup(func() { s.cancel(); workers.Wait() })
	close(start)
	first, second := midRequestPackets(t, s, wire), midRequestPackets(t, s, wire)
	a, err := ikev2.DecodeHeader(first[0])
	if err != nil {
		t.Fatal(err)
	}
	b, err := ikev2.DecodeHeader(second[0])
	if err != nil {
		t.Fatal(err)
	}
	if a.MessageID == b.MessageID {
		t.Fatal("two requests allocated the same MID")
	}
	s.taskMgr.mu.Lock()
	_, hasA := s.taskMgr.pending[a.MessageID]
	_, hasB := s.taskMgr.pending[b.MessageID]
	s.taskMgr.mu.Unlock()
	if !hasA || !hasB {
		t.Fatal("concurrent wire MIDs do not match their pending owners")
	}
	s.dispatchReceivedIKE(encodePeerPacket(t, s, nil, ikev2.INFORMATIONAL, a.MessageID+99, true), nil)
	if len(results) != 0 {
		t.Fatal("foreign MID completed a request")
	}
	// Reverse completion order, independent of the order sent on the socket.
	s.dispatchReceivedIKE(encodePeerPacket(t, s, nil, ikev2.INFORMATIONAL, b.MessageID, true), nil)
	select {
	case done := <-results:
		if done.err != nil || done.mid != b.MessageID {
			t.Fatal("first response completed another request")
		}
	case <-s.ctx.Done():
		t.Fatal("missing first completion")
	}
	s.taskMgr.mu.Lock()
	remaining := len(s.taskMgr.pending)
	_, hasA = s.taskMgr.pending[a.MessageID]
	s.taskMgr.mu.Unlock()
	if remaining != 1 || !hasA {
		t.Fatal("completion removed the other in-flight request")
	}
	s.dispatchReceivedIKE(encodePeerPacket(t, s, nil, ikev2.INFORMATIONAL, a.MessageID, true), nil)
	select {
	case done := <-results:
		if done.err != nil || done.mid != a.MessageID {
			t.Fatal("second response completed another request")
		}
	case <-s.ctx.Done():
		t.Fatal("missing second completion")
	}
	workers.Wait()
}

func TestMIDTransactionFreshSAGenerationRejectsOldResponse(t *testing.T) {
	old, _ := newMIDTransactionSession(t, false)
	oldResponse := encodePeerPacket(t, old, nil, ikev2.INFORMATIONAL, 1, true)
	s, wire := newMIDTransactionSession(t, false)
	s.SPIi++
	s.SPIr++
	finished := make(chan error, 1)
	go func() { _, err := s.sendEncryptedWithRetry(nil, ikev2.INFORMATIONAL); finished <- err }()
	midRequestPackets(t, s, wire)
	s.dispatchReceivedIKE(oldResponse, nil)
	select {
	case <-finished:
		t.Fatal("old SA response completed reused MID")
	default:
	}
	s.dispatchReceivedIKE(encodePeerPacket(t, s, nil, ikev2.INFORMATIONAL, 1, true), nil)
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal(err)
		}
	case <-s.ctx.Done():
		t.Fatal("new SA valid response could not complete its own reused MID")
	}
}

func TestMIDTransactionOutboundSnapshotAndActivityDoNotRegress(t *testing.T) {
	s, _ := newMIDTransactionSession(t, false)
	past, later := time.Unix(100, 0), time.Unix(200, 0)
	s.initializeOutboundActivity(past)
	s.recordOutboundActivity(later)
	s.initializeOutboundActivity(past)
	s.recordOutboundActivity(past)
	packet, err := s.encryptAndWrapWithMsgID(nil, ikev2.INFORMATIONAL, 7, false)
	if err != nil {
		t.Fatal(err)
	}
	s.recordEncryptedRequest(packet, 7, past)
	if !s.outboundActivityTime().Equal(later) {
		t.Fatal("older kernel/keepalive timestamp overwrote a later request")
	}
	s.outboundActivityMu.RLock()
	saved, savedID := s.lastEncryptedMsg, s.lastEncryptedMsgID
	s.outboundActivityMu.RUnlock()
	h, err := ikev2.DecodeHeader(saved)
	if err != nil || h.MessageID != savedID || savedID != 7 {
		t.Fatal("outgoing debug packet/MID snapshot split across transactions")
	}
}

package swu

import (
	"crypto/sha256"
	"time"

	"github.com/1239t/swu-go/pkg/ikev2"
)

// A single bounded overlap accepts only the rekey replay and the old IKE
// Delete. It cannot delete the children now inherited by the new SA.
type retiredIKESA struct {
	codec       *Session
	expires     time.Time
	rekeyMID    uint32
	requestHash [32]byte
	reply       []byte
	deleteMID   uint32
	deleteHash  [32]byte
	deleteReply []byte
}

func ikePayloadHash(payloads []ikev2.Payload) [32]byte {
	h := sha256.New()
	for _, p := range payloads {
		data, _ := p.Encode()
		h.Write([]byte{byte(p.Type()), byte(len(data) >> 8), byte(len(data))})
		h.Write(data)
	}
	var hash [32]byte
	copy(hash[:], h.Sum(nil))
	return hash
}

// Caller owns admission. No new old-generation request can enqueue here.
func (s *Session) ikeRequestsPending() bool {
	if s.taskMgr != nil {
		s.taskMgr.mu.Lock()
		busy := len(s.taskMgr.pending) > 0 || len(s.taskMgr.queue) > 0
		s.taskMgr.mu.Unlock()
		if busy {
			return true
		}
	}
	s.ikeMu.Lock()
	defer s.ikeMu.Unlock()
	return len(s.ikeWaiters) > 0
}

// Caller owns the crypto write lock. No mutexes or mutable buffers are copied.
func (s *Session) retainIKEForPeerDelete(mid uint32, request []ikev2.Payload, reply []byte) {
	codec := &Session{SPIi: s.SPIi, SPIr: s.SPIr, Keys: s.Keys, EncAlg: s.EncAlg, IntegAlg: s.IntegAlg, localResponder: s.localResponder, ikeIsAEAD: s.ikeIsAEAD, ikeEncrID: s.ikeEncrID, Logger: s.Logger, fragmentBuf: newFragmentBuffer()}
	s.retiredIKE = &retiredIKESA{codec: codec, expires: time.Now().Add(3 * time.Minute), rekeyMID: mid, requestHash: ikePayloadHash(request), reply: append([]byte(nil), reply...)}
}

func (s *Session) expireRetiredIKE(now time.Time) {
	s.ikeCryptoMu.Lock()
	defer s.ikeCryptoMu.Unlock()
	if s.retiredIKE != nil && !now.Before(s.retiredIKE.expires) {
		s.retiredIKE = nil
	}
}

func (s *Session) dispatchRetiredIKE(h *ikev2.IKEHeader, data []byte) bool {
	s.ikeCryptoMu.RLock()
	old := s.retiredIKE
	s.ikeCryptoMu.RUnlock()
	if old == nil || h.SPIi != old.codec.SPIi || h.SPIr != old.codec.SPIr {
		return false
	}
	if !time.Now().Before(old.expires) || h.Flags&ikev2.FlagResponse != 0 {
		return true
	}
	message, err := old.codec.decodeProtectedIKE(data)
	if err != nil || message == nil {
		return true
	}
	if h.ExchangeType == ikev2.CREATE_CHILD_SA && h.MessageID == old.rekeyMID && ikePayloadHash(message.payloads) == old.requestHash {
		_ = s.socket.SendIKE(old.reply)
		return true
	}
	if h.ExchangeType == ikev2.INFORMATIONAL && len(message.payloads) == 1 {
		if del, ok := message.payloads[0].(*ikev2.EncryptedPayloadDelete); ok && del.ProtocolID == ikev2.ProtoIKE && del.SPISize == 0 && del.NumSPIs == 0 && len(del.SPIs) == 0 {
			if old.deleteReply != nil {
				if old.deleteMID == h.MessageID && old.deleteHash == ikePayloadHash(message.payloads) {
					_ = s.socket.SendIKE(old.deleteReply)
				}
				return true
			}
			reply, err := old.codec.encryptAndWrapWithMsgID(nil, ikev2.INFORMATIONAL, h.MessageID, true)
			if err == nil {
				old.deleteMID, old.deleteHash, old.deleteReply = h.MessageID, ikePayloadHash(message.payloads), reply
				_ = s.socket.SendIKE(reply)
			}
		}
	}
	return true
}

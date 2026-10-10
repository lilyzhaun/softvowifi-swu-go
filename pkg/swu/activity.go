package swu

import "time"

func (s *Session) initializeInboundActivity(at time.Time) {
	s.inboundActivityMu.Lock()
	defer s.inboundActivityMu.Unlock()
	if s.lastInboundTime.IsZero() {
		s.lastInboundTime = at
	}
}

func (s *Session) recordInboundActivity(at time.Time) {
	s.inboundActivityMu.Lock()
	s.lastInboundTime = at
	s.inboundActivityMu.Unlock()
}

func (s *Session) inboundIdle(at time.Time) time.Duration {
	s.inboundActivityMu.RLock()
	last := s.lastInboundTime
	s.inboundActivityMu.RUnlock()
	return at.Sub(last)
}

func (s *Session) initializeOutboundActivity(at time.Time) {
	s.outboundActivityMu.Lock()
	defer s.outboundActivityMu.Unlock()
	if s.lastOutboundTime.IsZero() {
		s.lastOutboundTime = at
	}
}

func (s *Session) recordOutboundActivity(at time.Time) {
	s.outboundActivityMu.Lock()
	defer s.outboundActivityMu.Unlock()
	if at.After(s.lastOutboundTime) {
		s.lastOutboundTime = at
	}
}

func (s *Session) outboundActivityTime() time.Time {
	s.outboundActivityMu.RLock()
	defer s.outboundActivityMu.RUnlock()
	return s.lastOutboundTime
}

func (s *Session) recordEncryptedRequest(packet []byte, mid uint32, at time.Time) {
	s.outboundActivityMu.Lock()
	defer s.outboundActivityMu.Unlock()
	s.lastEncryptedMsg, s.lastEncryptedMsgID = packet, mid
	if at.After(s.lastOutboundTime) {
		s.lastOutboundTime = at
	}
}

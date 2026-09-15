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

package swu

import (
	"sync"
	"time"
)

// A hard deadline belongs to one SA generation, independently of the worker
// awaiting its rekey response and independently of authentication expiry.
type saHardExpiry struct {
	mu      sync.Mutex
	start   sync.Once
	wake    chan struct{}
	due     time.Time
	expired bool
}

func (a *saHardExpiry) deadline() time.Time {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.due
}

func retirementDeadline(now, hard time.Time) time.Time {
	due := now.Add(3 * time.Minute)
	if !hard.IsZero() && hard.Before(due) {
		due = hard
	}
	return due
}

func (s *Session) renewHardExpiry(a *saHardExpiry, interval time.Duration, now time.Time) {
	if interval == 0 {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.expired || (s.ctx != nil && s.ctx.Err() != nil) {
		return
	}
	a.due = now.Add(interval)
	if a.wake == nil {
		a.wake = make(chan struct{}, 1)
	}
	select {
	case a.wake <- struct{}{}:
	default:
	}
}

func (s *Session) startHardExpiry(a *saHardExpiry, interval time.Duration, reason SessionDownReason) {
	if interval == 0 {
		return
	}
	a.start.Do(func() {
		a.mu.Lock()
		if a.due.IsZero() {
			a.due = time.Now().Add(interval)
		}
		if a.wake == nil {
			a.wake = make(chan struct{}, 1)
		}
		a.mu.Unlock()
		go func() {
			timer := time.NewTimer(interval)
			defer timer.Stop()
			for {
				a.mu.Lock()
				due := a.due
				a.mu.Unlock()
				timer.Reset(time.Until(due))
				select {
				case <-s.ctx.Done():
					return
				case <-a.wake:
					timer.Stop()
				case <-timer.C:
					a.mu.Lock()
					expired := !time.Now().Before(a.due) && s.ctx.Err() == nil
					if expired {
						a.expired = true
						// Linearize expiry against renewal while holding this lock.
						// External observers run only after releasing it below.
						if s.cancelCause != nil {
							s.cancelCause(&SessionClosedError{Reason: reason})
						} else if s.cancel != nil {
							s.cancel()
						}
					}
					a.mu.Unlock()
					if expired {
						s.endSession(reason, "")
						return
					}
				}
			}
		}()
	})
}

func (s *Session) renewIKEHardExpiry(now time.Time) {
	if s.prepareRenewalPolicy() == nil {
		s.renewHardExpiry(&s.ikeHardExpiry, s.renewalPolicy.IKE.HardLifetime, now)
	}
}

func (s *Session) renewChildHardExpiry(now time.Time) {
	if s.prepareRenewalPolicy() == nil {
		s.renewHardExpiry(&s.childHardExpiry, s.renewalPolicy.Child.HardLifetime, now)
	}
}

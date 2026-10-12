package swu

import (
	"encoding/binary"
	"errors"
	"sync"
	"time"

	"github.com/1239t/swu-go/pkg/ikev2"
	"github.com/1239t/swu-go/pkg/logger"
)

// Authentication survives both IKE/Child rekeys. Only a fresh Initial/AUTH
// exchange creates a fresh owner. The local policy can be earlier, never later.
type authenticationExpiry struct {
	mu            sync.Mutex
	start         sync.Once
	wake          chan struct{}
	server, local time.Time
	infoKeys      *ikev2.IKESAKeys
	infoMID       uint32
	infoSeen      bool
}

func authenticatedLifetime(payloads []ikev2.Payload) (*uint32, error) {
	var lifetime *uint32
	for _, pl := range payloads {
		if n, ok := pl.(*ikev2.EncryptedPayloadNotify); ok && n.NotifyType == ikev2.AUTH_LIFETIME {
			if lifetime != nil || n.ProtocolID != 0 || len(n.SPI) != 0 || len(n.NotifyData) != 4 {
				return nil, errors.New("invalid protected AUTH_LIFETIME")
			}
			seconds := binary.BigEndian.Uint32(n.NotifyData)
			lifetime = &seconds
		}
	}
	return lifetime, nil
}

func (s *Session) setAuthLifetime(seconds uint32, received time.Time, mid *uint32) {
	if received.IsZero() {
		received = time.Now()
	}
	a := &s.authExpiry
	s.ikeCryptoMu.RLock()
	keys := s.Keys
	s.ikeCryptoMu.RUnlock()
	a.mu.Lock()
	if mid != nil {
		// A duplicate/older request cannot extend authentication by replaying
		// its relative lifetime. New IKE generations have independent MIDs.
		if a.infoSeen && a.infoKeys == keys && *mid <= a.infoMID {
			a.mu.Unlock()
			return
		}
		a.infoSeen, a.infoKeys, a.infoMID = true, keys, *mid
	}
	duration := time.Duration(seconds) * time.Second
	// Twenty percent margin, capped at one minute; never positive jitter.
	a.server = received.Add(duration - min(duration/5, time.Minute))
	if a.wake == nil {
		a.wake = make(chan struct{}, 1)
	}
	select {
	case a.wake <- struct{}{}:
	default:
	}
	a.mu.Unlock()
	s.Logger.Info("认证寿命已安排重新认证", logger.Uint32("authLifetime", seconds), logger.Bool("informational", mid != nil))
}

func (s *Session) startIKEReauthTimer(interval time.Duration) {
	a := &s.authExpiry
	a.mu.Lock()
	a.local = time.Now().Add(interval)
	if a.wake == nil {
		a.wake = make(chan struct{}, 1)
	}
	select {
	case a.wake <- struct{}{}:
	default:
	}
	a.mu.Unlock()
	s.startAuthenticationTimer()
}

func (s *Session) startAuthenticationTimer() {
	a := &s.authExpiry
	a.start.Do(func() {
		a.mu.Lock()
		if a.wake == nil {
			a.wake = make(chan struct{}, 1)
		}
		a.mu.Unlock()
		go func() {
			timer := time.NewTimer(time.Hour)
			timer.Stop()
			defer timer.Stop()
			for {
				a.mu.Lock()
				due := a.server
				if !a.local.IsZero() && (due.IsZero() || a.local.Before(due)) {
					due = a.local
				}
				a.mu.Unlock()
				var tick <-chan time.Time
				if !due.IsZero() {
					timer.Reset(time.Until(due))
					tick = timer.C
				}
				select {
				case <-s.ctx.Done():
					return
				case <-a.wake:
					timer.Stop()
				case <-tick:
					// An authenticated policy update may race the old timer.
					a.mu.Lock()
					current := a.server
					if !a.local.IsZero() && (current.IsZero() || a.local.Before(current)) {
						current = a.local
					}
					expired := !current.IsZero() && !time.Now().Before(current)
					a.mu.Unlock()
					if expired {
						s.Reauthenticate()
						return
					}
				}
			}
		}()
	})
}

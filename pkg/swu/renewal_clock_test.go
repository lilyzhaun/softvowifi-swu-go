//go:build go1.25

package swu

import (
	"context"
	"testing"
	"testing/synctest"
	"time"

	"go.uber.org/zap"
)

func TestRenewalPolicyChangesActualNATSchedule(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := NewSession(&Config{}, zap.NewNop())
		setRenewalInput(t, s.cfg, renewalInput())
		s.ctx, s.cancel = context.WithCancel(t.Context())
		defer s.cancel()
		pipe := &renewalKeepaliveTransport{keepalives: make(chan struct{}, 4)}
		s.socket = pipe
		s.startNATKeepalive(20 * time.Second)
		synctest.Wait()
		time.Sleep(999 * time.Millisecond)
		if len(pipe.keepalives) != 0 {
			t.Fatal("NAT keepalive fired before configured idle delay")
		}
		time.Sleep(time.Millisecond)
		synctest.Wait()
		if len(pipe.keepalives) != 1 {
			t.Fatal("configured NAT delay did not reach the sender")
		}
	})
}

func TestRenewalPolicyExpiredIKECannotSendDelete(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, pipe := renewalCryptoSession(t)
		defer s.cancel()
		setRenewalInput(t, s.cfg, renewalInput())
		s.renewIKEHardExpiry(time.Now())
		s.startHardExpiry(&s.ikeHardExpiry, 150*time.Second, SessionDownIKELifetime)
		time.Sleep(150 * time.Second)
		synctest.Wait()
		if s.ctx.Err() == nil {
			t.Fatal("hard-expiry precondition missing")
		}
		if err := s.sendDeleteIKE(); err == nil || len(pipe.sent) != 0 {
			t.Fatal("cleanup used an expired IKE generation to send Delete")
		}
	})
}

package swu

import (
	"context"
	"errors"
	"math"
	"sync/atomic"
	"testing"
	"time"

	"github.com/1239t/swu-go/pkg/ikev2"
)

func TestRenewalPolicyCappedRetryDoesNotOverflowBeforeLimit(t *testing.T) {
	cfg := &Config{}
	setRenewalInput(t, cfg, renewalInput())
	r := &cfg.RenewalPolicy.Retransmission
	r.InitialTimeout, r.MaxTimeout, r.BackoffFactor = time.Second, 2*time.Second, math.MaxFloat64
	if err := cfg.ValidateRenewalPolicy(); err != nil {
		t.Fatal("finite multiplier with a bounded actual delay rejected", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var sent atomic.Int32
	m := NewTaskManager(ctx, r, 1, func([][]byte) error { sent.Add(1); return nil })
	msg := m.enqueueRequest(0, ikev2.IKE_SA_INIT, nil, [][]byte{{0, 1, 2}})
	m.mu.Lock()
	msg.Deadline = time.Now().Add(-time.Millisecond)
	m.mu.Unlock()
	m.checkTimeouts()
	m.mu.Lock()
	delay, due := msg.NextTimeout, msg.Deadline
	m.mu.Unlock()
	if delay != 2*time.Second || !due.After(time.Now()) || sent.Load() != 2 {
		t.Fatalf("bounded retry overflowed: delay=%v sends=%d", delay, sent.Load())
	}
}

func TestRenewalPolicyLocalCancellationStillSendsValidIKEDelete(t *testing.T) {
	s, pipe := renewalCryptoSession(t)
	setRenewalInput(t, s.cfg, renewalInput())
	s.renewIKEHardExpiry(time.Now())
	s.cancel()
	if err := s.sendDeleteIKE(); err != nil || len(pipe.sent) != 1 {
		t.Fatal("ordinary cancellation lost valid graceful Delete", err)
	}
}

func TestRenewalPolicyRejectsOverflowAndNonfiniteRetry(t *testing.T) {
	for _, change := range []func(*RenewalPolicy){
		func(p *RenewalPolicy) { p.Retransmission.BackoffFactor = math.NaN() },
		func(p *RenewalPolicy) { p.Retransmission.BackoffFactor = math.Inf(1) },
		func(p *RenewalPolicy) { p.Retransmission.MaxRetries = 33 },
		func(p *RenewalPolicy) {
			p.Retransmission.InitialTimeout, p.Retransmission.MaxTimeout = time.Duration(math.MaxInt64/2+1), 0
		},
		func(p *RenewalPolicy) { p.NATKeepaliveDPDMargin = time.Duration(math.MaxInt64) },
	} {
		cfg := &Config{}
		setRenewalInput(t, cfg, renewalInput())
		change(cfg.RenewalPolicy)
		if !errors.Is(cfg.ValidateRenewalPolicy(), ErrInvalidRenewalPolicy) {
			t.Fatal("nonfinite/overflowing policy accepted")
		}
	}
}

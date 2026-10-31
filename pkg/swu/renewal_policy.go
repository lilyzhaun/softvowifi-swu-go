package swu

import (
	"errors"
	"math"
	"math/rand"
	"time"

	"github.com/1239t/swu-go/pkg/driver"
)

var ErrInvalidRenewalPolicy = errors.New("invalid session renewal policy")

// SALifetimePolicy is one complete local lifetime decision. Rekey starts at
// SoftLifetime minus an early-only jitter; HardLifetime ends this generation
// even while a rekey exchange is pending. Values are whole seconds.
type SALifetimePolicy struct {
	SoftLifetime time.Duration
	HardLifetime time.Duration
	RekeyJitter  time.Duration
}

// RenewalPolicy is an optional complete next-Session policy, not negotiated
// peer facts. Zero disables local reauthentication, DPD or NAT keepalive only;
// it never disables a protected AUTH_LIFETIME. SA lifetimes must be positive.
type RenewalPolicy struct {
	IKE                   SALifetimePolicy
	Child                 SALifetimePolicy
	Reauthentication      time.Duration
	DPDInterval           time.Duration
	NATKeepaliveInterval  time.Duration
	NATKeepaliveDPDMargin time.Duration
	Retransmission        RetryConfig
}

type sessionRenewalPolicy struct {
	RenewalPolicy
	explicit bool
}

// ValidateRenewalPolicy shares the Session's preflight without opening sockets,
// changing Config or starting timers. Error text contains no caller values.
func (c *Config) ValidateRenewalPolicy() error {
	_, err := compileRenewalPolicy(c)
	return err
}

func compileRenewalPolicy(c *Config) (*sessionRenewalPolicy, error) {
	p := &sessionRenewalPolicy{RenewalPolicy: RenewalPolicy{
		IKE:                  SALifetimePolicy{SoftLifetime: ikeRekeyInterval * time.Second, RekeyJitter: ikeRekeyJitter * time.Second},
		Child:                SALifetimePolicy{SoftLifetime: childRekeyInterval * time.Second, RekeyJitter: childRekeyJitter * time.Second},
		NATKeepaliveInterval: 20 * time.Second, NATKeepaliveDPDMargin: 150 * time.Second,
		Retransmission: *DefaultRetryConfig(),
	}}
	if c.RenewalPolicy == nil {
		if c.ReauthInterval > 0 {
			p.Reauthentication = time.Duration(c.ReauthInterval) * time.Second
		}
		return p, nil
	}
	p.RenewalPolicy, p.explicit = *c.RenewalPolicy, true
	for _, sa := range []SALifetimePolicy{p.IKE, p.Child} {
		if sa.SoftLifetime <= 0 || sa.HardLifetime <= sa.SoftLifetime || sa.RekeyJitter < 0 ||
			sa.RekeyJitter >= sa.SoftLifetime || sa.SoftLifetime-sa.RekeyJitter < 30*time.Second ||
			sa.SoftLifetime%time.Second != 0 || sa.HardLifetime%time.Second != 0 || sa.RekeyJitter%time.Second != 0 {
			return nil, ErrInvalidRenewalPolicy
		}
	}
	if p.Reauthentication < 0 || p.DPDInterval < 0 || p.NATKeepaliveInterval < 0 || p.NATKeepaliveDPDMargin < 0 ||
		p.NATKeepaliveInterval > time.Duration(math.MaxInt64)-p.NATKeepaliveDPDMargin || !validRenewalRetry(p.Retransmission) {
		return nil, ErrInvalidRenewalPolicy
	}
	return p, nil
}

func validRenewalRetry(r RetryConfig) bool {
	// Bound validation and request amplification. This does not increase the
	// legacy five retries or alter TaskManager's existing half-second clock.
	if r.MaxRetries < 0 || r.MaxRetries > 32 || r.InitialTimeout <= 0 || r.MaxTimeout < 0 ||
		(r.MaxTimeout > 0 && r.MaxTimeout < r.InitialTimeout) || r.BackoffFactor < 1 ||
		math.IsNaN(r.BackoffFactor) || math.IsInf(r.BackoffFactor, 0) {
		return false
	}
	delay, total := r.InitialTimeout, r.InitialTimeout
	for n := 0; n < r.MaxRetries; n++ {
		next := float64(delay) * r.BackoffFactor
		if r.MaxTimeout > 0 {
			next = min(next, float64(r.MaxTimeout))
		}
		if next >= float64(math.MaxInt64) {
			return false
		}
		delay = time.Duration(next)
		if delay > time.Duration(math.MaxInt64)-total {
			return false
		}
		total += delay
	}
	return true
}

func (s *Session) prepareRenewalPolicy() error {
	s.renewalOnce.Do(func() { s.renewalPolicy, s.renewalError = compileRenewalPolicy(s.cfg) })
	return s.renewalError
}

func rekeyDelay(interval, jitter time.Duration) time.Duration {
	if jitter == 0 {
		return interval
	}
	// Keep the original whole-second, early-only distribution for nil policy.
	return interval - time.Duration(rand.Int63n(int64(jitter/time.Second)))*time.Second
}

func (s *Session) applyChildLifetimes(configs ...*driver.XFRMSAConfig) error {
	if err := s.prepareRenewalPolicy(); err != nil {
		return err
	}
	if s.renewalPolicy.explicit {
		soft, hard := s.renewalPolicy.Child.SoftLifetime/time.Second, s.renewalPolicy.Child.HardLifetime/time.Second
		for _, cfg := range configs {
			cfg.TimeLimitSoft, cfg.TimeLimitHard = uint64(soft), uint64(hard)
		}
	}
	return nil
}

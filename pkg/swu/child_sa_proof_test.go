package swu

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/1239t/swu-go/pkg/driver"
)

type proofReaderFunc func(context.Context, driver.OwnedSAToken) driver.OwnedSAProof

func (f proofReaderFunc) ReadOwnedSAProof(ctx context.Context, token driver.OwnedSAToken) driver.OwnedSAProof {
	return f(ctx, token)
}

// This fixture controls read timing only. Actual installation, limits and
// retirement are exercised separately through the isolated kernel consumer.
func proofTimingSession(t *testing.T, read proofReaderFunc) (*Session, context.CancelFunc) {
	t.Helper()
	owner, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	s := &Session{}
	s.saProof.owner = owner
	s.saProof.current = &childProofPair{reader: read}
	return s, cancel
}

func TestChildSAProofNotReadyAndContendedNeverReads(t *testing.T) {
	s, cancel := proofTimingSession(t, func(context.Context, driver.OwnedSAToken) driver.OwnedSAProof {
		t.Fatal("inactive owner caused a read")
		return driver.OwnedSAProof{}
	})
	s.saProof.mu.Lock()
	if got := s.ReadChildSAProof(context.Background()); got.State != "unavailable" {
		t.Error("contended proof accepted")
	}
	s.saProof.mu.Unlock()
	change := s.beginChildProofChange()
	if got := s.ReadChildSAProof(context.Background()); got.State != "unavailable" {
		t.Error("in-flight install was accepted")
	}
	change.ok = true
	s.finishChildProofChange(change)
	cancel()
	if got := s.ReadChildSAProof(context.Background()); got.State != "unavailable" {
		t.Error("retired owner was accepted")
	}
	if got := (&Session{}).ReadChildSAProof(context.Background()); got.State != "unavailable" {
		t.Error("no owner was accepted")
	}
}

func TestChildSAProofInFlightReplacementAndCancellationDiscardWholeSample(t *testing.T) {
	for _, action := range []string{"install", "cleanup", "owner-cancel", "caller-cancel"} {
		t.Run(action, func(t *testing.T) {
			started, release := make(chan struct{}), make(chan struct{})
			var reads atomic.Int32
			s, cancelOwner := proofTimingSession(t, func(ctx context.Context, _ driver.OwnedSAToken) driver.OwnedSAProof {
				if reads.Add(1) == 1 {
					close(started)
					select {
					case <-release:
					case <-ctx.Done():
					}
				}
				return driver.OwnedSAProof{State: "verified", Limits: &driver.SALifetimeLimits{SoftSeconds: 120, HardSeconds: 180}}
			})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := make(chan ChildSAProof, 1)
			go func() { result <- s.ReadChildSAProof(ctx) }()
			select {
			case <-started:
			case <-time.After(time.Second):
				t.Fatal("read did not start")
			}
			switch action {
			case "install":
				change := s.beginChildProofChange()
				change.ok = true
				s.finishChildProofChange(change)
			case "cleanup":
				s.clearChildSAProof()
			case "owner-cancel":
				cancelOwner()
			case "caller-cancel":
				cancel()
			}
			close(release)
			select {
			case got := <-result:
				if got.State == "verified" || got.Current != nil || got.Previous != nil {
					t.Fatal("mixed or canceled sample escaped")
				}
			case <-time.After(time.Second):
				t.Fatal("read did not honor bounded cancellation")
			}
		})
	}
}

func TestChildSAProofPreviousAbsenceAndOverlapAreIndependent(t *testing.T) {
	for _, old := range []string{"verified", "absent", "present-or-reused", "unknown"} {
		t.Run(old, func(t *testing.T) {
			reads := 0
			s, _ := proofTimingSession(t, func(ctx context.Context, _ driver.OwnedSAToken) driver.OwnedSAProof {
				reads++
				deadline, ok := ctx.Deadline()
				if !ok || time.Until(deadline) > time.Second {
					t.Fatal("unbounded session read")
				}
				return driver.OwnedSAProof{State: "verified", Limits: &driver.SALifetimeLimits{SoftSeconds: 120, HardSeconds: 180}}
			})
			got := s.ReadChildSAProof(context.Background())
			if got.State != "verified" || got.Previous == nil || got.Previous.State != "not-observed" || reads != 2 {
				t.Fatal("missing previous pair was mistaken for proven absence")
			}
			reads = 0
			s.saProof.previousPhase = "overlap"
			s.saProof.previous = &childProofPair{reader: proofReaderFunc(func(context.Context, driver.OwnedSAToken) driver.OwnedSAProof {
				reads++
				return driver.OwnedSAProof{State: old}
			})}
			got = s.ReadChildSAProof(context.Background())
			want := old
			if old == "verified" {
				want = "overlap"
			}
			if got.State != "verified" || got.Previous.State != want || got.Previous.Phase != "overlap" || reads != 4 {
				t.Fatal("current pair/previous pair evidence or read budget was conflated")
			}
		})
	}
}

package swu

import (
	"context"
	"errors"
	"syscall"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestSessionCleanupRetainsPending_whenUndoFails(t *testing.T) {
	core, logs := observer.New(zap.InfoLevel)
	completed, prerequisite := 0, 0
	sess := &Session{Logger: zap.New(core), netUndos: []func() error{
		func() error { prerequisite++; return nil },
		func() error { return syscall.EIO },
		func() error { completed++; return nil },
	}}

	err := sess.cleanupNetworkConfig()

	if !errors.Is(err, ErrCleanup) || !errors.Is(err, syscall.EIO) {
		t.Fatalf("cleanup error chain: %v", err)
	}
	if completed != 1 || prerequisite != 0 || len(sess.netUndos) != 2 {
		t.Fatalf("completed=%d prerequisite=%d pending=%d", completed, prerequisite, len(sess.netUndos))
	}
	if logs.FilterLevelExact(zap.InfoLevel).Len() != 0 {
		t.Fatal("failed cleanup published success")
	}
}

func TestSessionCleanupReturnsCause_whenConnectCannotBind(t *testing.T) {
	attempts := 0
	sess := NewSession(&Config{TransportFactory: func(_, _ string) (Transport, error) {
		return nil, syscall.EADDRINUSE
	}}, zap.NewNop())
	sess.netUndos = []func() error{func() error { attempts++; return syscall.EIO }}

	err := sess.Connect(context.Background())

	if !errors.Is(err, ErrCleanup) || !errors.Is(err, syscall.EIO) || !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("Connect lost original or cleanup error: %v", err)
	}
	if attempts != 1 || len(sess.netUndos) != 1 {
		t.Fatalf("cleanup attempts=%d pending=%d", attempts, len(sess.netUndos))
	}
	select {
	case <-sess.done:
	default:
		t.Fatal("terminal Connect did not release WaitDone")
	}
	sess.Shutdown()
}

func TestSessionCleanupBlocksReauth_whenCleanupFails(t *testing.T) {
	attempts := 0
	sess := NewSession(&Config{TransportFactory: func(_, _ string) (Transport, error) {
		attempts++
		if attempts == 1 {
			return nil, ErrReauth
		}
		return nil, syscall.EADDRINUSE
	}}, zap.NewNop())
	sess.netUndos = []func() error{func() error { return syscall.EIO }}

	err := sess.Connect(context.Background())

	if attempts != 1 || !errors.Is(err, ErrReauth) || !errors.Is(err, ErrCleanup) {
		t.Fatalf("attempts=%d error=%v", attempts, err)
	}
}

func TestSessionCleanupReplaysOnlyPending_whenExplicitlyRetried(t *testing.T) {
	completed, attempts := 0, 0
	sess := &Session{Logger: zap.NewNop(), netUndos: []func() error{
		func() error {
			attempts++
			if attempts == 1 {
				return syscall.EIO
			}
			return nil
		},
		func() error { completed++; return nil },
	}}
	sess.cleanupNetworkConfig()

	sess.cleanupNetworkConfig()

	if completed != 1 || attempts != 2 || len(sess.netUndos) != 0 {
		t.Fatalf("completed=%d attempts=%d pending=%d", completed, attempts, len(sess.netUndos))
	}
}

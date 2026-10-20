package swu

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/1239t/swu-go/pkg/ipsec"
)

func TestSocketObserverNormalSessionAndOccupiedPortRetry(t *testing.T) {
	for _, occupied := range []bool{false, true} {
		t.Run(map[bool]string{false: "direct", true: "occupied-port"}[occupied], func(t *testing.T) {
			var mu sync.Mutex
			var events []ipsec.SocketEvent
			cfg := &Config{EpDGAddr: "127.0.0.1", EpDGPort: 500, LocalAddr: "127.0.0.1", SIM: &diagnosticSIM{}}
			if occupied {
				peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
				if err != nil {
					t.Fatal(err)
				}
				defer peer.Close()
				cfg.LocalPort = uint16(peer.LocalAddr().(*net.UDPAddr).Port)
			}
			type contextKey struct{}
			ctx, cancel := context.WithTimeout(context.WithValue(t.Context(), contextKey{}, cfg), 100*time.Millisecond)
			defer cancel()
			cfg.SocketObserver = func(ctx context.Context, event ipsec.SocketEvent) {
				mu.Lock()
				defer mu.Unlock()
				if ctx.Value(contextKey{}) != cfg {
					t.Error("Session did not pass its caller context")
				}
				events = append(events, event)
			}
			s := NewSession(cfg, nil)
			defer s.Shutdown()
			if err := s.Connect(ctx); err == nil {
				t.Fatal("silent loopback endpoint unexpectedly established a session")
			}
			mu.Lock()
			defer mu.Unlock()
			dialed, inUse, sent := 0, 0, 0
			for _, event := range events {
				if event.Role != ipsec.SocketRoleOuter {
					t.Error("literal endpoint fabricated DNS progress")
				}
				if event.Phase == ipsec.SocketPhaseDial && event.Result == ipsec.SocketResultSuccess {
					dialed++
					if event.Source != netip.MustParseAddr("127.0.0.1") {
						t.Error("missing actual session source")
					}
				}
				if event.Cause == ipsec.SocketCauseAddressInUse {
					inUse++
				}
				if event.Phase == ipsec.SocketPhaseWrite && event.Result == ipsec.SocketResultSuccess {
					sent++
				}
			}
			if dialed != 1 || sent == 0 || (occupied && inUse != 1) || (!occupied && inUse != 0) {
				t.Fatalf("Session/retry lost observer: dial=%d in-use=%d sent=%d", dialed, inUse, sent)
			}
		})
	}
}

func TestSocketObserverNormalSessionPreservesControlFailure(t *testing.T) {
	marker := errors.New("test-only control failure")
	var failure ipsec.SocketEvent
	cfg := &Config{
		EpDGAddr: "127.0.0.1", LocalAddr: "127.0.0.1", SIM: &diagnosticSIM{},
		SocketControl: func(string, string, syscall.RawConn) error { return errors.Join(marker, syscall.EPERM) },
		SocketObserver: func(_ context.Context, event ipsec.SocketEvent) {
			if event.Result == ipsec.SocketResultFailure {
				failure = event
			}
		},
	}
	s := NewSession(cfg, nil)
	defer s.Shutdown()
	if err := s.Connect(t.Context()); !errors.Is(err, marker) || !errors.Is(err, syscall.EPERM) {
		t.Fatal("Session observer changed control failure propagation")
	}
	if failure.Role != ipsec.SocketRoleOuter || failure.Phase != ipsec.SocketPhaseDial || failure.Cause != ipsec.SocketCausePermission || failure.Source.IsValid() {
		t.Fatal("normal Session did not report the actual failed socket creation")
	}
}

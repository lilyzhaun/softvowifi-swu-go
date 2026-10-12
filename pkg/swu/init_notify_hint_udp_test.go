package swu

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func TestConnectTimeoutRetainsUnauthenticatedHintWithoutChangingRetransmission(t *testing.T) {
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	_ = peer.SetDeadline(time.Now().Add(3 * time.Second))
	session := newInitTestSession("")
	session.cfg.LocalAddr, session.cfg.LocalPort = "127.0.0.1", 0
	session.cfg.EpDGAddr, session.cfg.EpDGPort = "127.0.0.1", uint16(peer.LocalAddr().(*net.UDPAddr).Port)
	hintSeen := make(chan struct{}, 1)
	core, logs := observer.New(zapcore.DebugLevel)
	session.Logger = zap.New(core, zap.Hooks(func(entry zapcore.Entry) error {
		if entry.Message == "IKE_SA_INIT unauthenticated notification hint" {
			hintSeen <- struct{}{}
		}
		return nil
	}))
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- session.Connect(ctx) }()
	t.Cleanup(func() { cancel(); session.Shutdown() })
	buf := make([]byte, 4096)
	n, addr, err := peer.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	offered := bytes.Clone(buf[:n])
	if _, err := peer.WriteToUDP(initHintWire(binary.BigEndian.Uint64(offered[:8]), 17, []byte{0, 19}), addr); err != nil {
		t.Fatal(err)
	}
	select {
	case <-hintSeen:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	// Advance only the test's deadline, under the real window lock. Production
	// retry counts, packet bytes and backoff remain the original values.
	manager := session.taskMgr
	manager.mu.Lock()
	pending := manager.pending[0]
	if pending == nil {
		manager.mu.Unlock()
		t.Fatal("advisory consumed pending")
	}
	before := *pending
	pending.Deadline = time.Now().Add(-time.Second)
	manager.mu.Unlock()
	manager.checkTimeouts()
	manager.mu.Lock()
	if pending.RetryCount != before.RetryCount+1 || pending.MaxRetries != before.MaxRetries || pending.NextTimeout != time.Duration(float64(before.NextTimeout)*manager.config.BackoffFactor) {
		t.Error("advisory changed normal retry policy")
	}
	manager.mu.Unlock()
	n, _, err = peer.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:n], offered) {
		t.Fatal("actual UDP retransmission changed original offer/KE")
	}
	manager.mu.Lock()
	pending.RetryCount = pending.MaxRetries
	pending.Deadline = time.Now().Add(-time.Second)
	manager.mu.Unlock()
	manager.checkTimeouts()
	select {
	case err := <-done:
		if !errors.Is(err, ErrWindowTimeout) || !strings.Contains(err.Error(), "unauthenticated IKE_SA_INIT notify type=17 dataLen=2 suggestedDHGroup=19") {
			t.Fatalf("public Connect timeout lost its diagnostic: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("Connect did not return its exhausted-window diagnostic")
	}
	if session.Keys != nil || session.SPIr != 0 || session.ChildSAIn != nil || session.ChildSAOut != nil {
		t.Fatal("hint-only exchange installed security state")
	}
	if logs.FilterMessage("IKE_SA_INIT unauthenticated notification hint").Len() != 1 {
		t.Fatal("notification logging exceeded its per-type bound")
	}
}

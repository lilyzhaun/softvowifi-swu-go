package swu

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/1239t/swu-go/pkg/ikev2"
	"go.uber.org/zap"
)

// JSON permits the behavioral regression to compile against the pre-policy
// Config. An ignored policy must fail through the real consumer, not compilation.
func setIdentityPolicyForTest(t *testing.T, cfg *Config, local, requested uint8, peer []byte) {
	t.Helper()
	policy := map[string]any{"LocalIDType": local, "RequestedIDrType": requested}
	if peer != nil {
		policy["Peer"] = map[string]any{"Type": ikev2.ID_FQDN, "Data": peer}
	}
	raw, err := json.Marshal(map[string]any{"IdentityPolicy": policy})
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, cfg); err != nil {
		t.Fatal(err)
	}
}

func TestIdentityPolicyConnectUsesRequestedTypesAndOriginalAUTH(t *testing.T) {
	testAKAIdentityAUTH(t, "identity-key-id")
}

func TestIdentityPolicyConnectAcceptsIndependentPeerConstraint(t *testing.T) {
	testAKAIdentityAUTH(t, "identity-pinned")
}

func TestIdentityPolicyConnectRejectsUnmatchedPeerBeforeEAP(t *testing.T) {
	peer := newAKAWirePeer(t)
	previous, provider := identitySession(t)
	cfg := previous.cfg
	cfg.LocalAddr, cfg.EpDGAddr, cfg.APN = "127.0.0.1", "127.0.0.1", "ims"
	cfg.EpDGPort = uint16(peer.conn.LocalAddr().(*net.UDPAddr).Port)
	setIdentityPolicyForTest(t, cfg, ikev2.ID_RFC822_ADDR, ikev2.ID_FQDN, []byte("expected.example.test"))
	session := NewSession(cfg, zap.NewNop())
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	done := make(chan struct{})
	var connectErr error
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
			session.Shutdown()
		case <-time.After(3 * time.Second):
			t.Error("Connect did not release")
		}
	})
	go func() { connectErr = session.Connect(ctx); close(done) }()
	peer.negotiate(t)
	peer.decrypt(t, peer.receive(t))
	peer.send(t, peer.protect(t, []akaWirePayload{
		{kind: 36, body: append([]byte{2, 0, 0, 0}, []byte("unmatched.example.test")...)},
		{kind: 48, body: []byte{1, 0x29, 0, 5, 1}},
	}))
	<-done
	if !errors.Is(connectErr, ErrIKEAuthFailed) || provider.calls != 0 || session.ChildSAIn != nil || session.ChildSAOut != nil {
		t.Fatalf("peer policy did not stop the real EAP consumer: %v", connectErr)
	}
}

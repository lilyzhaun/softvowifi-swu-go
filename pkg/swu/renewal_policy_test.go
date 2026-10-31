package swu

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/1239t/swu-go/pkg/ipsec"
	"go.uber.org/zap"
)

// JSON keeps the initial regression executable against the pre-policy API.
// This is an SDK input fixture, not a persisted application configuration.
func renewalInput() map[string]any {
	return map[string]any{
		"IKE":              map[string]any{"SoftLifetime": 90 * time.Second, "HardLifetime": 150 * time.Second, "RekeyJitter": 0},
		"Child":            map[string]any{"SoftLifetime": 120 * time.Second, "HardLifetime": 180 * time.Second, "RekeyJitter": 0},
		"Reauthentication": 0, "DPDInterval": time.Second,
		"NATKeepaliveInterval": time.Second, "NATKeepaliveDPDMargin": 150 * time.Second,
		"Retransmission": map[string]any{"MaxRetries": 1, "InitialTimeout": 250 * time.Millisecond, "MaxTimeout": time.Second, "BackoffFactor": 1.0},
	}
}

func setRenewalInput(t *testing.T, cfg *Config, value map[string]any) {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"RenewalPolicy": value})
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, cfg); err != nil {
		t.Fatal(err)
	}
}

func TestRenewalPolicyRejectsInvalidBeforeTransport(t *testing.T) {
	for _, name := range []string{"inverted_ike", "inverted_child", "jitter_at_soft", "cooldown_overlap", "fractional_kernel_lifetime", "negative_dpd", "negative_nat", "negative_reauth", "invalid_retries", "zero_retry_delay", "retry_cap_below_initial", "shrinking_backoff"} {
		t.Run(name, func(t *testing.T) {
			value := renewalInput()
			ike, child, retry := value["IKE"].(map[string]any), value["Child"].(map[string]any), value["Retransmission"].(map[string]any)
			switch name {
			case "inverted_ike":
				ike["HardLifetime"] = 89 * time.Second
			case "inverted_child":
				child["HardLifetime"] = 120 * time.Second
			case "jitter_at_soft":
				ike["RekeyJitter"] = 90 * time.Second
			case "cooldown_overlap":
				child["SoftLifetime"] = 20 * time.Second
			case "fractional_kernel_lifetime":
				child["HardLifetime"] = 180*time.Second + time.Nanosecond
			case "negative_dpd":
				value["DPDInterval"] = -1
			case "negative_nat":
				value["NATKeepaliveInterval"] = -1
			case "negative_reauth":
				value["Reauthentication"] = -1
			case "invalid_retries":
				retry["MaxRetries"] = -1
			case "zero_retry_delay":
				retry["InitialTimeout"] = 0
			case "retry_cap_below_initial":
				retry["MaxTimeout"] = time.Millisecond
			case "shrinking_backoff":
				retry["BackoffFactor"] = 0.5
			}
			var opened atomic.Int32
			sentinel := errors.New("transport reached")
			cfg := &Config{TransportFactory: func(string, string) (Transport, error) { opened.Add(1); return nil, sentinel }}
			setRenewalInput(t, cfg, value)
			err := NewSession(cfg, zap.NewNop()).Connect(t.Context())
			if err == nil || errors.Is(err, sentinel) || opened.Load() != 0 {
				t.Fatalf("invalid policy reached transport: opened=%d err=%v", opened.Load(), err)
			}
		})
	}
}

func TestRenewalPolicyChangesRealConnectRetransmission(t *testing.T) {
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	cfg := &Config{LocalAddr: "127.0.0.1", EpDGAddr: "127.0.0.1", EpDGPort: uint16(peer.LocalAddr().(*net.UDPAddr).Port)}
	setRenewalInput(t, cfg, renewalInput())
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	captured := make(chan struct{})
	cfg.TransportFactory = func(local, remote string) (Transport, error) {
		// Connect invokes this only after copying the policy. UDP receipt is
		// external IO, not a Go happens-before edge for editing caller memory.
		close(captured)
		return ipsec.NewSocketManagerWithObserver(ctx, local, remote, "", nil, nil, nil)
	}
	done := make(chan error, 1)
	go func() { done <- NewSession(cfg, zap.NewNop()).Connect(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
	read := func() []byte {
		t.Helper()
		if err := peer.SetReadDeadline(time.Now().Add(1500 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 4096)
		n, _, err := peer.ReadFromUDP(buf)
		if err != nil {
			t.Fatalf("configured retry never reached UDP: %v", err)
		}
		return bytes.Clone(buf[:n])
	}
	first := read()
	select {
	case <-captured:
	case <-ctx.Done():
		t.Fatal("Connect bypassed the capture-before-transport boundary")
	}
	cfg.RenewalPolicy.Retransmission.MaxRetries = 20
	cfg.RenewalPolicy.Retransmission.InitialTimeout = time.Minute
	repeated := read()
	if !bytes.Equal(first, repeated) {
		t.Fatal("retry rebuilt the original request")
	}
	// Requeue the observed outcome for the single cleanup owner.
	select {
	case err := <-done:
		done <- err
		if !errors.Is(err, ErrWindowTimeout) {
			t.Fatalf("retry exhaustion did not terminate Connect: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("configured retry budget was ignored")
	}
}

func TestRenewalPolicyReachesProtectedChildRekeyInstallation(t *testing.T) {
	s, _ := childRekeySession(t)
	setRenewalInput(t, s.cfg, renewalInput())
	kernel := newRekeyKernel()
	if err := exerciseChildRekey(t, s, func() error { return s.rekeyChildSA(kernel) }); err != nil {
		t.Fatal(err)
	}
	if len(kernel.adds) != 2 {
		t.Fatal("protected rekey did not install both directions")
	}
	for _, sa := range kernel.adds {
		if sa.TimeLimitSoft != 120 || sa.TimeLimitHard != 180 {
			t.Fatalf("installed lifetime = %d/%d, want 120/180", sa.TimeLimitSoft, sa.TimeLimitHard)
		}
	}
}

type renewalKeepaliveTransport struct {
	pipeTransport
	keepalives chan struct{}
}

func (p *renewalKeepaliveTransport) SendNATKeepalive() error {
	p.keepalives <- struct{}{}
	return nil
}

func renewalCryptoSession(t *testing.T) (*Session, *pipeTransport) {
	t.Helper()
	s := newLebaraRekeyCryptoSession(t)
	settings, pair := rekeyXFRMFixture()
	s.ChildSAIn, s.ChildSAOut = pair.in, pair.out
	s.childEncrID, s.childIntegID, s.childEncrKeyLenBits = pair.encrID, pair.integID, pair.keyBits
	s.cpConfig, s.tsi, s.tsr = settings.cpConfig, settings.tsi, settings.tsr
	s.ctx, s.cancelCause = context.WithCancelCause(t.Context())
	s.cancel = func() { s.cancelCause(context.Canceled) }
	pipe := &pipeTransport{sent: make(chan []byte, 16)}
	s.socket = pipe
	// Keep the exchange pending beyond either hard deadline. The retry
	// consumer itself is separately exercised through real Connect and UDP.
	s.taskMgr = NewTaskManager(s.ctx, &RetryConfig{InitialTimeout: time.Hour, BackoffFactor: 1}, 1, func(packets [][]byte) error {
		for _, packet := range packets {
			if err := pipe.SendIKE(packet); err != nil {
				return err
			}
		}
		return nil
	})
	return s, pipe
}

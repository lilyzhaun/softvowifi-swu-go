package driver

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/iniwex5/netlink"
)

func proofFixture(t *testing.T) (*testKernel, *XFRMManager, XFRMSAConfig, OwnedSAToken) {
	t.Helper()
	kernel := newTestKernel()
	x := kernel.manager(t)
	cfg := ownershipSA(0x601)
	cfg.TimeLimitSoft, cfg.TimeLimitHard = 120, 180
	mustXFRM(t, x.AddSA(cfg))
	x.ops.stateRead = func(ctx context.Context, query *netlink.XfrmState) (*netlink.XfrmState, error) {
		return x.ops.stateGet(query)
	}
	return kernel, x, cfg, x.CaptureOwnedSA(cfg.SPI, cfg.Dst, cfg.Proto)
}

func TestOwnedSAProofReadsConfirmedKernelLimitsWithoutMutation(t *testing.T) {
	kernel, x, cfg, token := proofFixture(t)
	reads := 0
	get := x.ops.stateRead
	var returned *netlink.XfrmState
	x.ops.stateRead = func(ctx context.Context, query *netlink.XfrmState) (*netlink.XfrmState, error) {
		reads++
		if query.Spi != int(cfg.SPI) || !query.Dst.Equal(cfg.Dst) || query.Proto != cfg.Proto {
			t.Fatal("read escaped the installed tuple")
		}
		var err error
		returned, err = get(ctx, query)
		return returned, err
	}
	proof := x.ReadOwnedSAProof(context.Background(), token)
	if proof.State != "verified" || proof.Limits == nil || proof.Limits.SoftSeconds != 120 || proof.Limits.HardSeconds != 180 {
		t.Fatal("readback did not verify the installed kernel limits")
	}
	if reads != 1 || kernel.updates != 0 || kernel.deletes != 0 || len(kernel.states) != 1 {
		t.Fatal("proof changed state or read beyond the one owned tuple")
	}
	for _, algo := range []*netlink.XfrmStateAlgo{returned.Auth, returned.Crypt, returned.Aead} {
		if algo != nil && len(algo.Key) != 0 {
			t.Fatal("temporary readback retained key material")
		}
	}
	data, err := json.Marshal(proof)
	if err != nil || string(data) != `{"state":"verified","limits":{"softSeconds":120,"hardSeconds":180}}` {
		t.Fatal("proof wire contains more than fixed status and limits")
	}
	for _, value := range []string{fmt.Sprintf("%v", token), fmt.Sprintf("%+v", token), fmt.Sprintf("%#v", token)} {
		if value != "owned-sa-token" {
			t.Fatal("opaque token formatting disclosed private state")
		}
	}
	encoded, err := json.Marshal(token)
	if err != nil || string(encoded) != "null" {
		t.Fatal("opaque token JSON disclosed private state")
	}
}

func TestOwnedSAProofMissingRequiresActualKernelAbsence(t *testing.T) {
	for _, code := range []syscall.Errno{syscall.ENOENT, syscall.ESRCH, syscall.EPERM, syscall.EIO, syscall.ETIMEDOUT} {
		t.Run(code.Error(), func(t *testing.T) {
			kernel, x, cfg, token := proofFixture(t)
			// A successful DELETE ACK is deliberately insufficient: the fake
			// kernel still contains the exact SA until the explicit GET below.
			x.ops.stateDel = func(*netlink.XfrmState) error { return nil }
			mustXFRM(t, x.DelSA(cfg.SPI, cfg.Src, cfg.Dst, cfg.Proto))
			if got := x.ReadOwnedSAProof(context.Background(), token); got.State != "present-or-reused" || got.Limits != nil {
				t.Fatal("DELETE ACK was mistaken for absence")
			}
			kernel.getErr = code
			want := "unknown"
			if code == syscall.ENOENT || code == syscall.ESRCH {
				want = "absent"
			}
			if got := x.ReadOwnedSAProof(context.Background(), token); got.State != want || got.Limits != nil {
				t.Fatal("read error was misclassified as kernel absence")
			}
		})
	}
}

func TestOwnedSAProofRejectsKernelReplacementAndForeignTokens(t *testing.T) {
	for _, field := range []string{"limits", "ifid", "key", "same-tuple-new-generation"} {
		t.Run(field, func(t *testing.T) {
			kernel, x, cfg, token := proofFixture(t)
			key := testSAKey(x.buildXfrmState(cfg))
			want := "mismatch"
			switch field {
			case "limits":
				kernel.states[key].Limits.TimeHard++
			case "ifid":
				kernel.states[key].Ifid++
			case "key":
				kernel.states[key].Crypt.Key[0]++
			case "same-tuple-new-generation":
				mustXFRM(t, x.DelSA(cfg.SPI, cfg.Src, cfg.Dst, cfg.Proto))
				mustXFRM(t, x.AddSA(cfg))
				want = "present-or-reused"
			}
			if got := x.ReadOwnedSAProof(context.Background(), token); got.State != want || got.Limits != nil {
				t.Fatal("kernel replacement was reported as the captured installation")
			}
			foreign := kernel.manager(t)
			foreign.ops.stateRead = func(context.Context, *netlink.XfrmState) (*netlink.XfrmState, error) {
				t.Fatal("foreign token caused a kernel read")
				return nil, nil
			}
			if foreign.ReadOwnedSAProof(context.Background(), token).State != "unavailable" {
				t.Fatal("foreign manager accepted an owned token")
			}
		})
	}
}

func TestOwnedSAProofCancellationContentionAndInFlightUpdate(t *testing.T) {
	_, x, cfg, token := proofFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	get := x.ops.stateRead
	x.ops.stateRead = func(context.Context, *netlink.XfrmState) (*netlink.XfrmState, error) {
		t.Fatal("canceled or contended request reached the kernel")
		return nil, nil
	}
	if x.ReadOwnedSAProof(ctx, token).State != "unknown" {
		t.Fatal("canceled proof was accepted")
	}
	x.mu.Lock()
	result := make(chan OwnedSAProof, 1)
	go func() { result <- x.ReadOwnedSAProof(context.Background(), token) }()
	select {
	case got := <-result:
		if got.State != "unavailable" {
			t.Error("contended owner was accepted")
		}
	case <-time.After(time.Second):
		t.Error("proof waited for lifecycle mutex")
	}
	x.mu.Unlock()
	// Even an update restoring identical bytes must invalidate an in-flight
	// proof; comparing only record generation or snapshot misses this case.
	x.ops.stateRead = func(ctx context.Context, query *netlink.XfrmState) (*netlink.XfrmState, error) {
		actual, err := get(ctx, query)
		mustXFRM(t, x.UpdateSA(cfg))
		return actual, err
	}
	if got := x.ReadOwnedSAProof(context.Background(), token); got.State != "stale" || got.Limits != nil {
		t.Fatal("concurrent same-byte update published a proof")
	}
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	x.ops.stateRead = func(ctx context.Context, query *netlink.XfrmState) (*netlink.XfrmState, error) {
		actual, err := get(ctx, query)
		cancel()
		return actual, err
	}
	if x.ReadOwnedSAProof(ctx, token).State != "unknown" {
		t.Fatal("late canceled read published success")
	}
	x.ops.stateRead = func(context.Context, *netlink.XfrmState) (*netlink.XfrmState, error) {
		return nil, fmt.Errorf("private endpoint and key: %s", strings.Repeat("a", 32))
	}
	if got := x.ReadOwnedSAProof(context.Background(), token); got.State != "unknown" || got.Limits != nil {
		t.Fatal("raw read error escaped fixed projection")
	}
}

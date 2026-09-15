package swu

import (
	"context"
	"errors"
	"testing"
	"time"

	"go.uber.org/zap"
)

func Test_ParseSessionDownReason_mapsUnknownToUnknown(t *testing.T) {
	cases := []struct {
		in   string
		want SessionDownReason
	}{
		{"ike_rekey_failed", SessionDownIKERekeyFailed},
		{"ike_rekey_peer_reject", SessionDownIKERekeyPeerReject},
		{"ike_rekey_timeout", SessionDownIKERekeyTimeout},
		{"ike_rekey_invalid_response", SessionDownIKERekeyInvalidResponse},
		{"child_rekey_failed", SessionDownChildRekeyFailed},
		{"dpd_exhausted", SessionDownDPDExhausted},
		{"dpd_failed", SessionDownDPDFailed},
		{"peer_ike_delete", SessionDownPeerIKEDelete},
		{"kernel_hard_expire", SessionDownKernelHardExpire},
		{"redirect", SessionDownRedirect},
		{"local_cancel", SessionDownLocalCancel},
		{"internal_transport", SessionDownInternalTransport},
		{"unknown", SessionDownUnknown},
		{"", SessionDownUnknown},
		{"spi=0xabc 10.1.2.3", SessionDownUnknown},
	}
	for _, tc := range cases {
		if got := ParseSessionDownReason(tc.in); got != tc.want {
			t.Fatalf("ParseSessionDownReason(%q)=%q want %q", tc.in, got, tc.want)
		}
	}
}

func Test_HardExpire_cancelPolicy_matchesBaselineObservers(t *testing.T) {
	t.Run("no_observer", func(t *testing.T) {
		sess := newClosedTestSession(t)
		sess.onHardExpire()
		if !errors.Is(sess.ctx.Err(), context.Canceled) {
			t.Fatalf("ctx.Err()=%v", sess.ctx.Err())
		}
	})
	t.Run("legacy_OnSessionDown", func(t *testing.T) {
		sess := newClosedTestSession(t)
		sess.OnSessionDown = func() {}
		sess.onHardExpire()
		if sess.ctx.Err() != nil {
			t.Fatalf("legacy skip-cancel broken, ctx.Err()=%v", sess.ctx.Err())
		}
	})
	t.Run("OnClosedReason_only", func(t *testing.T) {
		sess := newClosedTestSession(t)
		sess.OnClosedReason = func(SessionDownReason) {}
		sess.onHardExpire()
		if !errors.Is(sess.ctx.Err(), context.Canceled) {
			t.Fatalf("new observer must not skip-cancel, ctx.Err()=%v", sess.ctx.Err())
		}
	})
	t.Run("both", func(t *testing.T) {
		sess := newClosedTestSession(t)
		sess.OnSessionDown = func() {}
		sess.OnClosedReason = func(SessionDownReason) {}
		sess.onHardExpire()
		if sess.ctx.Err() != nil {
			t.Fatalf("production both-callbacks must keep skip-cancel, ctx.Err()=%v", sess.ctx.Err())
		}
	})
}

func Test_ClosedReason_doesNotDelayCancel_whenCallbackBlocks(t *testing.T) {
	sess := newClosedTestSession(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	finished := make(chan struct{})
	sess.OnClosedReason = func(SessionDownReason) {
		close(entered)
		<-release
	}
	go func() {
		if sess.cancel != nil {
			sess.cancel()
		}
		sess.observeClosed(SessionDownIKERekeyFailed)
		close(finished)
	}()
	<-entered
	if sess.ctx.Err() == nil {
		t.Fatal("blocked OnClosedReason postponed original cancel")
	}
	close(release)
	<-finished
}

func Test_StartDPD_reportsDPDFailed_whenSchedulerMissing(t *testing.T) {
	sess := newClosedTestSession(t)
	got := make(chan SessionDownReason, 1)
	sess.OnClosedReason = func(reason SessionDownReason) { got <- reason }
	sess.StartDPD(time.Millisecond)
	select {
	case reason := <-got:
		if reason == SessionDownDPDExhausted {
			t.Fatalf("claimed exhaustion without window proof: %s", reason)
		}
		if reason != SessionDownDPDFailed {
			t.Fatalf("reason=%s want %s", reason, SessionDownDPDFailed)
		}
	case <-time.After(time.Second):
		t.Fatal("StartDPD did not observe closed reason")
	}
	if sess.ctx.Err() == nil {
		t.Fatal("baseline DPD path must cancel")
	}
}

func Test_Shutdown_emitsLocalCancelAfterOriginalCancel(t *testing.T) {
	sess := newClosedTestSession(t)
	var reason SessionDownReason
	sess.OnClosedReason = func(r SessionDownReason) { reason = r }
	sess.Shutdown()
	if !errors.Is(sess.ctx.Err(), context.Canceled) {
		t.Fatalf("ctx.Err()=%v", sess.ctx.Err())
	}
	if reason != SessionDownLocalCancel {
		t.Fatalf("reason=%s", reason)
	}
}

func Test_dpdClosedReason_usesCapturedCtxNotGuessedExhaustion(t *testing.T) {
	if dpdClosedReason(context.Background()) != SessionDownDPDFailed {
		t.Fatal("live ctx must not claim dpd_exhausted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if dpdClosedReason(ctx) != SessionDownLocalCancel {
		t.Fatal("canceled captured ctx -> local_cancel")
	}
}

func newClosedTestSession(t *testing.T) *Session {
	t.Helper()
	sess := NewSession(&Config{
		EpDGAddr:  "192.0.2.2",
		EpDGPort:  500,
		LocalAddr: "192.0.2.1",
		LocalPort: 4500,
	}, zap.NewNop())
	ctx, cancel := context.WithCancel(context.Background())
	sess.ctx, sess.cancel = ctx, cancel
	t.Cleanup(cancel)
	return sess
}

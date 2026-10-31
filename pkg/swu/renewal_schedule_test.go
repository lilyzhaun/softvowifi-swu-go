//go:build go1.25

package swu

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/1239t/swu-go/pkg/ikev2"
)

func TestRenewalPolicyRekeyScheduleAndIndependentHardExpiry(t *testing.T) {
	for _, child := range []bool{false, true} {
		name := "ike"
		if child {
			name = "child"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s, pipe := renewalCryptoSession(t)
				defer s.cancel()
				setRenewalInput(t, s.cfg, renewalInput())
				var closed atomic.Int32
				s.OnClosedReason = func(SessionDownReason) { closed.Add(1) }
				soft, hard, protocol, reason := 90*time.Second, 150*time.Second, byte(1), SessionDownIKELifetime
				if child {
					soft, hard, protocol, reason = 120*time.Second, 180*time.Second, 3, SessionDownChildLifetime
					s.startChildSARekeyTimer(1800 * time.Second)
				} else {
					s.startIKESARekeyTimer(1500 * time.Second)
				}
				synctest.Wait()
				// Later Config edits cannot extend the captured policy.
				s.cfg.RenewalPolicy.IKE.HardLifetime = time.Hour
				s.cfg.RenewalPolicy.Child.HardLifetime = time.Hour
				time.Sleep(soft - time.Millisecond)
				if len(pipe.sent) != 0 {
					t.Fatal("rekey fired before its configured soft lifetime")
				}
				time.Sleep(time.Millisecond)
				synctest.Wait()
				select {
				case raw := <-pipe.sent:
					header, err := ikev2.DecodeHeader(raw)
					if err != nil || header.ExchangeType != ikev2.CREATE_CHILD_SA {
						t.Fatal("timer did not produce a CREATE_CHILD_SA exchange")
					}
					opened := peerChildOpen(t, raw, s.Keys.SK_ei, s.Keys.SK_ai)
					if sa := opened[33]; len(sa) < 8 || sa[5] != protocol {
						t.Fatal("timer renewed the wrong SA kind")
					}
				default:
					t.Fatal("configured soft lifetime did not send a protected rekey")
				}
				time.Sleep(hard - soft - time.Millisecond)
				if s.ctx.Err() != nil {
					t.Fatal("session retired before its independent hard deadline")
				}
				time.Sleep(time.Millisecond)
				synctest.Wait()
				var terminal *SessionClosedError
				if !errors.As(context.Cause(s.ctx), &terminal) || terminal.Reason != reason || closed.Load() != 1 {
					t.Fatalf("blocked exchange suppressed hard expiry: %v, callbacks=%d", context.Cause(s.ctx), closed.Load())
				}
			})
		})
	}
}

func TestRenewalPolicyDPDIsCapturedAndStartsOnlyOnce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, pipe := renewalCryptoSession(t)
		defer s.cancel()
		setRenewalInput(t, s.cfg, renewalInput())
		s.StartDPD(20 * time.Second)
		s.StartDPD(20 * time.Second) // OnReady plus the Session's own startup.
		s.cfg.RenewalPolicy.DPDInterval = time.Hour
		synctest.Wait()
		for n := 0; n < 2; n++ {
			time.Sleep(time.Second)
			synctest.Wait()
			select {
			case raw := <-pipe.sent:
				header, err := ikev2.DecodeHeader(raw)
				if err != nil || header.ExchangeType != ikev2.INFORMATIONAL || len(peerChildOpen(t, raw, s.Keys.SK_ei, s.Keys.SK_ai)) != 0 {
					t.Fatal("DPD did not send an authenticated empty INFORMATIONAL")
				}
				response := encodePeerPacket(t, s, nil, ikev2.INFORMATIONAL, header.MessageID, true)
				if !s.taskMgr.HandleResponse(header.MessageID, response) {
					t.Fatal("DPD response did not complete the pending transaction")
				}
			default:
				t.Fatal("configured DPD interval was ignored")
			}
			synctest.Wait()
			if len(pipe.sent) != 0 {
				t.Fatal("duplicate DPD worker")
			}
		}
		s.cancel()
		synctest.Wait()
		time.Sleep(2 * time.Second)
		if len(pipe.sent) != 0 {
			t.Fatal("DPD outlived its Session")
		}
	})
}

func TestRenewalPolicyNATMarginAndExplicitDisabledLiveness(t *testing.T) {
	for _, disabled := range []bool{false, true} {
		synctest.Test(t, func(t *testing.T) {
			s, sent := renewalCryptoSession(t)
			defer s.cancel()
			value := renewalInput()
			value["NATKeepaliveDPDMargin"] = 2 * time.Second
			if disabled {
				value["NATKeepaliveInterval"], value["DPDInterval"] = 0, 0
			}
			setRenewalInput(t, s.cfg, value)
			pipe := &renewalKeepaliveTransport{pipeTransport: *sent, keepalives: make(chan struct{}, 4)}
			s.socket = pipe
			s.recordOutboundActivity(time.Now().Add(-4 * time.Second))
			s.startNATKeepalive(20 * time.Second)
			if disabled {
				s.StartDPD(20 * time.Second)
				time.Sleep(40 * time.Second)
			}
			synctest.Wait()
			if len(pipe.keepalives) != 0 || (!disabled && len(pipe.sent) != 1) || (disabled && len(pipe.sent) != 0) {
				t.Fatal("NAT margin/disabled policy did not reach liveness consumers")
			}
		})
	}
}

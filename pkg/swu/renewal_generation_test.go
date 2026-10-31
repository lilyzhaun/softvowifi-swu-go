//go:build go1.25

package swu

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"github.com/1239t/swu-go/pkg/ikev2"
)

func TestRenewalPolicyPeerIKERekeyKeepsOtherOwnersAndOldDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, pipe := renewalCryptoSession(t)
		defer s.cancel()
		setRenewalInput(t, s.cfg, renewalInput())
		start := time.Now()
		s.renewIKEHardExpiry(start)
		s.renewChildHardExpiry(start)
		s.startHardExpiry(&s.ikeHardExpiry, 150*time.Second, SessionDownIKELifetime)
		s.startHardExpiry(&s.childHardExpiry, 180*time.Second, SessionDownChildLifetime)
		s.setAuthLifetime(3600, start, nil)
		s.authExpiry.mu.Lock()
		auth := s.authExpiry.server
		s.authExpiry.mu.Unlock()
		time.Sleep(100 * time.Second)
		if err := s.HandleRekeyIKESARequest(0, peerRekeyOffer(t, s)); err != nil {
			t.Fatal(err)
		}
		<-pipe.sent
		if !s.ikeHardExpiry.deadline().Equal(start.Add(250*time.Second)) || !s.childHardExpiry.deadline().Equal(start.Add(180*time.Second)) {
			t.Fatal("IKE rekey failed to reset only its own lifetime")
		}
		if s.retiredIKE == nil || !s.retiredIKE.expires.Equal(start.Add(150*time.Second)) {
			t.Fatal("old IKE overlap extended the retired generation's hard deadline")
		}
		s.authExpiry.mu.Lock()
		unchanged := s.authExpiry.server.Equal(auth)
		s.authExpiry.mu.Unlock()
		if !unchanged {
			t.Fatal("IKE rekey changed authentication ownership")
		}
		time.Sleep(50 * time.Second)
		synctest.Wait()
		if s.ctx.Err() != nil {
			t.Fatal("stale IKE timer retired the replacement generation")
		}
		old := s.retiredIKE.codec
		raw := encodePeerPacket(t, old, []ikev2.Payload{&ikev2.EncryptedPayloadDelete{ProtocolID: ikev2.ProtoIKE}}, ikev2.INFORMATIONAL, 8, false)
		header, err := ikev2.DecodeHeader(raw)
		if err != nil || !s.dispatchRetiredIKE(header, raw) || len(pipe.sent) != 0 {
			t.Fatal("retired IKE key answered after its original hard lifetime")
		}
		time.Sleep(30 * time.Second)
		synctest.Wait()
		var terminal *SessionClosedError
		if !errors.As(context.Cause(s.ctx), &terminal) || terminal.Reason != SessionDownChildLifetime {
			t.Fatal("IKE rekey postponed the independent Child expiry")
		}
	})
}

func TestRenewalPolicyPeerChildCommitReplayFailureAndRetirement(t *testing.T) {
	for _, failed := range []bool{false, true} {
		synctest.Test(t, func(t *testing.T) {
			s, pipe, offer := peerChildFixture(t, peerChildSuites[2])
			defer s.cancel()
			setRenewalInput(t, s.cfg, renewalInput())
			start := time.Now()
			s.renewIKEHardExpiry(start)
			s.renewChildHardExpiry(start)
			s.startHardExpiry(&s.childHardExpiry, 180*time.Second, SessionDownChildLifetime)
			oldIn, oldOut := s.ChildSAIn.SPI, s.ChildSAOut.SPI
			kernel := newRekeyKernel()
			kernel.live = map[uint32]bool{oldIn: true, oldOut: true}
			time.Sleep(100 * time.Second)
			if failed {
				pipe.sendErr = errSendIKE
			}
			err := s.handlePeerChildRekey(0, offer, kernel)
			if failed {
				if err == nil || !s.childHardExpiry.deadline().Equal(start.Add(180*time.Second)) || s.retiredChild != nil {
					t.Fatal("failed Child response renewed or committed an SA")
				}
				time.Sleep(80 * time.Second)
				synctest.Wait()
				if s.ctx.Err() == nil {
					t.Fatal("failed rekey postponed old Child expiry")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			<-pipe.sent
			for _, sa := range kernel.adds {
				if sa.TimeLimitSoft != 120 || sa.TimeLimitHard != 180 {
					t.Fatal("peer Child rekey omitted the configured kernel lifetimes")
				}
			}
			if !s.childHardExpiry.deadline().Equal(start.Add(280*time.Second)) || !s.ikeHardExpiry.deadline().Equal(start.Add(150*time.Second)) {
				t.Fatal("peer Child rekey renewed the wrong owner")
			}
			time.Sleep(5 * time.Second)
			if err := s.handlePeerChildRekey(0, offer, kernel); err != nil {
				t.Fatal(err)
			}
			<-pipe.sent
			if len(kernel.adds) != 2 || !s.childHardExpiry.deadline().Equal(start.Add(280*time.Second)) {
				t.Fatal("replayed Child rekey extended the committed generation")
			}
			time.Sleep(75 * time.Second)
			synctest.Wait()
			if s.ctx.Err() != nil || s.incomingChild(oldIn) != nil || !s.retiredChild.expires.Equal(start.Add(180*time.Second)) {
				t.Fatal("old Child hard expiry killed the new pair or accepted an expired key")
			}
			s.expireRetiredChild(time.Now())
			if kernel.live[oldIn] || kernel.live[oldOut] || len(kernel.live) != 2 {
				t.Fatal("expired old Child pair did not retire through its owner")
			}
		})
	}
}

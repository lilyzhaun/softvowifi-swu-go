package swu

import (
	"context"
	"encoding/binary"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/1239t/swu-go/pkg/ikev2"
	"github.com/1239t/swu-go/pkg/ipsec"
)

type childRekeySnapshot struct {
	out, in  *ipsec.SecurityAssociation
	inbound  map[uint32]*ipsec.SecurityAssociation
	policies []childOutPolicy
	last     time.Time
}

func snapshotChildRekey(sess *Session) childRekeySnapshot {
	inbound := make(map[uint32]*ipsec.SecurityAssociation, len(sess.ChildSAsIn))
	for spi, sa := range sess.ChildSAsIn {
		inbound[spi] = sa
	}
	return childRekeySnapshot{sess.ChildSAOut, sess.ChildSAIn, inbound, append([]childOutPolicy(nil), sess.childOutPolicies...), sess.lastRekeyTime}
}

func (snap childRekeySnapshot) assertUncommitted(t *testing.T, sess *Session) {
	t.Helper()
	if sess.ChildSAOut != snap.out || sess.ChildSAIn != snap.in {
		t.Error("Child SA references committed before kernel success")
	}
	if !reflect.DeepEqual(sess.ChildSAsIn, snap.inbound) || !reflect.DeepEqual(sess.childOutPolicies, snap.policies) {
		t.Error("Child SA map/policies changed on failed commit")
	}
	if !sess.lastRekeyTime.Equal(snap.last) || len(sess.rekeyResetCh) != 0 || len(sess.childRekeyResetCh) != 0 {
		t.Error("failure advanced cooldown/reset")
	}
}

func childRekeySession(t *testing.T) (*Session, *pipeTransport) {
	t.Helper()
	sess := newLebaraRekeyCryptoSession(t)
	settings, next := rekeyXFRMFixture()
	sess.cfg.ReplayWindow = settings.cfg.ReplayWindow
	sess.xfrmLocalIP, sess.xfrmRemoteIP = settings.xfrmLocalIP, settings.xfrmRemoteIP
	sess.xfrmLocalPort, sess.xfrmRemotePort, sess.xfrmIfID = settings.xfrmLocalPort, settings.xfrmRemotePort, settings.xfrmIfID
	sess.childIntegID, sess.childESN = settings.childIntegID, settings.childESN
	sess.ChildSAOut, sess.ChildSAIn = next.out, next.in
	sess.ChildSAOut.SPI, sess.ChildSAIn.SPI = 101, 102
	sess.ChildSAsIn = map[uint32]*ipsec.SecurityAssociation{102: sess.ChildSAIn}
	sess.tsr = []*ikev2.TrafficSelector{ikev2.NewTrafficSelectorIPV4([]byte{0, 0, 0, 0}, []byte{255, 255, 255, 255}, 0, 65535)}
	sess.childOutPolicies = []childOutPolicy{{saOut: sess.ChildSAOut, tsr: sess.tsr}}
	sess.lastRekeyTime = time.Unix(1, 0)
	sess.rekeyResetCh, sess.childRekeyResetCh = make(chan struct{}, 2), make(chan struct{}, 2)
	sess.SequenceNumber.Store(1)
	pipe := &pipeTransport{sent: make(chan []byte, 4)}
	sess.socket = pipe
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	sess.ctx, sess.cancel = ctx, cancel
	t.Cleanup(cancel)
	sess.taskMgr = NewTaskManager(ctx, nil, 1, func(packets [][]byte) error {
		for _, packet := range packets {
			if err := pipe.SendIKE(packet); err != nil {
				return err
			}
		}
		return nil
	})
	t.Cleanup(sess.taskMgr.Stop)
	return sess, pipe
}

func exerciseChildRekey(t *testing.T, sess *Session, invoke func() error) error {
	t.Helper()
	spi := make([]byte, 4)
	binary.BigEndian.PutUint32(spi, 201)
	proposal := ikev2.NewProposal(1, ikev2.ProtoESP, spi)
	proposal.AddTransformWithKeyLen(ikev2.TransformTypeEncr, ikev2.ENCR_AES_CBC, 128)
	proposal.AddTransform(ikev2.TransformTypeInteg, ikev2.AUTH_HMAC_SHA2_256_128, 0)
	response := encodeRekeyResponse(t, sess,
		&ikev2.EncryptedPayloadSA{Proposals: []*ikev2.Proposal{proposal}},
		&ikev2.EncryptedPayloadNonce{NonceData: make([]byte, 32)},
	)
	result := make(chan error, 1)
	go func() { result <- invoke() }()
	pipe := sess.socket.(*pipeTransport)
	select {
	case request := <-pipe.sent:
		header, err := ikev2.DecodeHeader(request)
		if err != nil {
			t.Fatal(err)
		}
		if header.ExchangeType != ikev2.CREATE_CHILD_SA || header.NextPayload != ikev2.SK {
			t.Fatal("expected encrypted CREATE_CHILD_SA request")
		}
		_, payloads, err := sess.decryptAndParse(request)
		if err != nil {
			t.Fatalf("REKEY request decode: %v", err)
		}
		found := false
		for _, payload := range payloads {
			notify, ok := payload.(*ikev2.EncryptedPayloadNotify)
			if !ok || notify.NotifyType != ikev2.REKEY_SA {
				continue
			}
			// RFC 7296 section 1.3.3: the initiator's inbound ESP SPI.
			if found || notify.ProtocolID != ikev2.ProtoESP || len(notify.SPI) != 4 || len(notify.NotifyData) != 0 || binary.BigEndian.Uint32(notify.SPI) != sess.ChildSAIn.SPI {
				t.Fatal("REKEY_SA did not identify the initiator's inbound SA")
			}
			found = true
		}
		if !found {
			t.Fatal("missing REKEY_SA notification")
		}
		if !sess.taskMgr.HandleResponse(header.MessageID, response) {
			t.Fatal("response was not matched to real request")
		}
	case <-sess.ctx.Done():
		t.Fatal("request timed out")
	}
	select {
	case err := <-result:
		return err
	case <-sess.ctx.Done():
		t.Fatal("rekey did not return")
		return sess.ctx.Err()
	}
}

func TestChildRekeyCallerPropagatesKernelFailure(t *testing.T) {
	for _, stage := range []string{"add1", "add2", "sp1", "sp2", "sp3", "sp4", "del101", "del102", "rollback"} {
		t.Run(stage, func(t *testing.T) {
			sess, pipe := childRekeySession(t)
			snap := snapshotChildRekey(sess)
			kernel := newRekeyKernel()
			kernel.fail = stage
			if stage == "rollback" {
				kernel.fail, kernel.rollbackFail = "add2", true
			}
			kernel.before = func() { snap.assertUncommitted(t, sess) }

			err := exerciseChildRekey(t, sess, func() error { return sess.rekeyChildSA(kernel) })

			if !errors.Is(err, errRekeyKernel) {
				t.Errorf("RekeyChildSA body swallowed kernel failure: %v", err)
			}
			if stage == "rollback" && !errors.Is(err, errRekeyRollback) {
				t.Error("rollback failure lost at caller")
			}
			snap.assertUncommitted(t, sess)
			if len(pipe.sent) != 0 {
				t.Error("sent old Child SA DELETE after kernel failure")
			}
		})
	}
}

func TestChildRekeyCallerCommitsOnceOnSuccess(t *testing.T) {
	for _, mode := range []string{"xfrm", "no_xfrm"} {
		t.Run(mode, func(t *testing.T) {
			sess, pipe := childRekeySession(t)
			snap := snapshotChildRekey(sess)
			kernel := newRekeyKernel()
			kernel.before = func() { snap.assertUncommitted(t, sess) }
			invoke := func() error { return sess.rekeyChildSA(kernel) }
			if mode == "no_xfrm" {
				invoke = sess.RekeyChildSA
			}

			err := exerciseChildRekey(t, sess, invoke)

			if err != nil {
				t.Fatal(err)
			}
			if sess.ChildSAOut == snap.out || sess.ChildSAIn == snap.in || sess.ChildSAOut.SPI != 201 {
				t.Fatal("new Child SAs not committed")
			}
			if sess.ChildSAsIn[102] != snap.in || sess.ChildSAsIn[sess.ChildSAIn.SPI] != sess.ChildSAIn || len(sess.ChildSAsIn) != 2 || sess.childOutPolicies[0].saOut != sess.ChildSAOut {
				t.Error("incorrect inbound map/outbound policy commit")
			}
			if !sess.lastRekeyTime.After(snap.last) || len(sess.rekeyResetCh) != 1 || len(sess.childRekeyResetCh) != 0 {
				t.Error("success bookkeeping changed")
			}
			select {
			case packet := <-pipe.sent:
				_, payloads, err := sess.decryptAndParse(packet)
				if err != nil || len(payloads) != 1 {
					t.Fatalf("DELETE decode: %v", err)
				}
				deleted, ok := payloads[0].(*ikev2.EncryptedPayloadDelete)
				// RFC 7296 section 1.4.1: retire our old inbound SPI, not the peer's.
				if !ok || deleted.ProtocolID != ikev2.ProtoESP || deleted.NumSPIs != 1 || len(deleted.SPIs) != 4 || binary.BigEndian.Uint32(deleted.SPIs) != 102 {
					t.Fatal("wrong old SA DELETE")
				}
			default:
				t.Fatal("missing old SA DELETE")
			}
			committedAt, operations := sess.lastRekeyTime, len(kernel.calls)
			if err := invoke(); err != nil {
				t.Fatal(err)
			}
			if len(pipe.sent) != 0 || len(kernel.calls) != operations || !sess.lastRekeyTime.Equal(committedAt) || len(sess.rekeyResetCh) != 1 {
				t.Error("cooldown repeated successful commit")
			}
		})
	}
}

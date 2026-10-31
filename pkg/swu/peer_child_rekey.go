package swu

import (
	"encoding/binary"
	"errors"
	"time"

	"github.com/1239t/swu-go/pkg/crypto"
	"github.com/1239t/swu-go/pkg/ikev2"
	"github.com/1239t/swu-go/pkg/ipsec"
	"github.com/1239t/swu-go/pkg/logger"
	"github.com/iniwex5/netlink"
)

type peerChildRetirement struct {
	in, out *ipsec.SecurityAssociation
	ops     childRekeyXFRMOps
	expires time.Time
	hardDue time.Time
	deleted bool
	keys    *ikev2.IKESAKeys
	mid     uint32
	hash    [32]byte
	reply   []byte
}

// The dispatcher holds rekeyMu. All validation and key construction precede
// kernel preparation; publication occurs only after the response send succeeds.
func (s *Session) handlePeerChildRekey(mid uint32, payloads []ikev2.Payload, ops childRekeyXFRMOps) error {
	if err := s.prepareRenewalPolicy(); err != nil {
		return err
	}
	if s.ctx != nil && s.ctx.Err() != nil {
		return s.ctx.Err()
	}
	hash := ikePayloadHash(payloads)
	if old := s.retiredChild; old != nil {
		if old.keys == s.Keys && old.mid == mid && old.hash == hash {
			return s.socket.SendIKE(old.reply)
		}
		return s.peerChildReject(mid, ikev2.TEMPORARY_FAILURE)
	}
	sel, notify := s.selectPeerChild(payloads)
	if notify != 0 {
		if notify == ikev2.CHILD_SA_NOT_FOUND {
			for _, pl := range payloads {
				if n, ok := pl.(*ikev2.EncryptedPayloadNotify); ok && n.NotifyType == ikev2.REKEY_SA {
					return s.sendEncryptedResponseWithMsgID([]ikev2.Payload{&ikev2.EncryptedPayloadNotify{NotifyType: notify, ProtocolID: ikev2.ProtoESP, SPI: append([]byte(nil), n.SPI...)}}, ikev2.CREATE_CHILD_SA, mid)
				}
			}
		}
		return s.peerChildReject(mid, notify)
	}
	nr, err := crypto.RandomBytes(32)
	if err != nil {
		return err
	}
	spi, err := crypto.RandomBytes(4)
	if err != nil {
		return err
	}
	localSPI, peerSPI := binary.BigEndian.Uint32(spi), binary.BigEndian.Uint32(sel.proposal.SPI)
	if localSPI == 0 || s.ChildSAsIn[localSPI] != nil {
		return s.peerChildReject(mid, ikev2.TEMPORARY_FAILURE)
	}
	next, err := s.deriveChildRekey(s.childEncrID, s.childIntegID, s.childEncrKeyLenBits, sel.nonce, nr, localSPI, peerSPI, false)
	if err != nil {
		return err
	}
	responseProposal := ikev2.NewProposal(sel.proposal.ProposalNum, ikev2.ProtoESP, spi)
	responseProposal.Transforms = sel.proposal.Transforms
	response, err := s.encryptAndWrapWithMsgID([]ikev2.Payload{
		&ikev2.EncryptedPayloadSA{Proposals: []*ikev2.Proposal{responseProposal}}, &ikev2.EncryptedPayloadNonce{NonceData: nr},
		&ikev2.EncryptedPayloadTS{IsInitiator: true, TrafficSelectors: sel.tsi}, &ikev2.EncryptedPayloadTS{TrafficSelectors: sel.tsr},
	}, ikev2.CREATE_CHILD_SA, mid, true)
	if err != nil {
		return err
	}
	undo, err := s.stagePeerChild(ops, next)
	if err != nil {
		_ = s.peerChildReject(mid, ikev2.TEMPORARY_FAILURE)
		return err
	}
	if s.ctx != nil && s.ctx.Err() != nil {
		return errors.Join(s.ctx.Err(), undo())
	}
	if err := s.socket.SendIKE(response); err != nil {
		rollback := undo()
		return errors.Join(err, rollback)
	}
	s.cacheFragmentReply(ikev2.CREATE_CHILD_SA, mid, response)
	s.childMu.Lock()
	hardDue := s.childHardExpiry.deadline()
	s.retiredChild = &peerChildRetirement{in: s.ChildSAIn, out: s.ChildSAOut, ops: ops, expires: retirementDeadline(time.Now(), hardDue), hardDue: hardDue, keys: s.Keys, mid: mid, hash: hash, reply: response}
	s.ChildSAIn, s.ChildSAOut = next.in, next.out
	if s.ChildSAsIn == nil {
		s.ChildSAsIn = make(map[uint32]*ipsec.SecurityAssociation)
	}
	s.ChildSAsIn[localSPI] = next.in
	s.tsi, s.tsr = sel.tsr, sel.tsi
	s.childOutPolicies = []childOutPolicy{{saOut: next.out, tsr: s.tsr}}
	s.lastChildRekeyTime = time.Now()
	s.childMu.Unlock()
	s.renewChildHardExpiry(s.lastChildRekeyTime)
	s.Logger.Info("对端 CHILD_SA Rekey 成功", logger.Uint32("oldOutSPI", s.retiredChild.out.SPI), logger.Uint32("newOutSPI", next.out.SPI), logger.Uint32("newInSPI", next.in.SPI))
	select {
	case s.childRekeyResetCh <- struct{}{}:
	default:
	}
	return nil
}

func (s *Session) peerChildReject(mid uint32, notify uint16) error {
	return s.sendEncryptedResponseWithMsgID([]ikev2.Payload{&ikev2.EncryptedPayloadNotify{NotifyType: notify}}, ikev2.CREATE_CHILD_SA, mid)
}

// Caller owns rekeyMu. Keep the small reply record after deletion to absorb
// a lost rekey response; there is only one previous generation at a time.
func (s *Session) deleteRetiredChild() error {
	old := s.retiredChild
	if old == nil || old.deleted {
		return nil
	}
	if old.ops != nil {
		if err := old.ops.DelSA(old.out.SPI, s.xfrmLocalIP, s.xfrmRemoteIP, netlink.XFRM_PROTO_ESP); err != nil {
			return err
		}
		if err := old.ops.DelSA(old.in.SPI, s.xfrmRemoteIP, s.xfrmLocalIP, netlink.XFRM_PROTO_ESP); err != nil {
			return err
		}
	}
	s.childMu.Lock()
	delete(s.ChildSAsIn, old.in.SPI)
	s.childMu.Unlock()
	old.deleted = true
	return nil
}

func (s *Session) expireRetiredChild(now time.Time) {
	if !s.rekeyMu.TryLock() {
		return
	}
	failed := false
	defer func() {
		s.rekeyMu.Unlock()
		if failed {
			s.endSession(SessionDownChildRekeyFailed, "")
		}
	}()
	if s.retiredChild != nil && !now.Before(s.retiredChild.expires) {
		if err := s.deleteRetiredChild(); err != nil {
			failed = true
			return
		}
		s.retiredChild = nil
	}
}

package swu

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/1239t/swu-go/pkg/crypto"
	"github.com/1239t/swu-go/pkg/ikev2"
	"github.com/1239t/swu-go/pkg/logger"
)

func (s *Session) RekeyChildSA() error {
	var ops childRekeyXFRMOps
	if s.xfrmMgr != nil {
		ops = s.xfrmMgr
	}
	return s.rekeyChildSA(ops)
}

func (s *Session) rekeyChildSA(ops childRekeyXFRMOps) error {
	s.rekeyMu.Lock()
	defer s.rekeyMu.Unlock()
	if s.ChildSAOut == nil || s.ChildSAIn == nil {
		return errors.New("no active Child pair to rekey")
	}
	if (!s.lastChildRekeyTime.IsZero() && time.Since(s.lastChildRekeyTime) < 30*time.Second) || (s.retiredChild != nil && !s.retiredChild.deleted) {
		return nil // Do not replace a pair still in its peer-initiated overlap.
	}
	ni, err := crypto.RandomBytes(32)
	if err != nil {
		return err
	}
	spi, err := crypto.RandomBytes(4)
	if err != nil {
		return err
	}
	localSPI := binary.BigEndian.Uint32(spi)
	if localSPI == 0 || s.ChildSAsIn[localSPI] != nil {
		return errors.New("new Child SPI collision")
	}
	proposals, err := s.localChildProposals(spi)
	if err != nil {
		return err
	}
	if len(s.tsi) == 0 || len(s.tsr) == 0 {
		return errors.New("missing negotiated Child selectors")
	}
	sa := &ikev2.EncryptedPayloadSA{Proposals: proposals}
	tsi, tsr := &ikev2.EncryptedPayloadTS{IsInitiator: true, TrafficSelectors: s.tsi}, &ikev2.EncryptedPayloadTS{TrafficSelectors: s.tsr}
	// Owned byte snapshot binds the response to the actual complete offer.
	packet := ikev2.NewIKEPacket()
	packet.Payloads = []ikev2.Payload{sa, tsi, tsr}
	offer, err := packet.Encode()
	if err != nil {
		return err
	}
	response, err := s.sendEncryptedWithRetry([]ikev2.Payload{sa, &ikev2.EncryptedPayloadNonce{NonceData: ni},
		&ikev2.EncryptedPayloadNotify{ProtocolID: ikev2.ProtoESP, SPI: binary.BigEndian.AppendUint32(nil, s.ChildSAIn.SPI), NotifyType: ikev2.REKEY_SA}, tsi, tsr}, ikev2.CREATE_CHILD_SA)
	if err != nil {
		return fmt.Errorf("Child rekey exchange: %w", err)
	}
	sel, err := s.selectLocalChildRekey(response.payloads, offer)
	if err != nil {
		return err
	}
	next, err := s.deriveChildRekey(sel.encr, sel.integ, sel.bits, ni, sel.nonce, localSPI, sel.spi, true)
	if err != nil {
		return err
	}
	next.esn = sel.esn
	if s.ctx != nil && s.ctx.Err() != nil {
		return s.ctx.Err()
	}
	return s.commitChildSARekey(next, ops)
}

func (s *Session) commitChildSARekey(next childSARekey, ops childRekeyXFRMOps) error {
	oldOut, oldIn := s.ChildSAOut.SPI, s.ChildSAIn.SPI
	if err := s.rekeyXFRM(ops, next, [2]uint32{oldOut, oldIn}); err != nil {
		return fmt.Errorf("commit local Child rekey: %w", err)
	}
	s.childMu.Lock()
	s.ChildSAOut, s.ChildSAIn = next.out, next.in
	if s.ChildSAsIn != nil {
		delete(s.ChildSAsIn, oldIn)
		s.ChildSAsIn[next.in.SPI] = next.in
	}
	s.childEncrID, s.childIntegID, s.childEncrKeyLenBits, s.childESN = next.encrID, next.integID, next.keyBits, next.esn
	if len(s.childOutPolicies) > 0 {
		s.childOutPolicies[0].saOut = next.out
	} else if len(s.tsr) > 0 {
		s.childOutPolicies = append(s.childOutPolicies, childOutPolicy{saOut: next.out, tsr: s.tsr})
	}
	s.lastChildRekeyTime = time.Now()
	s.childMu.Unlock()
	if s.ws != nil {
		s.ws.LogChildSA(next.in.SPI, next.out.SPI, s.cfg.LocalAddr, s.cfg.EpDGAddr, next.in.EncryptionKey, next.out.EncryptionKey, next.encrID)
	}
	s.Logger.Info("CHILD_SA Rekey 成功", logger.Uint32("oldSPI", oldOut), logger.Uint32("newSPI", next.in.SPI))
	select {
	case s.childRekeyResetCh <- struct{}{}:
	default:
	}
	if err := s.sendDeleteChildSA([]uint32{oldIn}); err != nil {
		s.Logger.Warn("发送旧 Child SA Delete 通知失败", logger.Err(err))
	}
	return nil
}

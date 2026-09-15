package swu

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/1239t/swu-go/pkg/crypto"
	"github.com/1239t/swu-go/pkg/ikev2"
	"github.com/1239t/swu-go/pkg/logger"
)

func (s *Session) performSessionResumption() error {
	s.resumeAuthPending = true
	s.Logger.Info("利用 Ticket 发起 IKE_SESSION_RESUME 闪电恢复", logger.Int("ticketLen", len(s.resumeTicket)))
	return fmt.Errorf("SESSION_RESUME AUTH signed material not implemented: %w", ErrResumeAuthUnsupported)
}

func (s *Session) handleIkeSessionResumeResp(data []byte) error {
	packet, err := ikev2.DecodePacket(data)
	if err != nil {
		return fmt.Errorf("解码 SESSION_RESUME 响应失败: %v", err)
	}

	if packet.Header.ExchangeType != ikev2.IKE_SESSION_RESUME {
		return fmt.Errorf("意外的交换类型 (期望 IKE_SESSION_RESUME): %d", packet.Header.ExchangeType)
	}
	s.SPIr = packet.Header.SPIr

	var noncePayload *ikev2.EncryptedPayloadNonce
	for _, p := range packet.Payloads {
		switch v := p.(type) {
		case *ikev2.EncryptedPayloadNonce:
			noncePayload = v
		case *ikev2.EncryptedPayloadNotify:
			if v.NotifyType == 14 { // NO_PROPOSAL_CHOSEN
				return errors.New("服务器拒绝了 Resume 请求 (NO_PROPOSAL_CHOSEN)")
			}
			if v.NotifyType == ikev2.TICKET_NACK {
				return errors.New("服务器拒绝了我们的 Ticket (TICKET_NACK)")
			}
		}
	}

	if noncePayload == nil {
		return errors.New("SESSION_RESUME 响应中缺少 Nonce(Nr)")
	}
	s.nr = noncePayload.NonceData

	// 根据 RFC 5723:
	// SKEYSEED = prf(SK_d_old, Ni | Nr)
	if s.PRFAlg == nil || len(s.resumeOldSKd) == 0 {
		return errors.New("缺少前任 PRF 和 SK_d 凭据，无法推演 SKEYSEED")
	}

	seedArgs := make([]byte, 0, len(s.ni)+len(s.nr))
	seedArgs = append(seedArgs, s.ni...)
	seedArgs = append(seedArgs, s.nr...)

	skeyseed, err := s.PRFAlg.Compute(s.resumeOldSKd, seedArgs)
	if err != nil {
		return fmt.Errorf("derive resume SKEYSEED: %w", err)
	}

	// 重建 IKE_SA Keys
	// 利用新的 SKEYSEED 走标准的 prf+
	s.Logger.Debug("利用复活 SKEYSEED 开始洗牌生成新密钥材料")

	// 从原有的算法继承，因为加密方式不改变
	// SKEYSEED 长度由 PRFAlg 决定

	// 这里我们需要复用 s.GenerateIKESAKeys(s.nr) 但略有不同，
	// s.GenerateIKESAKeys 需要 s.DH 计算出 SKEYSEED，但这次我们直接有了 skeyseed。
	// 为了不破坏原有的 GenerateIKESAKeys，我们直接写死推演流程。

	encKeyLen := s.EncAlg.KeySize()
	integKeyLen := s.IntegAlg.KeySize()
	prfKeyLen := s.PRFAlg.KeyLen()

	saltLen := 0
	if s.ikeIsAEAD {
		integKeyLen = 0
		saltLen = 4
	}

	keyMatLen := 3*prfKeyLen + 2*encKeyLen + 2*integKeyLen + 2*saltLen

	keySeedArgs := make([]byte, 0, 8+8+len(s.ni)+len(s.nr))
	spiBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(spiBuf, s.SPIi)
	keySeedArgs = append(keySeedArgs, s.nr...)
	keySeedArgs = append(keySeedArgs, s.ni...)
	keySeedArgs = append(keySeedArgs, spiBuf...)
	binary.BigEndian.PutUint64(spiBuf, s.SPIr)
	keySeedArgs = append(keySeedArgs, spiBuf...)

	keyMat, err := crypto.PrfPlus(s.PRFAlg, skeyseed, keySeedArgs, keyMatLen)
	if err != nil {
		return fmt.Errorf("复活推流密钥失败: %v", err)
	}

	cursor := 0
	sk_d := keyMat[cursor : cursor+prfKeyLen]
	cursor += prfKeyLen
	sk_ai := []byte(nil)
	if !s.ikeIsAEAD {
		sk_ai = keyMat[cursor : cursor+integKeyLen]
		cursor += integKeyLen
	}
	sk_ar := []byte(nil)
	if !s.ikeIsAEAD {
		sk_ar = keyMat[cursor : cursor+integKeyLen]
		cursor += integKeyLen
	}
	sk_ei := keyMat[cursor : cursor+encKeyLen+saltLen]
	cursor += encKeyLen + saltLen
	sk_er := keyMat[cursor : cursor+encKeyLen+saltLen]
	cursor += encKeyLen + saltLen
	sk_pi := keyMat[cursor : cursor+prfKeyLen]
	cursor += prfKeyLen
	sk_pr := keyMat[cursor : cursor+prfKeyLen]

	s.Keys = &ikev2.IKESAKeys{
		SK_d:  sk_d,
		SK_ai: sk_ai,
		SK_ar: sk_ar,
		SK_ei: sk_ei,
		SK_er: sk_er,
		SK_pi: sk_pi,
		SK_pr: sk_pr,
	}

	return nil
}

// sendIkeAuthChildless 是在 SESSION_RESUME 之后发起加密保护的 AUTH/CP 请求
// 在 Resumption 流中，这通常是 Message 3 和 Message 4
func (s *Session) sendIkeAuthChildless() error {
	s.resumeAuthPending = true
	// 复用原本 IKE_AUTH 中的大半逻辑，但是绕过 EAP
	// 我们需要给它下发 Child SA 的 Proposal (SPI) 还有 CP

	payloads, err := s.buildIKEAuthInitPayloads() // 这里面本就有 CP, SA, TSi, TSr
	if err != nil {
		return err
	}

	// 包裹进加密层中并推队列
	respData, err := s.sendEncryptedWithRetry(payloads, ikev2.IKE_AUTH)
	if err != nil {
		return err
	}

	// 如果服务端认出 Resume，它可能直接略过 EAP 丢回加密的 AUTH Final 响应！
	// 我们尝试解析最终 AUTH。
	msgID, parsedPayloads, err := s.decryptAndParse(respData)
	if err != nil {
		return fmt.Errorf("Resume Auth 解析错误: %v", err)
	}
	_ = msgID

	// 检查是否有 EAP 载荷？ 极少数 ePDG 可能会回退到索要求 Auth。但照理说不该有 EAP。
	var eapPayload *ikev2.EncryptedPayloadEAP
	for _, p := range parsedPayloads {
		if e, ok := p.(*ikev2.EncryptedPayloadEAP); ok {
			eapPayload = e
		}
	}
	if eapPayload != nil {
		s.Logger.Warn("SESSION_RESUME 遭遇了非预期的服务端 EAP 降级索求！将放弃无感恢复。")
		return errors.New("unexpected EAP payload in resumed auth")
	}

	// 如果没有 EAP，这正是最终的配置和 Child SA！直接移交给 handleIKEAuthFinalResp
	return s.handleIKEAuthFinalResp(respData)
}

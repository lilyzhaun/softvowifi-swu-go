package swu

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/1239t/swu-go/pkg/crypto"
	"github.com/1239t/swu-go/pkg/eap"
	"github.com/1239t/swu-go/pkg/ikev2"
	"github.com/1239t/swu-go/pkg/ipsec"
	"github.com/1239t/swu-go/pkg/logger"
	"github.com/1239t/swu-go/pkg/sim"
)

func (s *Session) buildIKEAuthInitPayloads() ([]ikev2.Payload, error) {
	if err := s.prepareIdentityPolicy(); err != nil {
		return nil, err
	}
	if err := s.prepareProposalPolicy(); err != nil {
		return nil, err
	}
	// 载荷: IDi, SA, TS, TS, N(EAP_ONLY)

	// 1. IDi
	var nai string
	if !s.akaHasTemporaryIdentity && !s.fastReauthCtx.CanUseReauth() && s.cfg.FastReauthID != "" && !s.akaPermanentIdentity && !s.akaFastConsumed {
		nai = s.cfg.FastReauthID
		if err := s.consumeFastIdentity(); err != nil {
			return nil, err
		}
	} else {
		identity, err := s.selectAKAIdentity(0)
		if err != nil {
			return nil, err
		}
		nai = string(identity)
	}
	if s.identityPolicy.explicit && (!validIdentityData(s.identityPolicy.localType, []byte(nai)) ||
		!validIdentityData(s.identityPolicy.requestedType, []byte(s.cfg.APN))) {
		return nil, ErrInvalidIdentityPolicy
	}
	s.akaIdentity.outer = []byte(nai)
	idPayload := &ikev2.EncryptedPayloadID{
		IDType:      s.identityPolicy.localType,
		IDData:      []byte(nai),
		IsInitiator: true,
	}
	idrPayload := &ikev2.EncryptedPayloadID{
		IDType:      s.identityPolicy.requestedType,
		IDData:      []byte(s.cfg.APN),
		IsInitiator: false,
	}

	// 1b. CP (CFG_REQUEST)
	// 双栈请求（IPv4 + IPv6）：部分 ePDG 对仅 v6 请求不响应，双栈最兼容
	cpPayload := &ikev2.EncryptedPayloadCP{
		CFGType: ikev2.CFG_REQUEST,
		Attributes: []*ikev2.CPAttribute{
			{Type: ikev2.INTERNAL_IP4_ADDRESS},
			{Type: ikev2.INTERNAL_IP4_DNS},
			{Type: ikev2.P_CSCF_IP4_ADDRESS},
			{Type: ikev2.INTERNAL_IP6_ADDRESS},
			{Type: ikev2.INTERNAL_IP6_DNS},
			{Type: ikev2.P_CSCF_IP6_ADDRESS},
			{Type: ikev2.ASSIGNED_PCSCF_IP6_ADDRESS},
		},
	}

	// 2. SA (Child SA)
	var spiBytes []byte
	if s.childSPI == 0 {
		var err error
		spiBytes, err = crypto.RandomBytes(4)
		if err != nil {
			return nil, err
		}
		s.childSPI = binary.BigEndian.Uint32(spiBytes)
	} else {
		spiBytes = make([]byte, 4)
		binary.BigEndian.PutUint32(spiBytes, s.childSPI)
	}

	proposals := policyProposalsWithSPI(s.proposalPolicy.initialChild, spiBytes)
	saPayload := &ikev2.EncryptedPayloadSA{
		Proposals: proposals,
	}

	// 3. TSi / TSr (0.0.0.0/0, ::/0) - 双栈（与 CP 一致）
	ts4 := ikev2.NewTrafficSelectorIPV4(
		[]byte{0, 0, 0, 0}, []byte{255, 255, 255, 255},
		0, 65535,
	)
	ipv6Max := make(net.IP, net.IPv6len)
	for i := range ipv6Max {
		ipv6Max[i] = 0xff
	}
	ts6 := ikev2.NewTrafficSelectorIPV6(net.IPv6zero, ipv6Max, 0, 65535)
	tsPayloadI := &ikev2.EncryptedPayloadTS{IsInitiator: true, TrafficSelectors: []*ikev2.TrafficSelector{ts4, ts6}}
	tsPayloadR := &ikev2.EncryptedPayloadTS{IsInitiator: false, TrafficSelectors: []*ikev2.TrafficSelector{ts4, ts6}}

	// RFC 5998 section 3: Protocol ID and SPI size are zero, with no additional data.
	notifyPayload := &ikev2.EncryptedPayloadNotify{
		ProtocolID: 0,
		NotifyType: ikev2.EAP_ONLY_AUTHENTICATION,
	}

	// RFC 7296 §2.4: INITIAL_CONTACT — 告知 ePDG 清除此身份关联的所有旧 IKE SA
	// 防止断网未发 DELETE 导致的僵尸半开隧道占用路由资源
	initialContactPayload := &ikev2.EncryptedPayloadNotify{
		ProtocolID: 0,
		NotifyType: ikev2.INITIAL_CONTACT,
	}
	s.Logger.Debug("IKE_AUTH 已注入 INITIAL_CONTACT，要求 ePDG 清理旧隧道残留")

	// 载荷顺序对齐 vowifi_gateway create_IKE_AUTH:
	// IDi → IDr → CP → SA → TSi → TSr → N(EAP_ONLY) → N(INITIAL_CONTACT)
	// 注意: 不附加 MOBIKE/TICKET_REQUEST/DEVICE_IDENTITY，避免部分 ePDG 拒绝
	payloads := []ikev2.Payload{idPayload, idrPayload, cpPayload, saPayload, tsPayloadI, tsPayloadR, notifyPayload, initialContactPayload}
	idiBody, err := idPayload.Encode()
	if err != nil {
		return nil, fmt.Errorf("encode local IDi: %w", err)
	}
	if len(s.localIDiBody) > 0 && !hmac.Equal(s.localIDiBody, idiBody) {
		return nil, errors.New("local IDi changed within IKE authentication attempt")
	}
	if len(s.localIDiBody) == 0 {
		s.localIDiBody = idiBody
	}
	if err := s.snapshotInitialChildRequest(cpPayload, saPayload, tsPayloadI, tsPayloadR); err != nil {
		return nil, err
	}
	return payloads, nil
}

// handleEAP 处理从 ePDG 接收到的 EAP (Extensible Authentication Protocol) 报文。
// 该方法负责解析 EAP 载荷，并根据 EAP 类型（如 Identity, AKA Challenge 等）生成相应的响应载荷。
func (s *Session) handleEAP(eapRaw []byte) (payloads []ikev2.Payload, result error) {
	defer func() {
		if result != nil {
			s.akaPending = nil
		}
	}()
	s.logEAPStage(eapReceived, eapRaw)
	if s.akaIdentity.failed {
		return nil, errors.New("EAP-AKA identity exchange failed")
	}
	pkt, err := eap.Parse(eapRaw)
	if err != nil {
		return nil, err
	}
	if pkt.Code == eap.CodeRequest && (pkt.Type == eap.TypeAKA || pkt.Type == eap.TypeAKAPrime) && pkt.Subtype == eap.SubtypeNotificationAlt {
		return s.handleEAPNotification(pkt, eapRaw)
	}
	if failure := s.eapNotification.failure; failure != nil {
		return nil, failure
	}
	if s.eapNotification.request != nil && pkt.Code == eap.CodeRequest {
		return nil, errEAPNotification
	}

	if pkt.Code == eap.CodeSuccess {
		if s.akaReauth.fallback && !s.eapNotification.authenticated {
			return nil, errAKAReauthentication
		}
		if s.eapNotification.request != nil && pkt.Identifier != s.eapNotification.request[1] {
			return nil, errEAPNotification
		}
		if s.eapNotification.resultInd && !s.eapNotification.success {
			return nil, errEAPNotification
		}
		// EAP 成功！
		s.Logger.Debug("收到 EAP Success")
		// 在 IKE_AUTH 中，EAP Success 通常伴随着服务器的 AUTH 载荷。
		// 这在 session.go 的循环中处理。
		// 我们这里只返回 nil 以表示不需要 EAP 响应。
		return nil, nil // Stop EAP loop
	}

	if pkt.Code != eap.CodeRequest {
		return nil, fmt.Errorf("unexpected EAP Code: %d", pkt.Code)
	}
	if (s.akaPrime.started && pkt.Type != eap.TypeAKAPrime) || (pkt.Type == eap.TypeAKAPrime && s.eapNotification.authenticated && s.eapNotification.method != eap.TypeAKAPrime) {
		return nil, errAKAPrimeChallenge
	}
	if pkt.Type == eap.TypeAKA && pkt.Subtype == eap.SubtypeIdentity {
		return s.handleAKAIdentity(pkt, eapRaw)
	}
	if pkt.Type == eap.TypeAKAPrime && len(s.akaIdentity.exchanges) > 0 {
		return nil, errors.New("EAP-AKA' cannot continue an EAP-AKA identity exchange")
	}

	// 处理身份请求
	if pkt.Type == eap.TypeIdentity {
		if len(s.akaIdentity.exchanges) > 0 || s.akaIdentity.closed {
			return nil, errors.New("unexpected outer identity after AKA method started")
		}
		identity := s.akaIdentity.outer
		if len(identity) == 0 || (!s.akaHasTemporaryIdentity && !s.fastReauthCtx.CanUseReauth() && s.akaPseudonym == "") {
			identity, err = s.selectAKAIdentity(0)
			if err != nil {
				return nil, err
			}
		}

		respPkt := &eap.EAPPacket{
			Code:       eap.CodeResponse,
			Identifier: pkt.Identifier,
			Type:       eap.TypeIdentity,
			Data:       identity,
		}

		eapPayload := &ikev2.EncryptedPayloadEAP{EAPMessage: respPkt.Encode()}
		s.akaIdentity.outer = bytes.Clone(identity)
		return []ikev2.Payload{eapPayload}, nil
	}

	// 处理 AKA 挑战
	if pkt.Type == eap.TypeAKA && pkt.Subtype == eap.SubtypeChallenge {
		if old := &s.akaChallenge; old.request != nil {
			if !bytes.Equal(eapRaw, old.request) {
				return nil, errAKAReauthentication
			}
			return notificationPayload(old.response), nil
		}
		if s.eapNotification.authenticated {
			return nil, errAKAReauthentication
		}
		s.akaIdentity.closed = true
		if err := s.validateAKACheckcode(pkt.Data); err != nil {
			return s.akaIdentityClientError(pkt.Identifier)
		}
		s.Logger.Info("收到 EAP-AKA Challenge (4G 模式)")
		attrs, err := eap.ParseAttributes(pkt.Data)
		if err != nil {
			return nil, err
		}
		strictAttrs, _, err := notificationAttributes(pkt.Data)
		if err != nil || len(eapRaw) < 8 || int(binary.BigEndian.Uint16(eapRaw[2:4])) != len(eapRaw) {
			return nil, errAKAReauthentication
		}
		for kind := range strictAttrs {
			switch kind {
			case eap.AT_RAND, eap.AT_AUTN, eap.AT_MAC:
			case eap.AT_NEXT_REAUTH_ID, eap.AT_NEXT_PSEUDONYM:
				return nil, errAKAReauthentication
			default:
				if kind < 128 {
					return nil, errAKAReauthentication
				}
			}
		}
		s.logAKARequestStructure(attrs)
		if attr, ok := attrs[eap.AT_RESULT_IND]; ok && len(attr.Value) != 2 {
			return nil, errEAPNotification
		}

		atRand, ok1 := attrs[eap.AT_RAND]
		atAutn, ok2 := attrs[eap.AT_AUTN]
		atMac, ok3 := attrs[eap.AT_MAC]

		// DEBUG: Print all received attributes
		var keys []uint8
		for k := range attrs {
			keys = append(keys, k)
		}
		s.Logger.Debug("Received EAP-AKA Challenge attributes", logger.Any("keys", keys))

		if !ok1 || !ok2 {
			return nil, errors.New("AKA 挑战中缺少 RAND 或 AUTN")
		}
		if !ok3 {
			return nil, errors.New("AKA 挑战中缺少 AT_MAC")
		}

		randVal, err := eapAKAAttrTail16(atRand.Value)
		if err != nil {
			return nil, err
		}
		autnVal, err := eapAKAAttrTail16(atAutn.Value)
		if err != nil {
			return nil, err
		}

		// 运行 SIM 算法
		res, ck, ik, auts, err := s.calculateAKAWithDiagnostics(randVal, autnVal)
		if err != nil {
			if errors.Is(err, sim.ErrSyncFailure) {
				// 发送同步失败
				// 载荷: EAP-Response/AKA-Sync-Failure
				// 属性: AT_AUTS
				return s.buildEAPSyncFailure(pkt.Identifier, auts)
			}
			return nil, fmt.Errorf("SIM AKA failed: %v", err)
		}
		if err := validateAKAResult(res, ck, ik); err != nil {
			return nil, err
		}

		identity, err := s.akaKeyIdentity()
		if err != nil {
			return nil, err
		}

		derive := func(order int) (kAut []byte, msk []byte, mk []byte, err error) {
			h := sha1.New()
			h.Write(identity)
			if order == 0 {
				h.Write(ik)
				h.Write(ck)
			} else {
				h.Write(ck)
				h.Write(ik)
			}
			mk = h.Sum(nil)

			keyMat := crypto.NewFIPS1862PRFSHA1(mk).Bytes(nil, 16+16+64)
			return keyMat[16:32], keyMat[32:96], mk, nil
		}

		tryOrders := []int{0, 1}
		var kAut []byte
		var msk []byte
		var mk []byte
		var macVerified bool
		macOutcome := akaMACInvalid
		var lastMacErr error
		recvMac, err := eapAKAAttrTail16(atMac.Value)
		if err != nil {
			return nil, err
		}
		for _, order := range tryOrders {
			kAutTry, mskTry, mkTry, err := derive(order)
			if err != nil {
				return nil, err
			}
			if s.cfg.DisableEAPMACValidation {
				kAut = kAutTry
				msk = mskTry
				mk = mkTry
				macVerified = true
				macOutcome = akaMACSkipped
				break
			}
			if err := verifyEAPAKAMAC(eapRaw, pkt.Data, kAutTry, recvMac); err == nil {
				kAut = kAutTry
				msk = mskTry
				mk = mkTry
				macVerified = true
				macOutcome = [2]akaMACOutcome{akaMACIKCK, akaMACCKIK}[order]
				break
			} else {
				lastMacErr = err
			}
		}
		s.logAKARequestMAC(macOutcome)
		if !macVerified {
			return nil, lastMacErr
		}

		var pending *AKATemporaryIdentity
		if !s.cfg.DisableEAPMACValidation {
			kEncr := crypto.NewFIPS1862PRFSHA1(mk).Bytes(nil, 16)
			pending, err = s.fullAuthTemporaryIdentity(strictAttrs, mk, kAut, kEncr)
			if err != nil {
				return nil, err
			}
		}

		// 构造响应：AT_RES [+ AT_RESULT_IND] + AT_MAC（对齐 SimAdmin eap_aka.rs）
		respAttrs := []byte{}

		// AT_RES
		resBits := make([]byte, 2)
		binary.BigEndian.PutUint16(resBits, uint16(len(res)*8))
		resValue := append(resBits, res...)
		atRes := &eap.Attribute{Type: eap.AT_RES, Value: resValue}
		respAttrs = append(respAttrs, atRes.Encode()...)

		if _, ok := attrs[eap.AT_RESULT_IND]; ok {
			atResultInd := &eap.Attribute{Type: eap.AT_RESULT_IND, Value: []byte{0, 0}}
			respAttrs = append(respAttrs, atResultInd.Encode()...)
		}

		// AT_MAC
		// 初始值为 16 字节零
		respMacAttr := &eap.Attribute{Type: eap.AT_MAC, Value: make([]byte, 18)}
		macOffset := len(respAttrs) // AT_MAC 属性开始的位置
		respAttrs = append(respAttrs, respMacAttr.Encode()...)

		// Construct EAP Packet
		respPkt := &eap.EAPPacket{
			Code:       eap.CodeResponse,
			Identifier: pkt.Identifier,
			Type:       eap.TypeAKA,
			Subtype:    eap.SubtypeChallenge,
			Data:       respAttrs,
		}

		eapBytes := respPkt.Encode()

		// 计算 MAC
		// EAP 数据包上的 HMAC-SHA1-128 (前 16 字节)
		mac := hmac.New(sha1.New, kAut)
		mac.Write(eapBytes)
		fullMac := mac.Sum(nil)

		// 将 MAC 放回数据包中 (在 macOffset + 2 + ??)。
		// 属性头是 2 字节。值头在内部？不。
		// 属性: Type(1), Len(1), Value...
		// AT_MAC 的值是 16 字节。
		// eapBytes 中的偏移量: Header(8) + macOffset + 2 (AttrHdr) = 10 + macOffset
		// 等等，EAP 头是 4 (Code, ID, Len). Type(1), Sub(1), Res(2). 总共 8。
		// 所以数据从 8 开始。
		macPos := 8 + macOffset + 4
		copy(eapBytes[macPos:], fullMac[:16])
		s.logAKAResponseStructure(eapBytes, kAut, akaResponseExpectation{identifier: pkt.Identifier, resOctets: len(res)})
		_, resultInd := attrs[eap.AT_RESULT_IND]
		s.completedEAPMethod(eap.TypeAKA, kAut, resultInd, false, 0, nil)
		s.MSK = msk
		if s.eapNotification.authenticated {
			s.akaPending = pending
		}
		s.akaChallenge = akaIdentityExchange{bytes.Clone(eapRaw), bytes.Clone(eapBytes)}
		s.akaReauth = akaReauthExchange{}

		eapPayload := &ikev2.EncryptedPayloadEAP{EAPMessage: eapBytes}

		return []ikev2.Payload{eapPayload}, nil
	}

	// EAP-AKA' Challenge (RFC 5448, 5G 核心网接入)
	if pkt.Type == eap.TypeAKAPrime && pkt.Subtype == eap.SubtypeChallenge {
		s.akaIdentity.closed = true
		return s.handleAKAPrimeChallenge(pkt, eapRaw)
	}

	// EAP-AKA Fast Re-authentication (RFC 4187 §5.4 / §9.7)
	if pkt.Type == eap.TypeAKA && pkt.Subtype == eap.SubtypeReauthentication {
		s.akaIdentity.closed = true
		if err := s.validateAKACheckcode(pkt.Data); err != nil {
			return s.akaIdentityClientError(pkt.Identifier)
		}
		return s.handleAKAReauthentication(pkt, eapRaw)
	}

	// EAP-AKA' Fast Re-authentication is not fully supported.
	// RFC 5448 §3.3 derives MK = PRF'(K_re, "EAP-AKA' re-auth"|Identity|counter|NONCE_S).
	// FastReauthContext only stores MK/K_aut/K_encr; full-auth never caches K_re, and
	// The Type23 fast context is not that KDF. Fail closed and keep Type50 Challenge.
	if pkt.Type == eap.TypeAKAPrime && pkt.Subtype == eap.SubtypeReauthentication {
		s.akaIdentity.closed = true
		if s.fastReauthCtx == nil || !s.fastReauthCtx.CanUseReauth() {
			s.Logger.Warn("收到 EAP-AKA' Re-auth 挑战但本地无缓存假名，回退全量认证")
			return nil, fmt.Errorf("fast reauth context not available")
		}
		s.Logger.Warn("EAP-AKA' fast reauth unsupported; falling back to full Challenge")
		s.fastReauthCtx = eap.NewFastReauthContext()
		return nil, fmt.Errorf("EAP-AKA' fast reauth unsupported: %w", ErrReauth)
	}

	return nil, fmt.Errorf("不支持的 EAP 类型/子类型: %d/%d", pkt.Type, pkt.Subtype)
}

func eapAKAAttrTail16(v []byte) ([]byte, error) {
	if len(v) < 16 {
		return nil, errors.New("AKA 属性长度不足")
	}
	return v[len(v)-16:], nil
}

func verifyEAPAKAMAC(eapRaw []byte, attrsData []byte, kAut []byte, recvMac []byte) error {
	macAttrOffset, ok := findEAPAttrOffset(attrsData, eap.AT_MAC)
	if !ok {
		return errors.New("未找到 AT_MAC 的偏移量")
	}
	macPos := 8 + macAttrOffset + 4
	if macPos < 0 || macPos+16 > len(eapRaw) {
		return errors.New("AT_MAC 偏移量越界")
	}

	tmp := make([]byte, len(eapRaw))
	copy(tmp, eapRaw)
	zero := make([]byte, 16)
	copy(tmp[macPos:macPos+16], zero)

	mac := hmac.New(sha1.New, kAut)
	mac.Write(tmp)
	fullMac := mac.Sum(nil)

	if !hmac.Equal(fullMac[:16], recvMac) {
		return errors.New("EAP-AKA AT_MAC 校验失败")
	}
	return nil
}

func findEAPAttrOffset(data []byte, attrType uint8) (int, bool) {
	offset := 0
	for offset+2 <= len(data) {
		t := data[offset]
		l := int(data[offset+1]) * 4
		if l == 0 || offset+l > len(data) {
			return 0, false
		}
		if t == attrType {
			return offset, true
		}
		offset += l
	}
	return 0, false
}

func (s *Session) buildEAPSyncFailure(id uint8, auts []byte) ([]ikev2.Payload, error) {
	// AT_AUTS
	atAuts := &eap.Attribute{Type: eap.AT_AUTS, Value: auts}

	respPkt := &eap.EAPPacket{
		Code:       eap.CodeResponse,
		Identifier: id,
		Type:       eap.TypeAKA,
		Subtype:    eap.SubtypeSyncFailure,
		Data:       atAuts.Encode(), // 只需要 AUTS
	}

	eapPayload := &ikev2.EncryptedPayloadEAP{EAPMessage: respPkt.Encode()}
	return []ikev2.Payload{eapPayload}, nil
}

// buildDeviceIdentityResponse 构造 DEVICE_IDENTITY 应答（TS 24.302 / 3GPP 私有 41101）
// 数据格式: [2 字节长度][1 字节身份类型][BCD 编码 IMEI/IMEISV]
// 类型 0x01=IMEI（15 位 + F padding 到 16），0x02=IMEISV（16 位）
func (s *Session) buildDeviceIdentityResponse(identityType uint8) ([]ikev2.Payload, error) {
	imei := s.cfg.IMEI
	if imei == "" {
		if p, ok := s.cfg.SIM.(sim.IMEIProvider); ok {
			v, err := p.GetIMEI()
			if err != nil {
				return nil, errors.New("equipment identity unavailable")
			}
			imei = v
		}
	}
	if identityType != 1 && identityType != 2 || (len(imei) != 15 && len(imei) != 16) {
		return nil, errors.New("equipment identity unavailable")
	}
	nonzero := false
	for i := range len(imei) {
		if imei[i] < '0' || imei[i] > '9' {
			return nil, errors.New("invalid equipment identity")
		}
		nonzero = nonzero || imei[i] != '0'
	}
	if !nonzero {
		return nil, errors.New("equipment identity unavailable")
	}

	// TS24.302 7.2.6: return the available IMEISV, otherwise the available
	// IMEI. Never manufacture an SV digit or an all-zero substitute.
	digits := imei
	identityType = 2
	if len(imei) == 15 {
		identityType = 1
		digits = imei + "F"
	}

	// BCD 编码（每 2 位数字 1 字节，低半字节在前）
	bcd := make([]byte, 0, len(digits)/2)
	for i := 0; i < len(digits); i += 2 {
		low := hexNibble(digits[i])
		high := hexNibble(digits[i+1])
		bcd = append(bcd, low|high<<4)
	}

	data := make([]byte, 2+1+len(bcd))
	binary.BigEndian.PutUint16(data[0:2], uint16(1+len(bcd)))
	data[2] = identityType
	copy(data[3:], bcd)

	s.Logger.Info("应答 DEVICE_IDENTITY",
		logger.Int("type", int(identityType)))

	return []ikev2.Payload{
		&ikev2.EncryptedPayloadNotify{
			ProtocolID: ikev2.ProtoIKE,
			NotifyType: ikev2.DEVICE_IDENTITY,
			NotifyData: data,
		},
	}, nil
}

func hexNibble(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	}
	return 0
}

func (s *Session) sendIKEAuthEAP(payloads []ikev2.Payload) error {
	// 包装载荷在 SK 中
	data, err := s.encryptAndWrap(payloads, ikev2.IKE_AUTH, false)
	if err != nil {
		return err
	}
	return s.socket.SendIKE(data)
}

func (s *Session) sendIKEAuthFinal() error {
	payloads, err := s.buildIKEAuthFinalPayloads()
	if err != nil {
		return err
	}

	data, err := s.encryptAndWrap(payloads, ikev2.IKE_AUTH, false)
	if err != nil {
		return err
	}

	return s.socket.SendIKE(data)
}

func (s *Session) buildIKEAuthFinalPayloads() ([]ikev2.Payload, error) {
	// Message 6: SK { AUTH }
	// AUTH = prf( prf(MSK, "Key Pad for IKEv2"), <SignedOctets> )
	// SignedOctets = RealMessage1 | NonceR_Data | prf(SK_pi, IDi_Body)

	if err := requirePostEAPMSK(s.MSK); err != nil {
		return nil, err
	}

	prf := s.PRFAlg
	if prf == nil {
		return nil, errors.New("PRF 不可用")
	}

	// 2. 计算签名八位字节
	// 2a. RealMessage1 (IKE_SA_INIT 请求)
	// 我们把它存储在 s.msgBuffer 了吗？
	// 确保 s.msgBuffer 正是发送的内容。
	if len(s.msgBuffer) == 0 {
		return nil, errors.New("SA_INIT 请求未存储")
	}

	// 2b. NonceR
	if len(s.nr) == 0 {
		return nil, errors.New("NonceR 不可用")
	}

	if len(s.localIDiBody) == 0 {
		return nil, errors.New("AUTH1 local IDi body unavailable")
	}

	authData, err := computeIKEAuthData(ikeAuthPRFInput{
		PRF:             prf,
		MSK:             s.MSK,
		InitiatorPRFKey: s.Keys.SK_pi,
		InitiatorIDBody: s.localIDiBody,
		SAInitRequest:   s.msgBuffer,
		ResponderNonce:  s.nr,
	})
	if err != nil {
		return nil, fmt.Errorf("build IKE_AUTH data: %w", err)
	}

	// 3. 构造 AUTH 载荷
	authPayload := &ikev2.EncryptedPayloadAuth{
		AuthMethod: ikev2.AuthMethodSharedKey, // 2 = Shared Key MIC
		AuthData:   authData,
	}
	return []ikev2.Payload{authPayload}, nil
}

func (s *Session) handleIKEAuthFinalResp(data []byte) error {
	message, err := s.decodeProtectedIKE(data)
	if err != nil {
		return fmt.Errorf("解析 IKE_AUTH 最终响应失败: %w", err)
	}
	if message == nil {
		return errFragmentIncomplete
	}
	return s.handleIKEAuthFinalParsed(message.payloads)
}

func (s *Session) handleIKEAuthFinalParsed(payloads []ikev2.Payload) error {
	return s.handleIKEAuthFinalAt(payloads, time.Now())
}

func (s *Session) handleIKEAuthFinalAt(payloads []ikev2.Payload, received time.Time) error {
	s.logIKEAuthMetadata(ikeAuthPhaseFinal, payloads)

	if s.resumeAuthPending {
		return fmt.Errorf("SESSION_RESUME AUTH signed material not implemented: %w", ErrResumeAuthUnsupported)
	}
	if !ikeAuthHasChildSA(payloads) {
		// A final error (notably address allocation failure) has no Child SA.
		// Preserve the rejection instead of asking for another initiator AUTH.
		if rej := s.ikeAuthErrorNotify(payloads); rej != nil {
			return rej
		}
		if err := s.captureEAPIDr(payloads); err != nil {
			return err
		}
		return errIKEAuthNeedInitiatorAUTH
	}
	idrBody, err := s.verifyPostEAPResponderAUTH(payloads)
	if err != nil {
		return err
	}
	if rej := s.ikeAuthErrorNotify(payloads); rej != nil {
		return rej
	}
	selection, err := s.selectInitialChild(payloads)
	selectionErr := err

	lifetime, mobike := s.authLifetime, s.mobikeSupported
	var ticket []byte
	var redirect *RedirectError
	seenNotify := map[uint16]bool{}
	for _, pl := range payloads {
		switch p := pl.(type) {
		case *ikev2.EncryptedPayloadNotify:
			// 打印所有收到的状态类型 Notify，便于调试
			s.Logger.Debug("IKE_AUTH 收到状态 Notify",
				logger.Int("type", int(p.NotifyType)),
				logger.Int("dataLen", len(p.NotifyData)))
			// RFC 4478: AUTH_LIFETIME — ePDG 通告 IKE SA 最大生存时间（秒）
			if p.NotifyType == ikev2.AUTH_LIFETIME || p.NotifyType == ikev2.MOBIKE_SUPPORTED || p.NotifyType == ikev2.TICKET_OPAQUE || p.NotifyType == ikev2.REDIRECT {
				// RFC 4478 specifies protocol zero. Some authenticated peers use
				// IKE/1 for this IKE-wide advisory; accept only that equivalent
				// scope, without changing the other status-notify rules.
				ikeLifetime := p.NotifyType == ikev2.AUTH_LIFETIME && p.ProtocolID == ikev2.ProtoIKE
				if p.ProtocolID != 0 && !ikeLifetime || len(p.SPI) != 0 || seenNotify[p.NotifyType] {
					return errInitialChild
				}
				seenNotify[p.NotifyType] = true
			}
			if p.NotifyType == ikev2.AUTH_LIFETIME {
				if len(p.NotifyData) != 4 {
					return errInitialChild
				}
				lifetime = binary.BigEndian.Uint32(p.NotifyData)
			}
			// RFC 5685: REDIRECT
			if p.NotifyType == ikev2.REDIRECT {
				addr, err := ParseRedirectData(p.NotifyData)
				if err != nil {
					return errInitialChild
				} else {
					redirect = &RedirectError{NewAddr: addr}
				}
			}
			// RFC 4555: MOBIKE_SUPPORTED
			if p.NotifyType == ikev2.MOBIKE_SUPPORTED {
				if len(p.NotifyData) != 0 {
					return errInitialChild
				}
				mobike = true
			}
			// RFC 5723: Session Resumption
			if p.NotifyType == ikev2.TICKET_OPAQUE {
				if len(p.NotifyData) == 0 {
					return errInitialChild
				}
				ticket = append([]byte(nil), p.NotifyData...)
			}
		}
	}
	if selectionErr != nil {
		if hint := s.initialChildProposalNumberHint(payloads); hint != nil {
			return hint
		}
		return selectionErr
	}
	if redirect != nil {
		return redirect
	}

	remoteSPI := binary.BigEndian.Uint32(selection.proposal.SPI)
	encrID, integID, encrKeyLenBits := selection.encr, selection.integ, selection.keyBits

	childEnc, err := crypto.GetEncrypterWithKeyLen(encrID, encrKeyLenBits)
	if err != nil {
		return fmt.Errorf("不支持的 Child SA 加密算法: %d", encrID)
	}

	isAEAD := encrID == uint16(ikev2.ENCR_AES_GCM_16) || encrID == uint16(ikev2.ENCR_AES_GCM_12) || encrID == uint16(ikev2.ENCR_AES_GCM_8)
	encKeyLen := childEnc.KeySize()
	saltLen := 0
	integKeyLen := 0
	var integAlg crypto.IntegrityAlgorithm
	if isAEAD {
		saltLen = 4
	} else {
		integAlg, err = crypto.GetIntegrityAlgorithm(integID)
		if err != nil {
			return fmt.Errorf("不支持的 Child SA 完整性算法: %d", integID)
		}
		integKeyLen = integAlg.KeySize()
	}
	keyMatLen := 2 * (encKeyLen + saltLen + integKeyLen)

	seed := make([]byte, 0, len(s.ni)+len(s.nr))
	seed = append(seed, s.ni...)
	seed = append(seed, s.nr...)

	keyMat, err := crypto.PrfPlus(s.PRFAlg, s.Keys.SK_d, seed, keyMatLen)
	if err != nil {
		return err
	}

	cursor := 0
	outEncKey := keyMat[cursor : cursor+encKeyLen+saltLen]
	cursor += encKeyLen + saltLen
	outIntegKey := []byte(nil)
	if !isAEAD {
		outIntegKey = keyMat[cursor : cursor+integKeyLen]
		cursor += integKeyLen
	}
	inEncKey := keyMat[cursor : cursor+encKeyLen+saltLen]
	cursor += encKeyLen + saltLen
	inIntegKey := []byte(nil)
	if !isAEAD {
		inIntegKey = keyMat[cursor : cursor+integKeyLen]
	}

	var childOut, childIn *ipsec.SecurityAssociation
	if isAEAD {
		childOut = ipsec.NewSecurityAssociation(remoteSPI, childEnc, outEncKey, nil)
		childIn = ipsec.NewSecurityAssociation(s.childSPI, childEnc, inEncKey, nil)
	} else {
		childOut = ipsec.NewSecurityAssociationCBC(remoteSPI, childEnc, outEncKey, integAlg, outIntegKey)
		childIn = ipsec.NewSecurityAssociationCBC(s.childSPI, childEnc, inEncKey, integAlg, inIntegKey)
	}
	childOut.RemoteSPI = s.childSPI
	childIn.RemoteSPI = remoteSPI

	// All validation and key derivation finished. No error paths or external
	// callbacks may observe a partially committed initial Child transaction.
	s.childMu.Lock()
	s.ChildSAOut, s.ChildSAIn = childOut, childIn
	if s.ChildSAsIn != nil {
		s.ChildSAsIn[s.childSPI] = s.ChildSAIn
	}

	// 保存 Child SA 算法 ID (供 XFRM 模式使用)
	s.childEncrID = encrID
	s.childIntegID = integID
	s.childEncrKeyLenBits = encrKeyLenBits
	s.childESN = false
	s.cpConfig = selection.cp
	s.tsi, s.tsr = selection.tsi, selection.tsr
	s.peerIDrBody = append([]byte(nil), idrBody...)
	s.authLifetime, s.mobikeSupported = lifetime, mobike
	if ticket != nil {
		s.resumeTicket = ticket
		s.resumeOldSKd = append([]byte(nil), s.Keys.SK_d...)
	}
	s.childOutPolicies = append(s.childOutPolicies, childOutPolicy{saOut: childOut, tsr: s.tsr})
	s.childMu.Unlock()
	if seenNotify[ikev2.AUTH_LIFETIME] {
		s.setAuthLifetime(lifetime, received, nil)
	}

	if s.ws != nil {
		s.ws.LogChildSA(s.childSPI, remoteSPI, s.cfg.LocalAddr, s.cfg.EpDGAddr, inEncKey, outEncKey, encrID)
	}

	if ticket != nil && s.cfg.OnTicketUpdate != nil {
		s.cfg.OnTicketUpdate(append([]byte(nil), ticket...), append([]byte(nil), s.resumeOldSKd...))
	}
	s.Logger.Info("ePDG_SA_AUTH: IPsec ESP (Child SA) 算法协商成功", logger.String("encr", ikev2.EncrToString(encrID)), logger.String("integ", ikev2.IntegToString(integID)), logger.Bool("esn", false))

	s.Logger.Debug("Child SA 已建立", logger.Uint32("localSPI", s.childSPI), logger.Uint32("remoteSPI", remoteSPI))
	return nil
}

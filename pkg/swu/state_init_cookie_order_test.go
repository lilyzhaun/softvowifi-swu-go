package swu

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/1239t/swu-go/pkg/crypto"
	"github.com/1239t/swu-go/pkg/ikev2"
	"github.com/1239t/swu-go/pkg/ipsec"
	"go.uber.org/zap"
)

func Test_InitCookieRetryIsFirstAndPreservesOtherBytes(t *testing.T) {
	for _, layout := range []string{"", ikev2.ProposalLayoutSingleCombined} {
		for _, size := range []int{1, 20, 64} {
			t.Run(fmt.Sprintf("%s/%d", layout, size), func(t *testing.T) {
				sess := newInitTestSession(layout)
				initial, err := sess.buildIKESAInitPacket()
				if err != nil {
					t.Fatal(err)
				}
				if initial[16] != byte(ikev2.SA) {
					t.Fatal("initial request must remain SA-first without a Cookie")
				}
				for _, value := range []byte{7, 9} {
					// Explicitly synthetic challenge; never a live server Cookie.
					cookie := bytes.Repeat([]byte{value}, size)
					response := ikev2.NewIKEPacket()
					response.Header.SPIi = sess.SPIi
					response.Header.Version = 0x20
					response.Header.ExchangeType = ikev2.IKE_SA_INIT
					response.Header.Flags = ikev2.FlagResponse
					response.Payloads = []ikev2.Payload{&ikev2.EncryptedPayloadNotify{NotifyType: ikev2.COOKIE, NotifyData: cookie}}
					raw, err := response.Encode()
					if err != nil {
						t.Fatal(err)
					}
					if err := sess.handleIKESAInitResp(raw, sess.msgBuffer); !errors.Is(err, ErrCookieRequired) {
						t.Fatalf("challenge did not request retry: %v", err)
					}
					retry, err := sess.buildIKESAInitPacket()
					if err != nil {
						t.Fatal(err)
					}
					packet, err := ikev2.DecodePacket(retry)
					if err != nil {
						t.Fatal(err)
					}
					first, ok := packet.Payloads[0].(*ikev2.EncryptedPayloadNotify)
					if retry[16] != byte(ikev2.N) || !ok || first.NotifyType != ikev2.COOKIE || !bytes.Equal(first.NotifyData, cookie) {
						t.Fatal("RFC7296 COOKIE must be the first retry payload")
					}
					cookieLength := int(binary.BigEndian.Uint16(retry[30:32]))
					if cookieLength != 8+size || !bytes.Equal(retry[28+cookieLength:], initial[28:]) {
						t.Fatal("Cookie retry changed another payload or inserted a second Cookie")
					}
					if !bytes.Equal(retry[:16], initial[:16]) || !bytes.Equal(retry[17:24], initial[17:24]) || len(retry) != len(initial)+cookieLength {
						t.Fatal("Cookie retry changed SPI, exchange, version, flags, message ID, or body length")
					}
					if sess.SPIr != 0 || sess.Keys != nil || sess.SequenceNumber.Load() != 0 {
						t.Fatal("Cookie challenge advanced the authenticated state")
					}
				}
			})
		}
	}
}

func Test_ConnectCookieRetryStartsWithCookieOverUDP(t *testing.T) {
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	if err := peer.SetDeadline(time.Now().Add(4 * time.Second)); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{EpDGAddr: "127.0.0.1", LocalAddr: "127.0.0.1", EpDGPort: uint16(peer.LocalAddr().(*net.UDPAddr).Port)}
	cfg.TransportFactory = func(local, remote string) (Transport, error) {
		return ipsec.NewSocketManager(local, remote, "127.0.0.1:1")
	}
	sess := NewSession(cfg, zap.NewNop())
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
	finished := make(chan error, 1)
	go func() { finished <- sess.Connect(ctx); close(finished) }()
	t.Cleanup(func() { cancel(); sess.Shutdown(); <-finished })
	var firstBody []byte
	for attempt := 0; attempt < 2; attempt++ {
		buffer := make([]byte, 4096)
		count, client, err := peer.ReadFromUDP(buffer)
		if err != nil {
			t.Fatal(err)
		}
		packet, err := ikev2.DecodePacket(buffer[:count])
		if err != nil {
			t.Fatal(err)
		}
		if attempt == 1 {
			cookie, ok := packet.Payloads[0].(*ikev2.EncryptedPayloadNotify)
			if !ok || cookie.NotifyType != ikev2.COOKIE || !bytes.Equal(cookie.NotifyData, []byte{1, 2, 3, 4}) {
				t.Fatal("production Connect sent a misplaced Cookie over UDP")
			}
			length := int(binary.BigEndian.Uint16(buffer[30:32]))
			if !bytes.Equal(buffer[28+length:count], firstBody) {
				t.Fatal("production Cookie retry changed non-Cookie payload bytes")
			}
			break
		}
		firstBody = bytes.Clone(buffer[28:count])
		response := ikev2.NewIKEPacket()
		response.Header = packet.Header
		response.Header.Flags = ikev2.FlagResponse
		response.Payloads = []ikev2.Payload{&ikev2.EncryptedPayloadNotify{NotifyType: ikev2.COOKIE, NotifyData: []byte{1, 2, 3, 4}}}
		raw, err := response.Encode()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := peer.WriteToUDP(raw, client); err != nil {
			t.Fatal(err)
		}
	}
}

type zeroCallSIM struct {
	vectorSIM
}

func (z *zeroCallSIM) GetIMSI() (string, error) {
	z.calls++
	return "", errors.New("unexpected SIM call")
}

func Test_InitSingleNotifyEmptySPIIgnoresProtocolIDAndPreservesGuards(t *testing.T) {
	baseSess, _ := initSelectionFixture(t)
	offered := bytes.Clone(baseSess.msgBuffer)
	cookie22 := bytes.Repeat([]byte{0x5a}, 22)

	encodeSingleNotify := func(spii uint64, proto ikev2.ProtocolID, spi []byte, notifyType uint16, data []byte) []byte {
		pkt := ikev2.NewIKEPacket()
		pkt.Header = &ikev2.IKEHeader{
			SPIi:         spii,
			Version:      0x20,
			ExchangeType: ikev2.IKE_SA_INIT,
			Flags:        ikev2.FlagResponse,
		}
		pkt.Payloads = []ikev2.Payload{&ikev2.EncryptedPayloadNotify{
			ProtocolID: proto,
			SPI:        spi,
			NotifyType: notifyType,
			NotifyData: data,
		}}
		raw, err := pkt.Encode()
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}

	// 1. Empty SPI must ignore all ProtocolID values (0, 1, 2, 3, 255) while preserving typed handling.
	for _, proto := range []ikev2.ProtocolID{0, ikev2.ProtoIKE, ikev2.ProtoAH, ikev2.ProtoESP, 255} {
		t.Run(fmt.Sprintf("empty_spi_proto_%d", proto), func(t *testing.T) {
			// 1a. Legal 22-byte COOKIE (58-byte packet) is accepted as COOKIE challenge.
			rawCookie := encodeSingleNotify(baseSess.SPIi, proto, nil, ikev2.COOKIE, cookie22)
			if len(rawCookie) != 58 || rawCookie[32] != byte(proto) || rawCookie[33] != 0 {
				t.Fatalf("unexpected 58B COOKIE wire framing: len=%d proto=%d spiLen=%d", len(rawCookie), rawCookie[32], rawCookie[33])
			}
			decoded, err := ikev2.DecodeInitResponse(rawCookie, offered)
			if err != nil || decoded == nil || len(decoded.Payloads) != 1 {
				t.Errorf("DecodeInitResponse(COOKIE proto=%d): %v", proto, err)
			}
			sCookie := newInitTestSession("")
			sCookie.SPIi = baseSess.SPIi
			sCookie.msgBuffer = bytes.Clone(offered)
			if err := sCookie.handleIKESAInitResp(rawCookie, offered); !errors.Is(err, ErrCookieRequired) {
				t.Errorf("handleIKESAInitResp(COOKIE proto=%d) = %v, want ErrCookieRequired", proto, err)
			} else if !sCookie.sendCookie || !bytes.Equal(sCookie.cookie, cookie22) || sCookie.SPIr != 0 || sCookie.Keys != nil {
				t.Errorf("COOKIE proto=%d did not record challenge or mutated SA state", proto)
			}

			// 1b. Notify 14 (NO_PROPOSAL_CHOSEN) decodes as single Notify and fails in handleIKESAInitResp without accepting.
			rawNoProp := encodeSingleNotify(baseSess.SPIi, proto, nil, ikev2.NO_PROPOSAL_CHOSEN, nil)
			if _, err := ikev2.DecodeInitResponse(rawNoProp, offered); err != nil {
				t.Errorf("DecodeInitResponse(NO_PROPOSAL_CHOSEN proto=%d): %v", proto, err)
			}
			sNoProp := newInitTestSession("")
			sNoProp.SPIi = baseSess.SPIi
			err = sNoProp.handleIKESAInitResp(rawNoProp, offered)
			if err == nil || errors.Is(err, ErrCookieRequired) || !strings.Contains(err.Error(), "NO_PROPOSAL_CHOSEN") || sNoProp.SPIr != 0 || sNoProp.Keys != nil {
				t.Errorf("handleIKESAInitResp(NO_PROPOSAL_CHOSEN proto=%d) = %v", proto, err)
			}

			// 1c. Notify 17 (INVALID_KE_PAYLOAD) and unknown error type 8195 return InitNotifyHintError (never accepted).
			for _, tc := range []struct {
				notifyType uint16
				data       []byte
				wantGroup  uint16
			}{
				{ikev2.INVALID_KE_PAYLOAD, []byte{0, 19}, 19},
				{8195, []byte{0x01, 0x02}, 0},
			} {
				rawErr := encodeSingleNotify(baseSess.SPIi, proto, nil, tc.notifyType, tc.data)
				_, err := ikev2.DecodeInitResponse(rawErr, offered)
				var hint *ikev2.InitNotifyHintError
				if !errors.Is(err, ikev2.ErrInitResponse) || !errors.As(err, &hint) || hint.NotifyType != tc.notifyType || hint.DataLen != len(tc.data) || hint.SuggestedDHGroup != tc.wantGroup {
					t.Errorf("DecodeInitResponse(type=%d proto=%d) = %v, want InitNotifyHintError", tc.notifyType, proto, err)
				}
				sErr := newInitTestSession("")
				sErr.SPIi = baseSess.SPIi
				if err := sErr.handleIKESAInitResp(rawErr, offered); err == nil || errors.Is(err, ErrCookieRequired) || sErr.SPIr != 0 || sErr.Keys != nil {
					t.Errorf("handleIKESAInitResp(type=%d proto=%d) = %v", tc.notifyType, proto, err)
				}
			}

			// 1d. Non-COOKIE status notify (e.g. INITIAL_CONTACT 16384) remains plain ErrInitResponse without hint.
			rawStatus := encodeSingleNotify(baseSess.SPIi, proto, nil, ikev2.INITIAL_CONTACT, nil)
			_, err = ikev2.DecodeInitResponse(rawStatus, offered)
			var hint *ikev2.InitNotifyHintError
			if !errors.Is(err, ikev2.ErrInitResponse) || errors.As(err, &hint) {
				t.Fatalf("status notify proto=%d result = %v, want plain ErrInitResponse", proto, err)
			}
		})
	}

	// 2. Non-empty SPI is still rejected for all ProtocolID values and notify types.
	for _, proto := range []ikev2.ProtocolID{0, ikev2.ProtoIKE, ikev2.ProtoAH, ikev2.ProtoESP, 255} {
		for _, spi := range [][]byte{{1}, {1, 2, 3, 4}} {
			for _, notifyType := range []uint16{ikev2.COOKIE, ikev2.NO_PROPOSAL_CHOSEN, ikev2.INVALID_KE_PAYLOAD, 8195} {
				raw := encodeSingleNotify(baseSess.SPIi, proto, spi, notifyType, []byte{0, 19})
				_, err := ikev2.DecodeInitResponse(raw, offered)
				var hint *ikev2.InitNotifyHintError
				if !errors.Is(err, ikev2.ErrInitResponse) || errors.As(err, &hint) {
					t.Fatalf("non-empty SPI(len=%d) proto=%d type=%d was not rejected: %v", len(spi), proto, notifyType, err)
				}
				s := newInitTestSession("")
				s.SPIi = baseSess.SPIi
				if err := s.handleIKESAInitResp(raw, offered); err == nil || errors.Is(err, ErrCookieRequired) || s.sendCookie || s.SPIr != 0 || s.Keys != nil {
					t.Fatalf("non-empty SPI accepted in handleIKESAInitResp: %v", err)
				}
			}
		}
	}

	// 3. Header binding, COOKIE bounds/duplication, and SA selection guards remain strict even with ProtocolID=1.
	badCookieCases := map[string]func() []byte{
		"wrongSPIi": func() []byte {
			return encodeSingleNotify(baseSess.SPIi^1, ikev2.ProtoIKE, nil, ikev2.COOKIE, cookie22)
		},
		"direction_initiator": func() []byte {
			raw := encodeSingleNotify(baseSess.SPIi, ikev2.ProtoIKE, nil, ikev2.COOKIE, cookie22)
			raw[19] |= ikev2.FlagInitiator
			return raw
		},
		"direction_request": func() []byte {
			raw := encodeSingleNotify(baseSess.SPIi, ikev2.ProtoIKE, nil, ikev2.COOKIE, cookie22)
			raw[19] = 0
			return raw
		},
		"msgid": func() []byte {
			raw := encodeSingleNotify(baseSess.SPIi, ikev2.ProtoIKE, nil, ikev2.COOKIE, cookie22)
			raw[23] = 1
			return raw
		},
		"exchange": func() []byte {
			raw := encodeSingleNotify(baseSess.SPIi, ikev2.ProtoIKE, nil, ikev2.COOKIE, cookie22)
			raw[18] = byte(ikev2.IKE_AUTH)
			return raw
		},
		"length": func() []byte {
			raw := encodeSingleNotify(baseSess.SPIi, ikev2.ProtoIKE, nil, ikev2.COOKIE, cookie22)
			raw[27]--
			return raw
		},
		"empty_cookie": func() []byte {
			return encodeSingleNotify(baseSess.SPIi, ikev2.ProtoIKE, nil, ikev2.COOKIE, nil)
		},
		"cookie_65": func() []byte {
			return encodeSingleNotify(baseSess.SPIi, ikev2.ProtoIKE, nil, ikev2.COOKIE, bytes.Repeat([]byte{0x77}, 65))
		},
		"duplicate_cookie": func() []byte {
			pkt := ikev2.NewIKEPacket()
			pkt.Header = &ikev2.IKEHeader{SPIi: baseSess.SPIi, Version: 0x20, ExchangeType: ikev2.IKE_SA_INIT, Flags: ikev2.FlagResponse}
			n := &ikev2.EncryptedPayloadNotify{ProtocolID: ikev2.ProtoIKE, NotifyType: ikev2.COOKIE, NotifyData: cookie22}
			pkt.Payloads = []ikev2.Payload{n, n}
			raw, err := pkt.Encode()
			if err != nil {
				t.Fatal(err)
			}
			return raw
		},
		"crossSA": func() []byte {
			_, pkt := initSelectionFixture(t)
			pkt.Header.SPIi = baseSess.SPIi
			selectedInitProposal(pkt).Transforms[0].Attributes[0].Val = 256
			raw, err := pkt.Encode()
			if err != nil {
				t.Fatal(err)
			}
			return raw
		},
		"wrong_proposal_num": func() []byte {
			_, pkt := initSelectionFixture(t)
			pkt.Header.SPIi = baseSess.SPIi
			selectedInitProposal(pkt).ProposalNum = 99
			raw, err := pkt.Encode()
			if err != nil {
				t.Fatal(err)
			}
			return raw
		},
		"wrong_dh": func() []byte {
			_, pkt := initSelectionFixture(t)
			pkt.Header.SPIi = baseSess.SPIi
			pkt.Payloads[1].(*ikev2.EncryptedPayloadKE).DHGroup = ikev2.MODP_1024_bit
			raw, err := pkt.Encode()
			if err != nil {
				t.Fatal(err)
			}
			return raw
		},
	}
	for name, build := range badCookieCases {
		t.Run(name, func(t *testing.T) {
			raw := build()
			if _, err := ikev2.DecodeInitResponse(raw, offered); !errors.Is(err, ikev2.ErrInitResponse) {
				t.Fatalf("%s: DecodeInitResponse = %v, want ErrInitResponse", name, err)
			}
			s := newInitTestSession("")
			s.SPIi = baseSess.SPIi
			if err := s.handleIKESAInitResp(raw, offered); err == nil || errors.Is(err, ErrCookieRequired) || s.sendCookie || s.SPIr != 0 || s.Keys != nil {
				t.Fatalf("%s: handleIKESAInitResp = %v, sendCookie=%v", name, err, s.sendCookie)
			}
		})
	}
}

func Test_ConnectUDP_CookieProtocolOneRetriesUnchangedAndReachesProtectedAuth(t *testing.T) {
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	if err := peer.SetDeadline(time.Now().Add(4 * time.Second)); err != nil {
		t.Fatal(err)
	}

	simTracker := &zeroCallSIM{}
	sess := newInitTestSession("")
	sess.cfg.SIM = simTracker
	sess.cfg.LocalAddr = "127.0.0.1"
	sess.cfg.LocalPort = 0
	sess.cfg.EpDGAddr = "127.0.0.1"
	sess.cfg.EpDGPort = uint16(peer.LocalAddr().(*net.UDPAddr).Port)
	sess.cfg.FastReauthID = "synthetic@invalid"

	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- sess.Connect(ctx) }()
	t.Cleanup(func() { cancel(); sess.Shutdown() })

	buf := make([]byte, 4096)
	// 1. Read initial IKE_SA_INIT request.
	n1, clientAddr, err := peer.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	firstOffer := bytes.Clone(buf[:n1])
	req1, err := ikev2.DecodePacket(firstOffer)
	if err != nil || firstOffer[16] != byte(ikev2.SA) {
		t.Fatalf("initial request decode err=%v nextPayload=%d", err, firstOffer[16])
	}

	// 2. Reply with 58B single-Notify COOKIE using ProtocolID=1 and empty SPI.
	cookie22 := bytes.Repeat([]byte{0x42}, 22)
	cookieResp := ikev2.NewIKEPacket()
	cookieResp.Header = &ikev2.IKEHeader{
		SPIi:         req1.Header.SPIi,
		Version:      0x20,
		ExchangeType: ikev2.IKE_SA_INIT,
		Flags:        ikev2.FlagResponse,
	}
	cookieResp.Payloads = []ikev2.Payload{&ikev2.EncryptedPayloadNotify{
		ProtocolID: ikev2.ProtoIKE,
		NotifyType: ikev2.COOKIE,
		NotifyData: cookie22,
	}}
	cookieWire, err := cookieResp.Encode()
	if err != nil || len(cookieWire) != 58 || cookieWire[32] != 1 || cookieWire[33] != 0 {
		t.Fatalf("unexpected COOKIE wire: len=%d err=%v", len(cookieWire), err)
	}
	if _, err := peer.WriteToUDP(cookieWire, clientAddr); err != nil {
		t.Fatal(err)
	}

	// 3. Read retried IKE_SA_INIT request and verify SPIi, nonce, KE and SA are unchanged.
	n2, clientAddr, err := peer.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("read COOKIE retry over UDP: %v", err)
	}
	retryOffer := bytes.Clone(buf[:n2])
	req2, err := ikev2.DecodePacket(retryOffer)
	if err != nil {
		t.Fatal(err)
	}
	firstPayload, ok := req2.Payloads[0].(*ikev2.EncryptedPayloadNotify)
	if !ok || firstPayload.NotifyType != ikev2.COOKIE || firstPayload.ProtocolID != 0 || len(firstPayload.SPI) != 0 || !bytes.Equal(firstPayload.NotifyData, cookie22) {
		t.Fatalf("unexpected retry COOKIE payload: %+v", firstPayload)
	}
	cookiePayloadLen := 8 + len(cookie22)
	if req2.Header.SPIi != req1.Header.SPIi || req2.Header.MessageID != 0 || !bytes.Equal(retryOffer[28+cookiePayloadLen:], firstOffer[28:]) {
		t.Fatal("COOKIE retry modified original SPIi, MessageID, SA, KE, Nonce or NAT-D bytes")
	}

	// 4. Reply with valid SA_INIT response selecting the 4th original suite.
	sa2, ke2, _ := decodeInitSA(t, retryOffer)
	var ni []byte
	for _, pl := range req2.Payloads {
		if nonce, ok := pl.(*ikev2.EncryptedPayloadNonce); ok {
			ni = nonce.NonceData
		}
	}
	dh14, err := crypto.NewDiffieHellman(14)
	if err != nil {
		t.Fatal(err)
	}
	if err := dh14.GenerateKey(); err != nil {
		t.Fatal(err)
	}
	secret, err := dh14.ComputeSharedSecret(ke2.KEData)
	if err != nil {
		t.Fatal(err)
	}
	nr := bytes.Repeat([]byte{0x3c}, 32)
	initResp := ikev2.NewIKEPacket()
	initResp.Header = &ikev2.IKEHeader{
		SPIi:         req2.Header.SPIi,
		SPIr:         0x1122334455667788,
		Version:      0x20,
		ExchangeType: ikev2.IKE_SA_INIT,
		Flags:        ikev2.FlagResponse,
	}
	initResp.Payloads = []ikev2.Payload{
		&ikev2.EncryptedPayloadSA{Proposals: []*ikev2.Proposal{sa2.Proposals[len(sa2.Proposals)-1]}},
		&ikev2.EncryptedPayloadKE{DHGroup: 14, KEData: dh14.PublicKeyBytes()},
		&ikev2.EncryptedPayloadNonce{NonceData: nr},
	}
	initRespWire, err := initResp.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := peer.WriteToUDP(initRespWire, clientAddr); err != nil {
		t.Fatal(err)
	}

	// 5. Read protected IKE_AUTH request, verify ICV and decrypt identity; verify 0 SIM calls.
	n3, _, err := peer.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	authWire := bytes.Clone(buf[:n3])
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Connect stop after IKE_AUTH: %v", err)
	}
	if simTracker.calls != 0 {
		t.Fatalf("SIM calls = %d, want 0", simTracker.calls)
	}

	authHdr, err := ikev2.DecodeHeader(authWire)
	if err != nil || authHdr.ExchangeType != ikev2.IKE_AUTH || authHdr.MessageID != 1 || authHdr.NextPayload != ikev2.SK {
		t.Fatalf("unexpected IKE_AUTH header: %+v err=%v", authHdr, err)
	}
	keys := independentSHA256Keys(secret, append(bytes.Clone(ni), nr...), initResp.Header)
	mac := hmac.New(sha256.New, keys[32:64])
	mac.Write(authWire[:len(authWire)-16])
	if !hmac.Equal(mac.Sum(nil)[:16], authWire[len(authWire)-16:]) {
		t.Fatal("independent peer rejected IKE_AUTH HMAC-SHA256-128 ICV")
	}
	block, err := aes.NewCipher(keys[96:128])
	if err != nil {
		t.Fatal(err)
	}
	plain := make([]byte, len(authWire)-64)
	cipher.NewCBCDecrypter(block, authWire[32:48]).CryptBlocks(plain, authWire[48:len(authWire)-16])
	if !bytes.Contains(plain, []byte("synthetic@invalid")) {
		t.Fatal("independent peer could not decrypt initial IKE_AUTH identity")
	}
}

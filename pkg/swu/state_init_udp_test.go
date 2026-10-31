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
	"net"
	"testing"
	"time"

	"github.com/1239t/swu-go/pkg/crypto"
	"github.com/1239t/swu-go/pkg/ikev2"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func Test_ConnectProtectsAuth_whenUDPPeerSelectsFourthSuite(t *testing.T) {
	for _, scenario := range []struct {
		name   string
		reject bool
		mutate func([]byte) []byte
		single uint8
		hint   bool
		policy bool
	}{
		{name: "fourth suite"},
		{name: "explicit fourth suite and GCM128 Child", policy: true},
		{name: "unauthenticated KE hint then fourth suite", hint: true},
		{name: "fresh single fourth suite", single: 4},
		{name: "cross proposal rejected", reject: true},
		{name: "minor V reserved", mutate: initRFCReservedWire},
		{name: "unknown noncritical", mutate: initUnknownNoncriticalWire},
		{name: "unknown critical", reject: true, mutate: initUnknownCriticalWire},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer peer.Close()
			if err := peer.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			sess := newInitTestSession("")
			hintSeen := make(chan struct{}, 1)
			if scenario.hint {
				core, _ := observer.New(zapcore.DebugLevel)
				sess.Logger = zap.New(core, zap.Hooks(func(entry zapcore.Entry) error {
					if entry.Message == "IKE_SA_INIT unauthenticated notification hint" {
						hintSeen <- struct{}{}
					}
					return nil
				}))
			}
			sess.cfg.InitialIKEProposalNumber = scenario.single
			if scenario.policy {
				sess.cfg.IKEProposals = []string{policyIKE256}
				sess.cfg.ESPProposals = []string{policyESP128}
			}
			sess.cfg.LocalAddr = "127.0.0.1"
			sess.cfg.LocalPort = 0
			sess.cfg.EpDGAddr = "127.0.0.1"
			sess.cfg.EpDGPort = uint16(peer.LocalAddr().(*net.UDPAddr).Port)
			sess.cfg.FastReauthID = "synthetic@invalid"
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			finished := make(chan error, 1)
			go func() { finished <- sess.Connect(ctx) }()
			t.Cleanup(func() { cancel(); sess.Shutdown() })
			buffer := make([]byte, 4096)
			count, address, err := peer.ReadFromUDP(buffer)
			if err != nil {
				t.Fatal(err)
			}
			offered := bytes.Clone(buffer[:count])
			sa, ke, _ := decodeInitSA(t, offered)
			wantProposals := 4
			if scenario.single != 0 || scenario.policy {
				wantProposals = 1
			}
			if len(sa.Proposals) != wantProposals {
				t.Fatalf("wire proposal count = %d", len(sa.Proposals))
			}
			request, err := ikev2.DecodePacket(offered)
			if err != nil {
				t.Fatal(err)
			}
			if scenario.hint {
				if _, err := peer.WriteToUDP(initHintWire(request.Header.SPIi, 17, []byte{0, 19}), address); err != nil {
					t.Fatal(err)
				}
				select {
				case <-hintSeen:
				case <-ctx.Done():
					t.Fatal("wire notification produced no diagnostic")
				}
				sess.taskMgr.mu.Lock()
				pending := sess.taskMgr.pending[0]
				preserved := pending != nil && pending.RetryCount == 0 && len(pending.Packets) == 1 && bytes.Equal(pending.Packets[0], offered)
				sess.taskMgr.mu.Unlock()
				if !preserved {
					t.Fatal("wire advisory changed the actual INIT request")
				}
			}
			var ni []byte
			for _, payload := range request.Payloads {
				if nonce, ok := payload.(*ikev2.EncryptedPayloadNonce); ok {
					ni = nonce.NonceData
				}
			}
			dh, err := crypto.NewDiffieHellman(14)
			if err != nil {
				t.Fatal(err)
			}
			if err := dh.GenerateKey(); err != nil {
				t.Fatal(err)
			}
			secret, err := dh.ComputeSharedSecret(ke.KEData)
			if err != nil {
				t.Fatal(err)
			}
			nr := bytes.Repeat([]byte{9}, 32)
			response := ikev2.NewIKEPacket()
			response.Header = &ikev2.IKEHeader{SPIi: request.Header.SPIi, SPIr: 4321, Version: 0x20, ExchangeType: ikev2.IKE_SA_INIT, Flags: ikev2.FlagResponse}
			chosen := sa.Proposals[len(sa.Proposals)-1]
			if scenario.reject && scenario.mutate == nil {
				chosen.ProposalNum = 1
			}
			response.Payloads = []ikev2.Payload{
				&ikev2.EncryptedPayloadSA{Proposals: []*ikev2.Proposal{chosen}},
				&ikev2.EncryptedPayloadKE{DHGroup: 14, KEData: dh.PublicKeyBytes()},
				&ikev2.EncryptedPayloadNonce{NonceData: nr},
			}
			raw, err := response.Encode()
			if err != nil {
				t.Fatal(err)
			}
			if scenario.mutate != nil {
				raw = scenario.mutate(raw)
			}
			if _, err := peer.WriteToUDP(raw, address); err != nil {
				t.Fatal(err)
			}
			if scenario.reject {
				// A structurally invalid response is discarded without consuming
				// the request. A strict numbering hint alone ends this Session.
				if scenario.mutate == nil {
					if err := <-finished; !errors.Is(err, ikev2.ErrInitResponse) {
						t.Fatalf("connect rejection: %v", err)
					}
				}
				if err := peer.SetReadDeadline(time.Now().Add(30 * time.Millisecond)); err != nil {
					t.Fatal(err)
				}
				if _, _, err := peer.ReadFromUDP(buffer); err == nil {
					t.Fatal("unexpected IKE_AUTH after invalid selection")
				} else if failure, ok := err.(net.Error); !ok || !failure.Timeout() {
					t.Fatal(err)
				}
				if scenario.mutate != nil {
					select {
					case err := <-finished:
						t.Fatalf("invalid packet consumed pending: %v", err)
					default:
					}
					cancel()
					if err := <-finished; !errors.Is(err, context.Canceled) {
						t.Fatalf("cancel after discarded response: %v", err)
					}
				}
				if sess.SPIr != 0 || sess.Keys != nil {
					t.Fatal("rejected connect changed SA")
				}
				return
			}
			count, _, err = peer.ReadFromUDP(buffer)
			if err != nil {
				t.Fatal(err)
			}
			auth := bytes.Clone(buffer[:count])
			authHeader, err := ikev2.DecodeHeader(auth)
			if err != nil || authHeader.ExchangeType != ikev2.IKE_AUTH {
				t.Fatalf("expected IKE_AUTH, got header=%v error=%v", authHeader, err)
			}
			cancel()
			if err := <-finished; !errors.Is(err, context.Canceled) {
				t.Fatalf("stop after AUTH: %v", err)
			}
			keys := independentSHA256Keys(secret, append(bytes.Clone(ni), nr...), response.Header)
			actual := [][]byte{sess.Keys.SK_d, sess.Keys.SK_ai, sess.Keys.SK_ar, sess.Keys.SK_ei, sess.Keys.SK_er, sess.Keys.SK_pi, sess.Keys.SK_pr}
			for index, key := range actual {
				if !bytes.Equal(key, keys[index*32:(index+1)*32]) {
					t.Fatalf("key %d differs from independent PRF+", index)
				}
			}
			header, err := ikev2.DecodeHeader(auth)
			if err != nil {
				t.Fatal(err)
			}
			if header.ExchangeType != ikev2.IKE_AUTH || header.MessageID != 1 || header.NextPayload != ikev2.SK {
				t.Fatal("not protected IKE_AUTH")
			}
			mac := hmac.New(sha256.New, keys[32:64])
			mac.Write(auth[:len(auth)-16])
			if !hmac.Equal(mac.Sum(nil)[:16], auth[len(auth)-16:]) {
				t.Fatal("peer rejected AUTH ICV")
			}
			block, err := aes.NewCipher(keys[96:128])
			if err != nil {
				t.Fatal(err)
			}
			plain := make([]byte, len(auth)-64)
			cipher.NewCBCDecrypter(block, auth[32:48]).CryptBlocks(plain, auth[48:len(auth)-16])
			if !bytes.Contains(plain, []byte("synthetic@invalid")) {
				t.Fatal("peer cannot decrypt initial AUTH identity")
			}
			receiver := newInitTestSession("")
			receiver.SPIi, receiver.SPIr = header.SPIi, header.SPIr
			receiver.localResponder = true
			receiver.EncAlg, receiver.IntegAlg = sess.EncAlg, sess.IntegAlg
			receiver.Keys = &ikev2.IKESAKeys{SK_ei: keys[96:128], SK_ai: keys[32:64]}
			_, payloads, err := receiver.decryptAndParse(auth)
			if err != nil {
				t.Fatalf("valid protected AUTH: %v", err)
			}
			if scenario.policy {
				found := false
				for _, payload := range payloads {
					if sa, ok := payload.(*ikev2.EncryptedPayloadSA); ok {
						found = true
						if len(sa.Proposals) != 1 || len(sa.Proposals[0].SPI) != 4 || len(sa.Proposals[0].Transforms) != 2 {
							t.Fatal("protected Child offer did not consume explicit policy")
						}
						p := sa.Proposals[0]
						if p.Transforms[0].ID != ikev2.ENCR_AES_GCM_16 || p.Transforms[0].Attributes[0].Val != 128 ||
							p.Transforms[1].Type != ikev2.TransformTypeESN || p.Transforms[1].ID != 0 {
							t.Fatal("protected Child offer changed the requested complete suite")
						}
					}
				}
				if !found {
					t.Fatal("protected AUTH omitted Child offer")
				}
			}
			auth[len(auth)-1] ^= 1
			if _, _, err := receiver.decryptAndParse(auth); err == nil {
				t.Fatal("tampered AUTH accepted")
			}
		})
	}
}

func independentSHA256Keys(secret, nonces []byte, header *ikev2.IKEHeader) []byte {
	mac := hmac.New(sha256.New, nonces)
	mac.Write(secret)
	seed := mac.Sum(nil)
	input := bytes.Clone(nonces)
	input = binary.BigEndian.AppendUint64(input, header.SPIi)
	input = binary.BigEndian.AppendUint64(input, header.SPIr)
	var previous, material []byte
	for counter := byte(1); counter <= 7; counter++ {
		mac := hmac.New(sha256.New, seed)
		mac.Write(previous)
		mac.Write(input)
		mac.Write([]byte{counter})
		previous = mac.Sum(nil)
		material = append(material, previous...)
	}
	return material
}

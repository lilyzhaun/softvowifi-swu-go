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
	"reflect"
	"testing"
	"time"

	"github.com/1239t/swu-go/pkg/crypto"
	"github.com/1239t/swu-go/pkg/driver"
	"github.com/1239t/swu-go/pkg/ikev2"
	"github.com/1239t/swu-go/pkg/ipsec"
)

type peerChildSuite struct {
	encr, integ     uint16
	bits, authBytes int
}

func TestPeerChildRekeyCancellationBeforeReplyRollsBack(t *testing.T) {
	s, _, p := peerChildFixture(t, peerChildSuites[2])
	in, out := s.ChildSAIn, s.ChildSAOut
	kernel := newRekeyKernel()
	kernel.live = map[uint32]bool{in.SPI: true, out.SPI: true}
	kernel.before = func() {
		if len(kernel.adds) == 2 {
			s.cancel()
		}
	}
	if err := s.handlePeerChildRekey(0, p, kernel); err == nil || s.ChildSAIn != in || s.ChildSAOut != out || !reflect.DeepEqual(kernel.live, map[uint32]bool{in.SPI: true, out.SPI: true}) {
		t.Fatal("canceled installation accepted/published a new pair")
	}
}

func TestChildCleanupWaitsForInFlightInstallation(t *testing.T) {
	s, _, _ := peerChildFixture(t, peerChildSuites[2])
	cleaned := make(chan struct{})
	s.netUndos = []func() error{func() error { close(cleaned); return nil }}
	s.rekeyMu.Lock()
	started, done := make(chan struct{}), make(chan error, 1)
	go func() { close(started); done <- s.cleanupNetworkConfig() }()
	<-started
	early := false
	select {
	case <-cleaned:
		early = true
	case <-time.After(50 * time.Millisecond):
	}
	s.rekeyMu.Unlock()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if early {
		t.Fatal("session cleanup removed owned resources during Child installation")
	}
}

func TestPeerChildRekeyKernelAndReplyFormATransaction(t *testing.T) {
	for _, failure := range []string{"", "add1", "add2", "sp1", "sp2", "sp3", "sp4", "send"} {
		t.Run(failure, func(t *testing.T) {
			s, pipe, p := peerChildFixture(t, peerChildSuites[2])
			in, out := s.ChildSAIn, s.ChildSAOut
			kernel := newRekeyKernel()
			kernel.live = map[uint32]bool{in.SPI: true, out.SPI: true}
			kernel.fail = failure
			if failure == "send" {
				pipe.sendErr = errSendIKE
			}
			pipe.beforeSend = func() {
				if s.ChildSAIn != in || s.ChildSAOut != out {
					t.Error("published new pair before response")
				}
			}
			err := s.handlePeerChildRekey(0, p, kernel)
			if failure != "" {
				if err == nil || s.ChildSAIn != in || s.ChildSAOut != out || s.retiredChild != nil {
					t.Fatalf("failed transaction committed: %v", err)
				}
				if !reflect.DeepEqual(kernel.live, map[uint32]bool{in.SPI: true, out.SPI: true}) {
					t.Fatalf("failed transaction left new kernel SAs: %v", kernel.live)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(kernel.adds) != 2 || len(kernel.live) != 4 {
				t.Fatal("did not keep old pair during accepted overlap")
			}
			want, _ := driver.IKEv2AlgToXFRMAuth(uint16(ikev2.AUTH_HMAC_SHA2_256_128))
			for _, sa := range kernel.adds {
				if sa.IsAEAD || sa.AuthAlgoName != want.Name || sa.AuthTruncLen != 128 || len(sa.AuthKey) != 32 {
					t.Fatal("kernel suite differs from selected CBC/SHA2")
				}
			}
			first := <-pipe.sent
			calls := len(kernel.calls)
			pipe.beforeSend = nil
			if err := s.handlePeerChildRekey(0, p, kernel); err != nil {
				t.Fatal(err)
			}
			if replay := <-pipe.sent; !bytes.Equal(first, replay) || len(kernel.calls) != calls {
				t.Fatal("retransmitted request installed another pair")
			}
			newIn, newOut := s.ChildSAIn, s.ChildSAOut
			deleteOld := &ikev2.EncryptedPayloadDelete{ProtocolID: ikev2.ProtoESP, SPISize: 4, NumSPIs: 1, SPIs: binary.BigEndian.AppendUint32(nil, out.SPI)}
			if err := s.handleIncomingInformationalParsed(1, []ikev2.Payload{deleteOld}); err != nil {
				t.Fatal(err)
			}
			<-pipe.sent
			if s.ctx.Err() != nil || s.ChildSAIn != newIn || s.ChildSAOut != newOut || s.ChildSAsIn[in.SPI] != nil || !reflect.DeepEqual(kernel.live, map[uint32]bool{newIn.SPI: true, newOut.SPI: true}) {
				t.Fatal("old Delete failed to retire exactly old pair")
			}
		})
	}
}

func TestPeerChildRekeyRollbackFailureEndsSessionWithOwnership(t *testing.T) {
	s, _, p := peerChildFixture(t, peerChildSuites[2])
	kernel := newRekeyKernel()
	kernel.fail, kernel.rollbackFail = "add2", true
	if err := s.handleIncomingCreateChildSAParsed(0, p, kernel); !errors.Is(err, ErrCleanup) || s.ctx.Err() == nil || s.retiredChild != nil {
		t.Fatalf("ambiguous rollback did not end session: %v", err)
	}
}

func TestPeerChildRekeyKernelSuiteMatrix(t *testing.T) {
	for _, suite := range peerChildSuites {
		t.Run(fmt.Sprintf("%d_%d_%d", suite.encr, suite.integ, suite.bits), func(t *testing.T) {
			s, _, p := peerChildFixture(t, suite)
			kernel := newRekeyKernel()
			if err := s.handlePeerChildRekey(0, p, kernel); err != nil {
				t.Fatal(err)
			}
			if len(kernel.adds) != 2 {
				t.Fatal("kernel did not receive both SA directions")
			}
			for _, sa := range kernel.adds {
				if suite.integ == 0 {
					if !sa.IsAEAD || sa.AeadAlgoName != "rfc4106(gcm(aes))" || sa.AeadICVLen != 128 || len(sa.AeadKey) != suite.bits/8+4 {
						t.Fatal("selected GCM suite not installed exactly")
					}
				} else {
					name, bits := "hmac(sha256)", 128
					if suite.integ == uint16(ikev2.AUTH_HMAC_SHA1_96) {
						name, bits = "hmac(sha1)", 96
					}
					if suite.integ == uint16(ikev2.AUTH_HMAC_SHA2_512_256) {
						name, bits = "hmac(sha512)", 256
					}
					if sa.IsAEAD || sa.CryptAlgoName != "cbc(aes)" || len(sa.CryptKey) != suite.bits/8 || sa.AuthAlgoName != name || sa.AuthTruncLen != bits || len(sa.AuthKey) != suite.authBytes {
						t.Fatal("selected CBC/integrity suite not installed exactly")
					}
				}
			}
		})
	}
}

func TestPeerChildRekeyRejectsInvalidPredecessorSuiteAndSelectors(t *testing.T) {
	for _, kind := range []string{"missing_rekey", "unknown_spi", "wrong_spi_direction", "duplicate_nonce", "short_nonce", "missing_integ", "key_length", "esn", "missing_tsr", "ts_protocol"} {
		t.Run(kind, func(t *testing.T) {
			s, pipe, p := peerChildFixture(t, peerChildSuites[2])
			in, out := s.ChildSAIn, s.ChildSAOut
			proposal := p[1].(*ikev2.EncryptedPayloadSA).Proposals[0]
			switch kind {
			case "missing_rekey":
				p = p[1:]
			case "unknown_spi":
				p[0].(*ikev2.EncryptedPayloadNotify).SPI = []byte{9, 9, 9, 9}
			case "wrong_spi_direction":
				p[0].(*ikev2.EncryptedPayloadNotify).SPI = binary.BigEndian.AppendUint32(nil, in.SPI)
			case "duplicate_nonce":
				p = append(p, p[2])
			case "short_nonce":
				p[2].(*ikev2.EncryptedPayloadNonce).NonceData = []byte{1}
			case "missing_integ":
				proposal.Transforms = append(proposal.Transforms[:1], proposal.Transforms[2:]...)
			case "key_length":
				proposal.Transforms[0].Attributes[0].Val = 128
			case "esn":
				proposal.Transforms[2].ID = 1
			case "missing_tsr":
				p = p[:4]
			case "ts_protocol":
				s.tsr = []*ikev2.TrafficSelector{ikev2.NewTrafficSelectorIPV4([]byte{192, 0, 2, 1}, []byte{192, 0, 2, 1}, 500, 500)}
			}
			kernel := newRekeyKernel()
			if err := s.handlePeerChildRekey(0, p, kernel); err != nil {
				t.Fatal(err)
			}
			reply := peerChildOpen(t, <-pipe.sent, s.Keys.SK_ei, s.Keys.SK_ai)
			if len(reply[byte(ikev2.N)]) < 4 || len(reply[byte(ikev2.SA)]) != 0 || len(kernel.calls) != 0 || s.ChildSAIn != in || s.ChildSAOut != out {
				t.Fatal("invalid request accepted or mutated state")
			}
		})
	}
}

var peerChildSuites = []peerChildSuite{
	{uint16(ikev2.ENCR_AES_GCM_16), 0, 256, 0}, {uint16(ikev2.ENCR_AES_GCM_16), 0, 128, 0},
	{uint16(ikev2.ENCR_AES_CBC), uint16(ikev2.AUTH_HMAC_SHA2_256_128), 256, 32},
	{uint16(ikev2.ENCR_AES_CBC), uint16(ikev2.AUTH_HMAC_SHA2_256_128), 128, 32},
	{uint16(ikev2.ENCR_AES_CBC), uint16(ikev2.AUTH_HMAC_SHA1_96), 128, 20},
	{uint16(ikev2.ENCR_AES_CBC), uint16(ikev2.AUTH_HMAC_SHA2_512_256), 256, 64},
}

func peerChildFixture(t *testing.T, suite peerChildSuite) (*Session, *pipeTransport, []ikev2.Payload) {
	t.Helper()
	s := newLebaraRekeyCryptoSession(t)
	s.ctx, s.cancel = context.WithCancel(t.Context())
	t.Cleanup(s.cancel)
	s.PRFAlg, _ = crypto.GetPRF(uint16(ikev2.PRF_HMAC_SHA2_256))
	s.ikePRFID = uint16(ikev2.PRF_HMAC_SHA2_256)
	s.Keys.SK_d = bytes.Repeat([]byte{0x42}, 32)
	s.childEncrID, s.childIntegID, s.childEncrKeyLenBits = suite.encr, suite.integ, suite.bits
	s.ChildSAOut = &ipsec.SecurityAssociation{SPI: 0x22222222, RemoteSPI: 0x11111111}
	s.ChildSAIn = &ipsec.SecurityAssociation{SPI: 0x11111111, RemoteSPI: 0x22222222}
	s.ChildSAsIn = map[uint32]*ipsec.SecurityAssociation{s.ChildSAIn.SPI: s.ChildSAIn}
	settings, _ := rekeyXFRMFixture()
	s.cpConfig, s.tsi, s.tsr = settings.cpConfig, settings.tsi, settings.tsr
	s.xfrmLocalIP, s.xfrmRemoteIP = settings.xfrmLocalIP, settings.xfrmRemoteIP
	pipe := &pipeTransport{sent: make(chan []byte, 8)}
	s.socket, s.ikeControlAlive = pipe, true
	p := ikev2.NewProposal(1, ikev2.ProtoESP, binary.BigEndian.AppendUint32(nil, 0x33333333))
	p.AddTransformWithKeyLen(ikev2.TransformTypeEncr, ikev2.AlgorithmType(suite.encr), suite.bits)
	if suite.integ != 0 {
		p.AddTransform(ikev2.TransformTypeInteg, ikev2.AlgorithmType(suite.integ), 0)
	}
	p.AddTransform(ikev2.TransformTypeESN, 0, 0)
	return s, pipe, []ikev2.Payload{
		&ikev2.EncryptedPayloadNotify{ProtocolID: ikev2.ProtoESP, SPI: binary.BigEndian.AppendUint32(nil, s.ChildSAOut.SPI), NotifyType: ikev2.REKEY_SA},
		&ikev2.EncryptedPayloadSA{Proposals: []*ikev2.Proposal{p}},
		&ikev2.EncryptedPayloadNonce{NonceData: bytes.Repeat([]byte{0xa5}, 32)},
		&ikev2.EncryptedPayloadTS{IsInitiator: true, TrafficSelectors: s.tsr},
		&ikev2.EncryptedPayloadTS{IsInitiator: false, TrafficSelectors: s.tsi},
	}
}

func peerChildOpen(t *testing.T, raw, enc, mac []byte) map[byte][]byte {
	t.Helper()
	h := hmac.New(sha256.New, mac)
	h.Write(raw[:len(raw)-16])
	if !hmac.Equal(h.Sum(nil)[:16], raw[len(raw)-16:]) {
		t.Fatal("independent response ICV mismatch")
	}
	b, err := aes.NewCipher(enc)
	if err != nil {
		t.Fatal(err)
	}
	plain := make([]byte, len(raw)-64)
	cipher.NewCBCDecrypter(b, raw[32:48]).CryptBlocks(plain, raw[48:len(raw)-16])
	plain = plain[:len(plain)-int(plain[len(plain)-1])-1]
	out := map[byte][]byte{}
	kind := raw[28]
	for off := 0; kind != 0; {
		length := int(binary.BigEndian.Uint16(plain[off+2 : off+4]))
		out[kind] = plain[off+4 : off+length]
		kind = plain[off]
		off += length
	}
	return out
}

func peerChildPRF(key, seed []byte, size int) []byte {
	var last, out []byte
	for i := byte(1); len(out) < size; i++ {
		h := hmac.New(sha256.New, key)
		h.Write(last)
		h.Write(seed)
		h.Write([]byte{i})
		last = h.Sum(nil)
		out = append(out, last...)
	}
	return out[:size]
}

func TestPeerInitiatedChildRekeyThroughProductionDispatcher(t *testing.T) {
	for _, suite := range peerChildSuites {
		t.Run(fmt.Sprintf("%d_%d_%d", suite.encr, suite.integ, suite.bits), func(t *testing.T) {
			s, pipe, p := peerChildFixture(t, suite)
			s.dispatchReceivedIKE(encodePeerPacket(t, s, p, ikev2.CREATE_CHILD_SA, 0, false), nil)
			response := peerChildOpen(t, <-pipe.sent, s.Keys.SK_ei, s.Keys.SK_ai)
			sa, nr := response[byte(ikev2.SA)], response[byte(ikev2.NiNr)]
			if len(sa) < 12 || len(nr) < 16 {
				t.Fatal("missing accepted SA/Nonce")
			}
			localSPI := binary.BigEndian.Uint32(sa[8:12])
			if s.ChildSAOut.SPI != 0x33333333 || s.ChildSAIn.SPI != localSPI {
				t.Error("Child SPI direction reversed")
			}
			keyBytes := suite.bits / 8
			if suite.integ == 0 {
				keyBytes += 4
			}
			km := peerChildPRF(s.Keys.SK_d, append(bytes.Repeat([]byte{0xa5}, 32), nr...), 2*(keyBytes+suite.authBytes))
			if !bytes.Equal(s.ChildSAIn.EncryptionKey, km[:keyBytes]) || !bytes.Equal(s.ChildSAIn.IntegrityKey, km[keyBytes:keyBytes+suite.authBytes]) || !bytes.Equal(s.ChildSAOut.EncryptionKey, km[keyBytes+suite.authBytes:2*keyBytes+suite.authBytes]) || !bytes.Equal(s.ChildSAOut.IntegrityKey, km[2*keyBytes+suite.authBytes:]) {
				t.Error("Child KEYMAT layout/direction differs from independent RFC7296 reference")
			}
			if s.ChildSAIn.IsAEAD != (suite.integ == 0) || s.ChildSAOut.IsAEAD != (suite.integ == 0) {
				t.Error("CBC/AEAD mismatch")
			}
			seen := map[byte]uint16{}
			for off := 12; off < len(sa); {
				length := int(binary.BigEndian.Uint16(sa[off+2 : off+4]))
				kind := sa[off+4]
				seen[kind] = binary.BigEndian.Uint16(sa[off+6 : off+8])
				if kind == byte(ikev2.TransformTypeEncr) && !bytes.Equal(sa[off+8:off+length], []byte{0x80, 14, byte(suite.bits >> 8), byte(suite.bits)}) {
					t.Error("lost encryption key-length attribute")
				}
				off += length
			}
			if seen[byte(ikev2.TransformTypeEncr)] != suite.encr || seen[byte(ikev2.TransformTypeInteg)] != suite.integ {
				t.Error("selected another suite")
			}
		})
	}
}

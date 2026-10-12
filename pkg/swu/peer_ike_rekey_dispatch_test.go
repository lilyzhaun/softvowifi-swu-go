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
	"testing"
	"time"

	"github.com/1239t/swu-go/pkg/crypto"
	"github.com/1239t/swu-go/pkg/ikev2"
	"github.com/1239t/swu-go/pkg/ipsec"
)

func peerRekeyOffer(t *testing.T, s *Session) []ikev2.Payload {
	t.Helper()
	dh, err := crypto.NewDiffieHellman(s.ikeDHID)
	if err != nil {
		t.Fatal(err)
	}
	if err = dh.GenerateKey(); err != nil {
		t.Fatal(err)
	}
	p := ikev2.NewProposal(1, ikev2.ProtoIKE, []byte{1, 2, 3, 4, 5, 6, 7, 8})
	p.AddTransformWithKeyLen(ikev2.TransformTypeEncr, ikev2.AlgorithmType(s.ikeEncrID), s.ikeEncrKeyLenBits)
	if !s.ikeIsAEAD {
		p.AddTransform(ikev2.TransformTypeInteg, ikev2.AlgorithmType(s.ikeIntegID), 0)
	}
	p.AddTransform(ikev2.TransformTypePRF, ikev2.AlgorithmType(s.ikePRFID), 0)
	p.AddTransform(ikev2.TransformTypeDH, ikev2.AlgorithmType(s.ikeDHID), 0)
	return []ikev2.Payload{&ikev2.EncryptedPayloadSA{Proposals: []*ikev2.Proposal{p}}, &ikev2.EncryptedPayloadNonce{NonceData: bytes.Repeat([]byte{0x5a}, 32)}, &ikev2.EncryptedPayloadKE{DHGroup: ikev2.AlgorithmType(s.ikeDHID), KEData: dh.PublicKeyBytes()}}
}

func TestPeerIKERekeyRetiresOnlyTheOldIKEGeneration(t *testing.T) {
	s := newLebaraRekeyCryptoSession(t)
	s.ctx, s.cancel = context.WithCancel(t.Context())
	defer s.cancel()
	pipe := &pipeTransport{sent: make(chan []byte, 8)}
	s.socket, s.ikeControlAlive = pipe, true
	s.ChildSAIn = &ipsec.SecurityAssociation{SPI: 111}
	s.ChildSAOut = &ipsec.SecurityAssociation{SPI: 222}
	in, out := s.ChildSAIn, s.ChildSAOut
	request := encodePeerPacket(t, s, peerRekeyOffer(t, s), ikev2.CREATE_CHILD_SA, 0, false)
	oldDelete := encodePeerPacket(t, s, []ikev2.Payload{&ikev2.EncryptedPayloadDelete{ProtocolID: ikev2.ProtoIKE}}, ikev2.INFORMATIONAL, 1, false)
	s.dispatchReceivedIKE(request, nil)
	reply := <-pipe.sent
	keys := s.Keys
	s.dispatchReceivedIKE(request, nil)
	if replay := <-pipe.sent; !bytes.Equal(reply, replay) || s.Keys != keys {
		t.Fatal("duplicate rekey created another generation")
	}
	var deleteResponse []byte
	for range 2 {
		s.dispatchReceivedIKE(oldDelete, nil)
		select {
		case response := <-pipe.sent:
			if deleteResponse != nil && !bytes.Equal(response, deleteResponse) {
				t.Fatal("old Delete retransmission changed response bytes")
			}
			deleteResponse = response
		default:
			t.Fatal("old IKE Delete not acknowledged")
		}
		if s.ctx.Err() != nil || s.Keys != keys || s.ChildSAIn != in || s.ChildSAOut != out {
			t.Fatal("retired IKE Delete destroyed new generation or children")
		}
	}
	bad := bytes.Clone(oldDelete)
	bad[len(bad)-1] ^= 1
	s.dispatchReceivedIKE(bad, nil)
	select {
	case <-pipe.sent:
		t.Fatal("unauthenticated old packet elicited response")
	default:
	}
	s.expireRetiredIKE(time.Now().Add(4 * time.Minute))
	s.dispatchReceivedIKE(oldDelete, nil)
	select {
	case <-pipe.sent:
		t.Fatal("old keys retained beyond grace period")
	default:
	}
}

func TestPeerIKERekeySelectsCurrentSuiteFromAnOfferedAlternative(t *testing.T) {
	s := newLebaraRekeyCryptoSession(t)
	pipe := &pipeTransport{sent: make(chan []byte, 4)}
	s.socket = pipe
	p := peerRekeyOffer(t, s)
	sa := p[0].(*ikev2.EncryptedPayloadSA)
	unsupported := s.ikeRekeyProposal([]byte{8, 7, 6, 5, 4, 3, 2, 1})
	unsupported.Transforms[0].Attributes[0].Val = 256
	sa.Proposals[0].ProposalNum = 2
	sa.Proposals = append([]*ikev2.Proposal{unsupported}, sa.Proposals...)
	if err := s.HandleRekeyIKESARequest(0, p); err != nil {
		t.Fatal(err)
	}
	if !s.localResponder || s.DH.Group != s.ikeDHID || s.SPIi != 0x0102030405060708 {
		t.Fatal("rekey did not select the supported second proposal")
	}
}

func TestPeerIKERekeyInvalidOrUnsentResponseNeverCommits(t *testing.T) {
	for _, kind := range []string{"key_length", "unknown_attribute", "short_nonce", "duplicate_nonce", "duplicate_sa", "ke_group", "spi_length", "send_failure"} {
		t.Run(kind, func(t *testing.T) {
			s := newLebaraRekeyCryptoSession(t)
			pipe := &pipeTransport{sent: make(chan []byte, 4)}
			s.socket = pipe
			before, spii, spir := s.Keys, s.SPIi, s.SPIr
			p := peerRekeyOffer(t, s)
			sa := p[0].(*ikev2.EncryptedPayloadSA)
			switch kind {
			case "key_length":
				sa.Proposals[0].Transforms[0].Attributes[0].Val = 256
			case "unknown_attribute":
				sa.Proposals[0].Transforms[0].Attributes[0].Type = 222
			case "short_nonce":
				p[1].(*ikev2.EncryptedPayloadNonce).NonceData = []byte{1}
			case "duplicate_nonce":
				p = append(p, p[1])
			case "duplicate_sa":
				p = append(p, p[0])
			case "ke_group":
				p[2].(*ikev2.EncryptedPayloadKE).DHGroup = ikev2.MODP_1024_bit
			case "spi_length":
				sa.Proposals[0].SPI = append(sa.Proposals[0].SPI, 0)
			case "send_failure":
				pipe.sendErr = errors.New("synthetic send failure")
			}
			if err := s.HandleRekeyIKESARequest(0, p); err == nil {
				t.Fatal("invalid/uncommitted rekey reported success")
			}
			if s.Keys != before || s.SPIi != spii || s.SPIr != spir || s.retiredIKE != nil || s.localResponder {
				t.Fatal("failed rekey committed a generation")
			}
		})
	}
}

func TestPeerIKERekeyKeepsOldOutstandingMessageID(t *testing.T) {
	s := newLebaraRekeyCryptoSession(t)
	s.ctx, s.cancel = context.WithCancel(t.Context())
	defer s.cancel()
	pipe := &pipeTransport{sent: make(chan []byte, 4)}
	s.socket, s.ikeControlAlive = pipe, true
	s.taskMgr = NewTaskManager(s.ctx, &RetryConfig{InitialTimeout: time.Hour}, 1, nil)
	defer s.taskMgr.Stop()
	pending := s.taskMgr.enqueueRequest(0, ikev2.INFORMATIONAL, nil, nil)
	keys := s.Keys
	s.dispatchReceivedIKE(encodePeerPacket(t, s, peerRekeyOffer(t, s), ikev2.CREATE_CHILD_SA, 0, false), nil)
	if s.Keys != keys || s.localResponder {
		t.Fatal("rekey collided with outstanding old MID0")
	}
	select {
	case <-pending.CompletionCh:
		t.Fatal("busy rekey consumed old transaction")
	default:
	}
	select {
	case <-pipe.sent:
	default:
		t.Fatal("busy rekey lacked TEMPORARY_FAILURE reply")
	}
}

func TestPeerInitiatedIKERekeyThroughProductionDispatcher(t *testing.T) {
	s := newLebaraRekeyCryptoSession(t)
	pipe := &pipeTransport{sent: make(chan []byte, 4)}
	s.socket, s.ikeControlAlive = pipe, true
	request := encodePeerPacket(t, s, peerRekeyOffer(t, s), ikev2.CREATE_CHILD_SA, 0, false)
	done := make(chan struct{})
	go func() { s.dispatchReceivedIKE(request, nil); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("valid peer IKE rekey deadlocked production dispatcher")
	}
	select {
	case <-pipe.sent:
	default:
		t.Fatal("no rekey response")
	}
	if !s.localResponder {
		t.Fatal("new SA did not adopt responder role")
	}
}

func TestPeerInitiatedIKERekeyResponseKeepsOfferedAttributes(t *testing.T) {
	s := newLebaraRekeyCryptoSession(t)
	pipe := &pipeTransport{sent: make(chan []byte, 4)}
	s.socket = pipe
	enc, mac := bytes.Clone(s.Keys.SK_ei), bytes.Clone(s.Keys.SK_ai)
	if err := s.HandleRekeyIKESARequest(0, peerRekeyOffer(t, s)); err != nil {
		t.Fatal(err)
	}
	raw := <-pipe.sent
	// Independent standard-library decryption, not the producer's parser.
	h := hmac.New(sha256.New, mac)
	h.Write(raw[:len(raw)-16])
	if !hmac.Equal(h.Sum(nil)[:16], raw[len(raw)-16:]) {
		t.Fatal("bad response ICV")
	}
	b, err := aes.NewCipher(enc)
	if err != nil {
		t.Fatal(err)
	}
	plain := make([]byte, len(raw)-64)
	cipher.NewCBCDecrypter(b, raw[32:48]).CryptBlocks(plain, raw[48:len(raw)-16])
	if raw[28] != byte(ikev2.SA) {
		t.Fatal("missing SA")
	}
	sa := plain[4:int(binary.BigEndian.Uint16(plain[2:4]))]
	for off := 8 + int(sa[6]); off < len(sa); {
		length := int(binary.BigEndian.Uint16(sa[off+2 : off+4]))
		if sa[off+4] == byte(ikev2.TransformTypeEncr) && !bytes.Equal(sa[off+8:off+length], []byte{0x80, 0x0e, 0, 0x80}) {
			t.Fatal("response lost offered AES Key Length=128")
		}
		off += length
	}
}

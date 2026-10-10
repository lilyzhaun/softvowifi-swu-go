package swu

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/1239t/swu-go/pkg/ikev2"
	"github.com/1239t/swu-go/pkg/ipsec"
)

func TestReceiveValidationRejectsPlaintextWithoutCommit(t *testing.T) {
	s, _ := newPostEAPSession(t)
	s.SPIr = 4321
	p := ikev2.NewIKEPacket()
	p.Header = &ikev2.IKEHeader{SPIi: s.SPIi, SPIr: s.SPIr, Version: 0x20, ExchangeType: ikev2.IKE_AUTH, Flags: ikev2.FlagResponse, MessageID: 3}
	p.Payloads = []ikev2.Payload{testIDrPayload(), validResponderAUTH(t, s), testChildSA()}
	raw, err := p.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.handleIKEAuthFinalResp(raw); err == nil || s.ChildSAOut != nil {
		t.Fatal("plaintext final response committed Child SA")
	}
}

func TestReceiveValidationShortSKNeverPanics(t *testing.T) {
	for size := 28; size < 52; size++ {
		s, _ := newPostEAPSession(t)
		s.SPIr = 4321
		h := &ikev2.IKEHeader{SPIi: s.SPIi, SPIr: s.SPIr, NextPayload: ikev2.SK, Version: 0x20, ExchangeType: ikev2.IKE_AUTH, Flags: ikev2.FlagResponse, Length: uint32(size)}
		raw := append(h.Encode(), make([]byte, size-28)...)
		func() {
			defer func() {
				if recover() != nil {
					t.Errorf("short SK panicked at length %d", size)
				}
			}()
			if _, _, err := s.decryptAndParse(raw); err == nil {
				t.Errorf("accepted short SK length %d", size)
			}
		}()
	}
}

func TestReceiveValidationBadHeaderOrMACDoesNotMutateSPI(t *testing.T) {
	for _, mutation := range []string{"spii", "spir", "direction", "length", "icv"} {
		t.Run(mutation, func(t *testing.T) {
			s, _ := newPostEAPSession(t)
			s.SPIr = 4321
			raw := a01PeerResponse(t, s, []ikev2.Payload{eapSuccessPayload()}, 3)
			switch mutation {
			case "spii":
				binary.BigEndian.PutUint64(raw[:8], 99)
			case "spir":
				binary.BigEndian.PutUint64(raw[8:16], 9999)
			case "direction":
				raw[19] |= ikev2.FlagInitiator
			case "length":
				binary.BigEndian.PutUint32(raw[24:28], uint32(len(raw)+1))
			case "icv":
				raw[len(raw)-1] ^= 1
			}
			if _, _, err := s.decryptAndParse(raw); err == nil {
				t.Fatal("invalid packet accepted")
			}
			if s.SPIr != 4321 {
				t.Fatal("invalid packet mutated responder SPI")
			}
			valid := a01PeerResponse(t, s, []ikev2.Payload{eapSuccessPayload()}, 3)
			if _, payloads, err := s.decryptAndParse(valid); err != nil || len(payloads) != 1 {
				t.Fatal("invalid packet poisoned later valid response")
			}
		})
	}
}

func TestReceiveWindowForeignResponseKeepsPending(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tm := NewTaskManager(ctx, nil, 1, func([][]byte) error { return nil })
	defer tm.Stop()
	completion := tm.EnqueueRequest(7, ikev2.IKE_AUTH, nil, [][]byte{{1}})
	h := &ikev2.IKEHeader{SPIi: 99, SPIr: 88, Version: 0x20, ExchangeType: ikev2.INFORMATIONAL, Flags: ikev2.FlagResponse, MessageID: 7, Length: 28}
	if tm.HandleResponse(7, h.Encode()) {
		t.Fatal("foreign exchange consumed AUTH pending")
	}
	select {
	case <-completion:
		t.Fatal("invalid response completed request")
	default:
	}
	h.ExchangeType = ikev2.IKE_AUTH
	if !tm.HandleResponse(7, h.Encode()) {
		t.Fatal("valid matching exchange could not finish original pending")
	}
}

func a01PeerResponse(t *testing.T, s *Session, payloads []ikev2.Payload, mid uint32) []byte {
	t.Helper()
	return encodePeerPacket(t, s, payloads, ikev2.IKE_AUTH, mid, true)
}

func TestReceiveInvalidResponseKeepsWindowEndpointAndActivity(t *testing.T) {
	for _, role := range []bool{false, true} {
		for _, variant := range []string{"plaintext", "exchange", "mid", "spii", "spir", "direction", "length", "icv", "payload chain", "endpoint denied"} {
			t.Run(fmtRole(role)+"/"+variant, func(t *testing.T) {
				s, _ := newPostEAPSession(t)
				s.localResponder = role
				manager, _ := newIdleWindow(t, 1)
				manager.responseValidator = s.validateWindowResponse
				s.taskMgr = manager
				completion := manager.EnqueueRequest(3, ikev2.INFORMATIONAL, nil, nil)
				before := *manager.pending[3]
				past := time.Unix(1, 0)
				s.initializeInboundActivity(past)
				raw := encodePeerPacket(t, s, nil, ikev2.INFORMATIONAL, 3, true)
				switch variant {
				case "plaintext":
					raw[16] = 0
				case "exchange":
					raw[18] = byte(ikev2.IKE_AUTH)
				case "mid":
					binary.BigEndian.PutUint32(raw[20:24], 4)
				case "spii":
					raw[0] ^= 1
				case "spir":
					raw[8] ^= 1
				case "direction":
					raw[19] ^= ikev2.FlagInitiator
				case "length":
					raw[27] ^= 1
				case "icv":
					raw[len(raw)-1] ^= 1
				case "payload chain":
					raw = encodePeerCBCPlaintext(t, s, []byte{0, 0, 0, 3}, ikev2.N, ikev2.INFORMATIONAL, 3, true)
				}
				commits := 0
				s.dispatchReceivedIKE(raw, func() error {
					if variant == "endpoint denied" {
						return errors.New("unbound endpoint")
					}
					commits++
					return nil
				})
				if len(manager.pending) != 1 || !reflect.DeepEqual(*manager.pending[3], before) || commits != 0 || !s.lastInboundTime.Equal(past) || s.SPIr != 4321 || len(s.ikePending) != 0 {
					t.Fatal("invalid response changed request, endpoint, SPI or activity")
				}
				select {
				case <-completion:
					t.Fatal("invalid response completed pending")
				default:
				}
				valid := encodePeerPacket(t, s, nil, ikev2.INFORMATIONAL, 3, true)
				s.dispatchReceivedIKE(valid, func() error { commits++; return nil })
				select {
				case response := <-completion:
					if !bytes.Equal(response, valid) {
						t.Fatal("wrong completion")
					}
				default:
					t.Fatal("valid response cannot complete original request")
				}
				if commits != 1 || len(manager.pending) != 0 || !s.lastInboundTime.After(past) {
					t.Fatal("valid response was not committed once")
				}
				s.dispatchReceivedIKE(valid, func() error { commits++; return nil })
				if commits != 1 || len(s.ikePending) != 0 {
					t.Fatal("late response committed endpoint or was retained")
				}
			})
		}
	}
}

func fmtRole(responder bool) string {
	if responder {
		return "local responder"
	}
	return "local initiator"
}

func TestReceiveMalformedProtectedPayloadChainIsRejected(t *testing.T) {
	for _, variant := range []struct {
		name  string
		first ikev2.PayloadType
		inner []byte
	}{
		{"short header", ikev2.N, []byte{0}},
		{"zero length", ikev2.N, []byte{0, 0, 0, 0}},
		{"truncated body", ikev2.N, []byte{0, 0, 0, 10}},
		{"missing next", ikev2.N, []byte{byte(ikev2.N), 0, 0, 8, 0, 0, 0, 1}},
		{"trailing data", ikev2.N, []byte{0, 0, 0, 8, 0, 0, 0, 1, 0}},
		{"critical unknown", ikev2.PayloadType(200), []byte{0, 0x80, 0, 4}},
	} {
		t.Run(variant.name, func(t *testing.T) {
			s, _ := newPostEAPSession(t)
			raw := encodePeerCBCPlaintext(t, s, variant.inner, variant.first, ikev2.IKE_AUTH, 3, true)
			if _, _, err := s.decryptAndParse(raw); err == nil {
				t.Fatal("malformed authenticated chain accepted")
			}
		})
	}
	s, _ := newPostEAPSession(t)
	raw := encodePeerCBCPlaintext(t, s, []byte{0, 0, 0, 4}, ikev2.PayloadType(200), ikev2.IKE_AUTH, 3, true)
	if _, payloads, err := s.decryptAndParse(raw); err != nil || len(payloads) != 1 {
		t.Fatal("legal unknown noncritical payload rejected")
	}
}

func TestReceivePeerRequestRequiresIntegrityAndAllowedExchange(t *testing.T) {
	for _, role := range []bool{false, true} {
		t.Run(fmtRole(role), func(t *testing.T) {
			s, _ := newPostEAPSession(t)
			s.localResponder = role
			s.ikeControlAlive = true
			pipe := &pipeTransport{sent: make(chan []byte, 2)}
			s.socket = pipe
			past := time.Unix(1, 0)
			s.initializeInboundActivity(past)
			bad := encodePeerPacket(t, s, nil, ikev2.INFORMATIONAL, 7, false)
			bad[len(bad)-1] ^= 1
			s.dispatchReceivedIKE(bad, func() error { t.Error("bad request committed peer"); return nil })
			unexpected := encodePeerPacket(t, s, nil, ikev2.IKE_AUTH, 7, false)
			s.dispatchReceivedIKE(unexpected, func() error { t.Error("unsolicited AUTH request committed peer"); return nil })
			if !s.lastInboundTime.Equal(past) || len(pipe.sent) != 0 {
				t.Fatal("invalid request renewed activity or got a reply")
			}
			valid := encodePeerPacket(t, s, nil, ikev2.INFORMATIONAL, 7, false)
			commits := 0
			s.dispatchReceivedIKE(valid, func() error { commits++; return nil })
			if commits != 1 || !s.lastInboundTime.After(past) {
				t.Fatal("valid DPD request not committed")
			}
			select {
			case response := <-pipe.sent:
				h, _ := ikev2.DecodeHeader(response)
				if h.MessageID != 7 || h.ExchangeType != ikev2.INFORMATIONAL || h.Flags&ikev2.FlagResponse == 0 {
					t.Fatal("wrong DPD reply header")
				}
				if _, payloads, err := testPeerReceiver(s).decryptAndParse(response); err != nil || len(payloads) != 0 {
					t.Fatal("peer cannot authenticate DPD reply")
				}
			default:
				t.Fatal("valid DPD request got no response")
			}
		})
	}
}

func TestReceiveUDPEnvelopeCommitsPortOnlyAfterValidation(t *testing.T) {
	initial, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer initial.Close()
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	socket, err := ipsec.NewSocketManager("127.0.0.1:0", initial.LocalAddr().String(), "")
	if err != nil {
		t.Fatal(err)
	}
	envelopes := socket.IKEEnvelopes()
	socket.Start()
	defer socket.Stop()
	s, _ := newPostEAPSession(t)
	s.SPIi = 0x0102030405060708
	s.socket = socket
	manager, _ := newIdleWindow(t, 1)
	manager.responseValidator = s.validateWindowResponse
	s.taskMgr = manager
	completion := manager.EnqueueRequest(3, ikev2.INFORMATIONAL, nil, nil)
	past := time.Unix(1, 0)
	s.initializeInboundActivity(past)
	valid := encodePeerPacket(t, s, nil, ikev2.INFORMATIONAL, 3, true)
	for _, bad := range []bool{true, false} {
		raw := bytes.Clone(valid)
		if bad {
			raw[len(raw)-1] ^= 1
		}
		if _, err := peer.WriteToUDP(raw, socket.LocalAddr); err != nil {
			t.Fatal(err)
		}
		var envelope ipsec.IKEEnvelope
		select {
		case envelope = <-envelopes:
		case <-time.After(time.Second):
			t.Fatal("IKE envelope not received")
		}
		if socket.RemotePort() != initial.LocalAddr().(*net.UDPAddr).Port {
			t.Fatal("UDP receive committed endpoint before validation")
		}
		s.dispatchReceivedIKE(envelope.Data, func() error { return socket.CommitIKEPeer(envelope.Peer, true) })
		if bad {
			if socket.RemotePort() != initial.LocalAddr().(*net.UDPAddr).Port || !s.lastInboundTime.Equal(past) || len(socket.NetEvents) != 0 {
				t.Fatal("invalid ICV committed port or activity")
			}
			select {
			case <-completion:
				t.Fatal("invalid ICV completed window")
			default:
			}
		}
	}
	if socket.RemotePort() != peer.LocalAddr().(*net.UDPAddr).Port || !s.lastInboundTime.After(past) {
		t.Fatal("validated peer port/activity not committed")
	}
	select {
	case response := <-completion:
		if !bytes.Equal(response, valid) {
			t.Fatal("wrong response")
		}
	default:
		t.Fatal("valid UDP response not delivered")
	}
	select {
	case event := <-socket.NetEvents:
		if event.Type != ipsec.EventNATPortChanged {
			t.Fatal("wrong event")
		}
	default:
		t.Fatal("missing port-change event")
	}
}
